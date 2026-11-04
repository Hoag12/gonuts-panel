package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"gonutspanel/internal/store"
)

const (
	defaultHeartbeatSeconds  = 20
	defaultTelemetryInterval = time.Second
	defaultMaxMessageBytes   = 32768
	defaultPanelTimeout      = 15 * time.Second
	defaultMaxPanelInFlight  = 8
	heartbeatSweepInterval   = 5 * time.Second
	telemetryFlushInterval   = time.Second
	persistInterval          = 5 * time.Second
	// maxReadBytes is the socket read limit. It is independent of
	// Options.MaxMessageBytes because panel_result frames may carry up to
	// 768 KiB; telemetry frames are still bounded to 32 KiB by ParseTelemetry.
	maxReadBytes            = 1 << 20
	helloTimeout            = 10 * time.Second
	clientSilenceTimeout    = 80 * time.Second
	writeTimeout            = 10 * time.Second
	sendBuffer              = 16
	maxCloseReasonBytes     = 120
	websocketCloseGoingAway = 1001
	websocketCloseProtocol  = 4400
	websocketCloseForbidden = 4403
	websocketCloseHeartbeat = 4408
	websocketCloseReplaced  = 4409

	// defaultCommandTTL is the contract's result deadline: a command without a
	// result after 30 s is reported expired to the browser.
	defaultCommandTTL = 30 * time.Second
	// panelExpiry is the deadline advertised to the mod inside a panel frame.
	// It is intentionally shorter than PanelTimeout so the mod gives up before
	// the browser is told "no answer". The gap also absorbs clock skew: the mod
	// refuses a frame whose expiresAt is more than 15 s ahead of its own clock,
	// so a client running a few seconds slow would otherwise see every panel
	// request rejected as an invalid expiry.
	panelExpiry  = 10 * time.Second
	idBytes      = 12 // 12 bytes of entropy encode to 16 base64url chars
	commandIDTag = "cmd_"
	panelIDTag   = "pr_"
)

// errPanelBody reports a base64 panel result the relay could not decode. The
// message never contains frame contents.
var errPanelBody = errors.New("relay: panel response body is not valid base64")

// idFallback makes ID generation unique even if the system random source
// fails.
var idFallback atomic.Uint64

// The values below mirror the protocol-1 contract advertised after pairing.
var welcomeCommands = []string{"pause", "resume", "snapshot", "panel"}

// Options tunes the WebSocket hub. Zero values are replaced with the contract
// defaults by NewHub.
type Options struct {
	HeartbeatSeconds     int
	TelemetryMinInterval time.Duration
	MaxMessageBytes      int
	PanelTimeout         time.Duration
	MaxPanelInFlight     int
}

// Hub owns the live client sockets. It implements the web layer's Relay
// interface: presence, commands, panel requests, and change notifications.
//
// Telemetry is coalesced to at most one stored update per
// Options.TelemetryMinInterval; the Start loop stores the newest pending frame
// once a second, persists state every five seconds, and Stop flushes once more.
type Hub struct {
	store   *store.Store
	opts    Options
	updates chan struct{}

	// flushEvery is the telemetry coalescing tick. It is a field so tests can
	// drive flushes deterministically; production uses one second.
	flushEvery time.Duration
	// commandTTL is the result deadline for a command. It is a field so tests
	// can exercise expiry without waiting 30 seconds; production uses
	// defaultCommandTTL.
	commandTTL time.Duration

	mu       sync.Mutex
	clients  map[int64]*client
	conns    sync.WaitGroup
	stopping bool

	stopCh   chan struct{}
	stopOnce sync.Once

	lifeMu  sync.Mutex
	started bool
	done    chan struct{}
}

// client is one live socket for one installation. All writes are serialised
// through writeMu so the read loop, the write pump, and close frames can never
// interleave on the wire.
type client struct {
	hub            *Hub
	conn           *websocket.Conn
	send           chan []byte
	installationID int64
	lastSeen       atomic.Int64
	closed         chan struct{}
	once           sync.Once
	writeMu        sync.Mutex

	// Telemetry is coalesced: the first frame is stored immediately, frames
	// inside Options.TelemetryMinInterval replace pendingTelemetry, and the
	// hub tick stores the newest pending frame once per interval.
	telemetryMu      sync.Mutex
	pendingTelemetry *store.Telemetry
	lastTelemetryAt  time.Time

	// panelMu guards the in-flight panel requests and the closed flag. Each
	// pending request has a buffered answer channel; exactly one value is sent
	// and the sender removes the entry first, so a duplicate result is ignored.
	panelMu     sync.Mutex
	pending     map[string]chan *PanelResult
	panelClosed bool

	// commandIDs tracks commands delivered on this socket so a disconnect can
	// report them unknown. It is per socket: a replacement connection must not
	// mark the new socket's commands unknown when the old one exits.
	commandMu  sync.Mutex
	commandIDs map[string]struct{}
}

var upgrader = websocket.Upgrader{
	// The credential is checked before the upgrade; browser-style requests that
	// carry an Origin header are closed with 4403 immediately afterwards.
	CheckOrigin: func(*http.Request) bool { return true },
}

// NewHub builds a hub around st, filling zero options with the protocol
// defaults. It also clears persisted presence flags: after a crash no socket is
// live, so any stored "online" value is stale until a client reconnects.
func NewHub(st *store.Store, opts Options) *Hub {
	opts = normalizeOptions(opts)
	if st != nil {
		_ = st.ClearOnline()
	}
	return &Hub{
		store:      st,
		opts:       opts,
		updates:    make(chan struct{}, 1),
		flushEvery: telemetryFlushInterval,
		commandTTL: defaultCommandTTL,
		clients:    map[int64]*client{},
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// normalizeOptions replaces zero option values with the contract defaults.
func normalizeOptions(opts Options) Options {
	if opts.HeartbeatSeconds <= 0 {
		opts.HeartbeatSeconds = defaultHeartbeatSeconds
	}
	if opts.TelemetryMinInterval <= 0 {
		opts.TelemetryMinInterval = defaultTelemetryInterval
	}
	if opts.MaxMessageBytes <= 0 {
		opts.MaxMessageBytes = defaultMaxMessageBytes
	}
	if opts.PanelTimeout <= 0 {
		opts.PanelTimeout = defaultPanelTimeout
	}
	if opts.MaxPanelInFlight <= 0 {
		opts.MaxPanelInFlight = defaultMaxPanelInFlight
	}
	return opts
}

// Start runs the heartbeat sweep and the telemetry flush loop until ctx is
// cancelled or Stop is called. It may be started once.
func (h *Hub) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	h.lifeMu.Lock()
	if h.started {
		h.lifeMu.Unlock()
		return
	}
	h.started = true
	h.lifeMu.Unlock()
	defer close(h.done)

	sweep := time.NewTicker(heartbeatSweepInterval)
	defer sweep.Stop()
	flushEvery := h.flushEvery
	if flushEvery <= 0 {
		flushEvery = telemetryFlushInterval
	}
	telemetry := time.NewTicker(flushEvery)
	defer telemetry.Stop()
	persist := time.NewTicker(persistInterval)
	defer persist.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ctx.Done():
			return
		case now := <-sweep.C:
			h.sweep(now)
		case <-telemetry.C:
			h.flushTelemetry()
		case <-persist.C:
			h.flush()
		}
	}
}

// Stop ends the background loops, closes every live socket, waits for the
// connection handlers to finish, and flushes pending telemetry to disk. It is
// safe to call more than once.
func (h *Hub) Stop() {
	h.stopOnce.Do(func() { close(h.stopCh) })
	h.lifeMu.Lock()
	started := h.started
	h.lifeMu.Unlock()
	if started {
		<-h.done
	}

	// Refuse new sockets, then close the live ones so their read loops exit.
	h.mu.Lock()
	h.stopping = true
	clients := make([]*client, 0, len(h.clients))
	for id, c := range h.clients {
		clients = append(clients, c)
		delete(h.clients, id)
		_ = h.store.SetOnline(id, false, time.Now())
	}
	h.mu.Unlock()
	for _, c := range clients {
		c.closeWith(websocketCloseGoingAway, "server shutting down")
	}
	h.conns.Wait()
	// Handlers are done, so any coalesced frame they produced can be stored.
	for _, c := range clients {
		h.flushClient(c)
	}
	h.flush()
}

// Updates returns the change-notification channel used by the dashboard SSE
// stream. It is buffered so notify never blocks.
func (h *Hub) Updates() <-chan struct{} {
	return h.updates
}

// Online reports whether an installation currently has a live socket.
func (h *Hub) Online(id int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.clients[id]
	return ok
}

// CloseInstallation closes the live socket for id, if any, and marks the
// installation offline. Pending panel calls fail with ErrOffline, delivered
// commands become unknown, and a coalesced telemetry frame is stored before
// the socket disappears.
func (h *Hub) CloseInstallation(id int64, code int, reason string) {
	if code < 3000 || code > 4999 {
		code = websocketCloseForbidden
	}
	h.mu.Lock()
	c := h.clients[id]
	if c != nil {
		delete(h.clients, id)
	}
	_ = h.store.SetOnline(id, false, time.Now())
	h.mu.Unlock()
	if c != nil {
		c.closeWith(code, reason)
		c.failPending()
		_ = c.failCommands(h.store)
		h.flushClient(c)
	}
	h.notify()
}

// SendCommand records a command for an online installation and writes it to
// the socket. It returns the command id; the contract reports the outcome
// asynchronously (ack, result, expiry, or disconnect).
func (h *Hub) SendCommand(id int64, command string) (string, error) {
	h.mu.Lock()
	c := h.clients[id]
	h.mu.Unlock()
	if c == nil {
		return "", ErrOffline
	}
	inst, ok := h.store.Installation(id)
	if !ok {
		return "", ErrOffline
	}

	now := time.Now()
	cmdID := newID(commandIDTag)
	cmd := store.Command{
		ID:             cmdID,
		InstallationID: id,
		DiscordID:      inst.DiscordID,
		Command:        command,
		CreatedAt:      now.UnixMilli(),
		ExpiresAt:      now.Add(h.commandTTL).UnixMilli(),
		State:          "accepted",
	}
	if err := h.store.AddCommand(cmd); err != nil {
		return "", err
	}
	c.trackCommand(cmdID)
	// The command is marked delivered before its frame is queued: the ack
	// transition is delivered→received, so an ack that races the write pump
	// must still find the command delivered.
	if !h.store.TransitionCommand(cmdID, id, []string{"accepted"}, "delivered", "") {
		c.untrackCommand(cmdID)
		return "", errors.New("relay: command state could not be recorded")
	}
	frame := map[string]any{
		"type":      "command",
		"id":        cmdID,
		"command":   command,
		"createdAt": cmd.CreatedAt,
		"expiresAt": cmd.ExpiresAt,
	}
	if !c.sendFrame(frame) {
		c.untrackCommand(cmdID)
		if h.store.TransitionCommand(cmdID, id, []string{"delivered"}, "unknown", "") {
			h.notify()
		}
		return "", ErrOffline
	}
	h.notify()
	ttl := h.commandTTL
	time.AfterFunc(ttl, func() {
		if h.store.TransitionCommand(cmdID, id,
			[]string{"accepted", "delivered", "received"}, "expired", "") {
			c.untrackCommand(cmdID)
			h.notify()
		}
	})
	return cmdID, nil
}

// PanelRequest relays one panel frame to an online installation and waits for
// the matching panel_result. At most Options.MaxPanelInFlight calls may be
// outstanding per installation; a disconnect fails every pending call with
// ErrOffline.
func (h *Hub) PanelRequest(ctx context.Context, id int64, frame map[string]any) (*PanelResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	h.mu.Lock()
	c := h.clients[id]
	h.mu.Unlock()
	if c == nil {
		return nil, ErrOffline
	}
	inst, ok := h.store.Installation(id)
	if !ok {
		return nil, ErrOffline
	}
	if !hasCapability(inst.Capabilities, "panel") {
		return nil, ErrNoPanel
	}

	reqID := newID(panelIDTag)
	out := make(map[string]any, len(frame)+3)
	for k, v := range frame {
		out[k] = v
	}
	out["type"] = "panel"
	out["id"] = reqID
	out["expiresAt"] = time.Now().Add(panelExpiry).UnixMilli()

	answer := make(chan *PanelResult, 1)
	if err := c.registerPending(reqID, answer, h.opts.MaxPanelInFlight); err != nil {
		return nil, err
	}
	defer c.forgetPending(reqID)

	if !c.sendFrame(out) {
		return nil, ErrOffline
	}

	timer := time.NewTimer(h.opts.PanelTimeout)
	defer timer.Stop()
	select {
	case res := <-answer:
		if res == nil {
			return nil, ErrOffline
		}
		if res.Encoding == "base64" {
			body, err := decodePanelBody(res.Body)
			if err != nil {
				return nil, err
			}
			res.Body = body
		}
		return res, nil
	case <-timer.C:
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrOffline
	}
}

// registerPending atomically checks the in-flight limit and registers the
// request's answer channel.
func (c *client) registerPending(id string, ch chan *PanelResult, limit int) error {
	c.panelMu.Lock()
	defer c.panelMu.Unlock()
	if c.panelClosed {
		return ErrOffline
	}
	if len(c.pending) >= limit {
		return ErrBusy
	}
	c.pending[id] = ch
	return nil
}

func (c *client) forgetPending(id string) {
	c.panelMu.Lock()
	delete(c.pending, id)
	c.panelMu.Unlock()
}

// failPending wakes every waiter with a nil answer, which PanelRequest maps to
// ErrOffline. It is idempotent.
func (c *client) failPending() {
	c.panelMu.Lock()
	if c.panelClosed {
		c.panelMu.Unlock()
		return
	}
	c.panelClosed = true
	pending := c.pending
	c.pending = map[string]chan *PanelResult{}
	c.panelMu.Unlock()
	for _, ch := range pending {
		select {
		case ch <- nil:
		default:
		}
	}
}

// resolvePanel delivers one answer. The entry is removed before the send, so a
// duplicate panel_result carrying the same id is ignored.
func (c *client) resolvePanel(id string, res *PanelResult) {
	if id == "" {
		return
	}
	c.panelMu.Lock()
	ch := c.pending[id]
	delete(c.pending, id)
	c.panelMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- res:
	default:
	}
}

// trackCommand remembers a command delivered on this socket.
func (c *client) trackCommand(id string) {
	c.commandMu.Lock()
	c.commandIDs[id] = struct{}{}
	c.commandMu.Unlock()
}

func (c *client) untrackCommand(id string) {
	c.commandMu.Lock()
	delete(c.commandIDs, id)
	c.commandMu.Unlock()
}

// failCommands reports every command delivered on this socket that has no
// terminal state yet as unknown. It reports whether anything changed.
func (c *client) failCommands(st *store.Store) bool {
	c.commandMu.Lock()
	ids := c.commandIDs
	c.commandIDs = map[string]struct{}{}
	c.commandMu.Unlock()
	changed := false
	for id := range ids {
		if st.TransitionCommand(id, c.installationID,
			[]string{"delivered", "received"}, "unknown", "") {
			changed = true
		}
	}
	return changed
}

// ServeWS authenticates a client socket, performs the hello/welcome handshake,
// and then relays frames until the connection closes.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		writeUnauthorized(w)
		return
	}
	credential := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if credential == "" {
		writeUnauthorized(w)
		return
	}
	inst, ok := h.store.InstallationByCredential(store.HashToken(credential))
	if !ok {
		writeUnauthorized(w)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Browsers always send Origin; the mod never does. The credential has
	// already been accepted, so answer with a clean application close code.
	if r.Header.Get("Origin") != "" {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocketCloseForbidden, "origin not allowed"))
		_ = conn.Close()
		return
	}
	conn.SetReadLimit(maxReadBytes)

	c := &client{
		hub:            h,
		conn:           conn,
		send:           make(chan []byte, sendBuffer),
		installationID: inst.ID,
		closed:         make(chan struct{}),
		pending:        map[string]chan *PanelResult{},
		commandIDs:     map[string]struct{}{},
	}
	c.lastSeen.Store(time.Now().UnixMilli())

	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		c.closeWith(websocketCloseGoingAway, "server shutting down")
		return
	}
	old := h.clients[inst.ID]
	h.clients[inst.ID] = c
	h.conns.Add(1)
	// Presence is written while the map lock is held so a dying replacement
	// cannot mark the installation offline after the new socket is registered.
	_ = h.store.SetOnline(inst.ID, true, time.Now())
	h.mu.Unlock()
	defer h.conns.Done()
	if old != nil {
		old.closeWith(websocketCloseReplaced, "replaced by a newer connection")
		// The old socket's read loop may not run again before its pending
		// work stalls, so release its panel calls, report its unanswered
		// commands, and persist any coalesced telemetry here.
		old.failPending()
		_ = old.failCommands(h.store)
		h.flushClient(old)
	}

	h.notify()

	go c.writePump()

	_ = conn.SetReadDeadline(time.Now().Add(helloTimeout))
	_, data, err := conn.ReadMessage()
	if err != nil {
		h.dropClient(c)
		return
	}
	c.lastSeen.Store(time.Now().UnixMilli())

	var hello struct {
		Type      string `json:"type"`
		Protocols []int  `json:"protocols"`
	}
	if err := json.Unmarshal(data, &hello); err != nil ||
		hello.Type != "hello" || !hasProtocol(hello.Protocols, 1) {
		c.closeWith(websocketCloseProtocol, "protocol 1 required")
		h.dropClient(c)
		return
	}
	c.sendJSON(Welcome(inst.ID, h.opts))

	for {
		_ = conn.SetReadDeadline(time.Now().Add(clientSilenceTimeout))
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		c.lastSeen.Store(time.Now().UnixMilli())
		h.handleFrame(c, data)
	}
	h.dropClient(c)
}

// Welcome builds the protocol-1 welcome frame from the hub's options. The
// advertised commands are the ones the relay forwards; optional client
// features stay off.
func Welcome(id int64, opts Options) map[string]any {
	opts = normalizeOptions(opts)
	return map[string]any{
		"type":                   "welcome",
		"protocol":               1,
		"installationId":         id,
		"heartbeatSeconds":       opts.HeartbeatSeconds,
		"telemetryMinIntervalMs": opts.TelemetryMinInterval.Milliseconds(),
		"maxMessageBytes":        opts.MaxMessageBytes,
		"panelTimeoutMs":         opts.PanelTimeout.Milliseconds(),
		"commands":               append([]string{}, welcomeCommands...),
	}
}

// handleFrame dispatches one post-handshake frame. Malformed or refused
// frames produce a fixed error frame; the socket stays open unless the read
// side fails.
func (h *Hub) handleFrame(c *client, data []byte) {
	var env struct {
		Type   string          `json:"type"`
		At     json.RawMessage `json:"at"`
		ID     string          `json:"id"`
		Status json.RawMessage `json:"status"`
		Reason string          `json:"reason"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		c.sendJSON(errorFrame("invalid frame"))
		return
	}

	switch env.Type {
	case "ping":
		pong := map[string]any{"type": "pong"}
		if len(env.At) > 0 {
			var at json.Number
			if err := json.Unmarshal(env.At, &at); err == nil {
				pong["at"] = at
			}
		}
		c.sendJSON(pong)

	case "telemetry":
		tel, err := ParseTelemetry(data)
		if err != nil {
			if errors.Is(err, errSensitive) {
				c.sendJSON(errorFrame("telemetry looks like a credential or a local path and was refused"))
			} else {
				c.sendJSON(errorFrame("telemetry frame refused"))
			}
			return
		}
		c.queueTelemetry(tel)

	case "ack":
		if env.ID != "" {
			// Only the owning installation may move its own command forward;
			// ack is only legal once the command was delivered.
			if h.store.TransitionCommand(env.ID, c.installationID,
				[]string{"delivered"}, "received", "") {
				h.notify()
			}
		}

	case "result":
		status := rawString(env.Status)
		if env.ID != "" && (status == "completed" || status == "rejected") {
			reason := truncate(env.Reason, maxTextLen)
			if sensitive(reason) {
				reason = ""
			}
			// A result is only legal after the client acknowledged delivery,
			// and terminal states are never overwritten. Ownership is checked
			// by the store, so a foreign installation's id changes nothing.
			if h.store.TransitionCommand(env.ID, c.installationID,
				[]string{"received"}, status, reason) {
				h.notify()
			}
		}

	case "panel_result":
		h.handlePanelResult(c, data)

	case "pong", "error":
		// Nothing to do: pongs only prove liveness, and client errors are
		// informational.

	default:
		c.sendJSON(errorFrame("unsupported frame type"))
	}
}

// handlePanelResult resolves the pending call matching the frame's id. An
// unknown or duplicate id is ignored, so the first answer wins.
func (h *Hub) handlePanelResult(c *client, data []byte) {
	var frame struct {
		ID          string          `json:"id"`
		Status      json.RawMessage `json:"status"`
		ContentType string          `json:"contentType"`
		Body        string          `json:"body"`
		Encoding    string          `json:"encoding"`
	}
	if err := json.Unmarshal(data, &frame); err != nil || frame.ID == "" {
		return
	}
	c.resolvePanel(frame.ID, &PanelResult{
		Status:      panelStatus(frame.Status),
		ContentType: frame.ContentType,
		Body:        []byte(frame.Body),
		Encoding:    frame.Encoding,
	})
}

// panelStatus reads the numeric HTTP status from a panel_result. A missing or
// out-of-range value is reported as 502 so the web layer never writes an
// invalid header.
func panelStatus(raw json.RawMessage) int {
	var n json.Number
	if len(raw) == 0 || json.Unmarshal(raw, &n) != nil {
		return http.StatusBadGateway
	}
	v, err := n.Int64()
	if err != nil || v < 100 || v > 599 {
		return http.StatusBadGateway
	}
	return int(v)
}

// decodePanelBody decodes a base64 panel result, accepting padded and unpadded
// standard or URL alphabets.
func decodePanelBody(body []byte) ([]byte, error) {
	s := string(body)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil {
			return out, nil
		}
	}
	return nil, errPanelBody
}

// rawString decodes a JSON string field, returning "" for any other type.
func rawString(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// newID returns prefix followed by 16 base64url characters.
func newID(prefix string) string {
	var b [idBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is effectively impossible; keep ids unique anyway.
		binary.LittleEndian.PutUint64(b[:8], idFallback.Add(1))
		binary.LittleEndian.PutUint64(b[8:], uint64(time.Now().UnixNano()))
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:])
}

func hasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// sweep closes sockets that have been silent longer than the contract allows.
func (h *Hub) sweep(now time.Time) {
	h.mu.Lock()
	stale := make([]*client, 0, 1)
	for _, c := range h.clients {
		if now.Sub(time.UnixMilli(c.lastSeen.Load())) > clientSilenceTimeout {
			stale = append(stale, c)
		}
	}
	h.mu.Unlock()
	for _, c := range stale {
		c.closeWith(websocketCloseHeartbeat, "no heartbeat")
	}
}

// dropClient forgets c when it is still the current socket and marks the
// installation offline. A socket replaced by a newer one is ignored for
// presence, but its own pending panel calls and unanswered commands still have
// to be released: they belong to that socket, not to the installation.
func (h *Hub) dropClient(c *client) {
	c.close()
	h.mu.Lock()
	current := h.clients[c.installationID] == c
	if current {
		delete(h.clients, c.installationID)
		_ = h.store.SetOnline(c.installationID, false, time.Now())
	}
	h.mu.Unlock()

	c.failPending()
	changed := c.failCommands(h.store)
	// Persist the last coalesced frame before the client disappears. This runs
	// for a replaced socket too: its read loop may have queued one final frame
	// after the replacement flush, and losing it was a defect found in review.
	// A flush with nothing pending is a no-op.
	h.flushClient(c)
	if current || changed {
		h.notify()
	}
}

func (h *Hub) notify() {
	select {
	case h.updates <- struct{}{}:
	default:
	}
}

func (h *Hub) flush() {
	_ = h.store.SaveNow()
}

// queueTelemetry stores tel immediately unless a frame was stored less than
// TelemetryMinInterval ago, in which case it replaces the pending frame. The
// hub tick writes the newest pending frame once per interval.
func (c *client) queueTelemetry(tel *store.Telemetry) {
	now := time.Now()
	c.telemetryMu.Lock()
	if !c.lastTelemetryAt.IsZero() &&
		now.Sub(c.lastTelemetryAt) < c.hub.opts.TelemetryMinInterval {
		c.pendingTelemetry = tel
		c.telemetryMu.Unlock()
		return
	}
	c.pendingTelemetry = nil
	c.lastTelemetryAt = now
	c.telemetryMu.Unlock()
	if err := c.hub.store.SetTelemetry(c.installationID, tel, now); err == nil {
		c.hub.notify()
	}
}

// flushTelemetry stores the newest pending frame for every live client.
func (h *Hub) flushTelemetry() {
	h.mu.Lock()
	clients := make([]*client, 0, len(h.clients))
	for _, c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		h.flushClient(c)
	}
}

// flushClient stores c's pending frame, if any. The read-and-clear is guarded
// by telemetryMu so a concurrent tick or disconnect cannot store it twice.
func (h *Hub) flushClient(c *client) {
	c.telemetryMu.Lock()
	tel := c.pendingTelemetry
	c.pendingTelemetry = nil
	now := time.Now()
	if tel != nil {
		c.lastTelemetryAt = now
	}
	c.telemetryMu.Unlock()
	if tel == nil {
		return
	}
	if err := h.store.SetTelemetry(c.installationID, tel, now); err == nil {
		h.notify()
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"message":"invalid credential","status":401}`))
}

func errorFrame(message string) map[string]any {
	return map[string]any{"type": "error", "message": message}
}

func hasProtocol(list []int, want int) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

// sendJSON queues v for the write pump unless the client is already closed.
func (c *client) sendJSON(v any) {
	_ = c.sendFrame(v)
}

// sendFrame marshals v and queues it, reporting whether the frame was
// accepted by the send channel.
func (c *client) sendFrame(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return c.enqueue(b)
}

// enqueue hands one frame to the write pump. It reports false when the client
// closed first.
func (c *client) enqueue(b []byte) bool {
	select {
	case c.send <- b:
		return true
	case <-c.closed:
		return false
	}
}

func (c *client) writePump() {
	for {
		select {
		case b := <-c.send:
			if err := c.writeMessage(websocket.TextMessage, b); err != nil {
				c.close()
				return
			}
		case <-c.closed:
			return
		}
	}
}

func (c *client) writeMessage(messageType int, b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return c.conn.WriteMessage(messageType, b)
}

// close tears down the socket without a close frame.
func (c *client) close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}

// closeWith sends an application close frame, then tears down the socket.
func (c *client) closeWith(code int, reason string) {
	c.once.Do(func() {
		close(c.closed)
		_ = c.writeMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(code, safeCloseReason(reason)))
		_ = c.conn.Close()
	})
}

// safeCloseReason bounds a close reason to the 123-byte control-frame budget
// without splitting a UTF-8 sequence.
func safeCloseReason(reason string) string {
	for len(reason) > maxCloseReasonBytes {
		_, size := utf8.DecodeLastRuneInString(reason)
		reason = reason[:len(reason)-size]
	}
	return reason
}
