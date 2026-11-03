package relay

import (
	"context"
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
	telemetryFlushInterval   = 5 * time.Second
	helloTimeout             = 10 * time.Second
	clientSilenceTimeout     = 80 * time.Second
	writeTimeout             = 10 * time.Second
	sendBuffer               = 16
	maxCloseReasonBytes      = 120
	websocketCloseGoingAway  = 1001
	websocketCloseProtocol   = 4400
	websocketCloseForbidden  = 4403
	websocketCloseHeartbeat  = 4408
	websocketCloseReplaced   = 4409
)

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
// Telemetry is written to the store's in-memory state on every frame; the
// Start loop flushes it to disk every five seconds and Stop flushes once more.
type Hub struct {
	store   *store.Store
	opts    Options
	updates chan struct{}

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
}

var upgrader = websocket.Upgrader{
	// The credential is checked before the upgrade; browser-style requests that
	// carry an Origin header are closed with 4403 immediately afterwards.
	CheckOrigin: func(*http.Request) bool { return true },
}

// NewHub builds a hub around st, filling zero options with the protocol
// defaults.
func NewHub(st *store.Store, opts Options) *Hub {
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
	return &Hub{
		store:   st,
		opts:    opts,
		updates: make(chan struct{}, 1),
		clients: map[int64]*client{},
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
	}
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
	flush := time.NewTicker(telemetryFlushInterval)
	defer flush.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ctx.Done():
			return
		case now := <-sweep.C:
			h.sweep(now)
		case <-flush.C:
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
// installation offline.
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
	}
	h.notify()
}

// SendCommand is replaced by the command broker in the next task.
func (h *Hub) SendCommand(id int64, command string) (string, error) {
	return "", ErrOffline
}

// PanelRequest is replaced by the panel broker in the next task.
func (h *Hub) PanelRequest(ctx context.Context, id int64, frame map[string]any) (*PanelResult, error) {
	return nil, ErrOffline
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
	conn.SetReadLimit(int64(h.opts.MaxMessageBytes))

	c := &client{
		hub:            h,
		conn:           conn,
		send:           make(chan []byte, sendBuffer),
		installationID: inst.ID,
		closed:         make(chan struct{}),
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
	c.sendJSON(Welcome(inst.ID))

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

// Welcome builds the protocol-1 welcome frame. The advertised commands are
// the ones the relay forwards; optional client features stay off.
func Welcome(id int64) map[string]any {
	return map[string]any{
		"type":                   "welcome",
		"protocol":               1,
		"installationId":         id,
		"heartbeatSeconds":       defaultHeartbeatSeconds,
		"telemetryMinIntervalMs": defaultTelemetryInterval.Milliseconds(),
		"maxMessageBytes":        defaultMaxMessageBytes,
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
		Status string          `json:"status"`
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
		if err := h.store.SetTelemetry(c.installationID, tel, time.Now()); err == nil {
			h.notify()
		}

	case "ack":
		if env.ID != "" {
			if err := h.store.UpdateCommand(env.ID, "received", ""); err == nil {
				h.notify()
			}
		}

	case "result":
		if env.ID != "" && (env.Status == "completed" || env.Status == "rejected") {
			reason := truncate(env.Reason, maxTextLen)
			if sensitive(reason) {
				reason = ""
			}
			if err := h.store.UpdateCommand(env.ID, env.Status, reason); err == nil {
				h.notify()
			}
		}

	case "panel_result":
		// The panel broker lands in the next task; there is nothing pending yet.

	case "pong", "error":
		// Nothing to do: pongs only prove liveness, and client errors are
		// informational.

	default:
		c.sendJSON(errorFrame("unsupported frame type"))
	}
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
// installation offline. A socket replaced by a newer one is ignored.
func (h *Hub) dropClient(c *client) {
	c.close()
	h.mu.Lock()
	current := h.clients[c.installationID] == c
	if current {
		delete(h.clients, c.installationID)
		_ = h.store.SetOnline(c.installationID, false, time.Now())
	}
	h.mu.Unlock()
	if !current {
		return
	}
	h.notify()
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
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case c.send <- b:
	case <-c.closed:
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
