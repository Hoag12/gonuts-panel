package relay

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"gonutspanel/internal/store"
)

func TestParseTelemetryClampsAndRefusesSecrets(t *testing.T) {
	j := []byte(`{"type":"telemetry","at":1,"state":"SCANNING","account":"Acc","bank":99999999999999999,
	  "listed":-5,"slots":18,"trades":3,"profit":{"h1":10,"h24":20,"source":"booked"},
	  "mascotFace":"WATCH","swarm":{"enabled":false},"detail":"ok"}`)
	tel, err := ParseTelemetry(j)
	if err != nil {
		t.Fatal(err)
	}
	if tel.Listed != 0 || tel.Bank == nil || *tel.Bank != 1000000000000 || tel.State != "SCANNING" {
		t.Fatalf("%+v", tel)
	}
	bad := []byte(`{"type":"telemetry","detail":"token gni1_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"}`)
	if _, err := ParseTelemetry(bad); err == nil {
		t.Fatal("credential-looking detail accepted")
	}
}

func TestPairResponseUsesConfiguredOrigin(t *testing.T) {
	m := PairResponse("https://panel.example.com", 12, "gni1_x", "Laptop")
	if m["wsUrl"] != "wss://panel.example.com/dashboard/ws/client" ||
		m["checkUrl"] != "https://panel.example.com/dashboard/api/client/check" {
		t.Fatalf("%+v", m)
	}
	local := PairResponse("http://localhost:8080", 13, "gni1_y", "Local")
	if local["wsUrl"] != "ws://localhost:8080/dashboard/ws/client" {
		t.Fatalf("local wsUrl=%v", local["wsUrl"])
	}
	if m["installationId"] != int64(12) || m["credential"] != "gni1_x" ||
		m["protocol"] != 1 || m["maxMessageBytes"] != 32768 {
		t.Fatalf("unexpected fields: %+v", m)
	}
}

func TestParseTelemetryRejectsOversizedFrame(t *testing.T) {
	raw := []byte(`{"detail":"` + strings.Repeat("a", maxTelemetryBytes) + `"}`)
	if _, err := ParseTelemetry(raw); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestParseTelemetryRejectsNonObjectsAndWrongTypes(t *testing.T) {
	for _, raw := range []string{``, `[]`, `"x"`, `null`, `{"listed":"many"}`, `{"profit":7}`} {
		if _, err := ParseTelemetry([]byte(raw)); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestParseTelemetryUnknownStateAndCountClamps(t *testing.T) {
	tel, err := ParseTelemetry([]byte(`{"state":"DANCING","listed":2000000,"slots":-1,"trades":5,"bank":-99999999999999999}`))
	if err != nil {
		t.Fatal(err)
	}
	if tel.State != "UNKNOWN" || tel.Listed != maxCount || tel.Slots != 0 || tel.Trades != 5 {
		t.Fatalf("%+v", tel)
	}
	if tel.Bank == nil || *tel.Bank != -maxMoney {
		t.Fatalf("bank=%v", tel.Bank)
	}
}

func TestParseTelemetryIntervals(t *testing.T) {
	tel, err := ParseTelemetry([]byte(`{"profit":{"h1":-5000000000000,"h24":7,"source":"booked"},
		"sales":{"h1":-3,"h24":99999999},"purchases":{},"listings":{"h24":2},"reprices":{"h1":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tel.Profit == nil || tel.Profit.H1 == nil || *tel.Profit.H1 != -maxMoney ||
		tel.Profit.H24 == nil || *tel.Profit.H24 != 7 || tel.Profit.Source != "booked" {
		t.Fatalf("profit=%+v", tel.Profit)
	}
	if tel.Sales == nil || tel.Sales.H1 == nil || *tel.Sales.H1 != 0 ||
		tel.Sales.H24 == nil || *tel.Sales.H24 != maxCount {
		t.Fatalf("sales=%+v", tel.Sales)
	}
	if tel.Purchases == nil || tel.Purchases.H1 != nil || tel.Purchases.H24 != nil {
		t.Fatalf("purchases=%+v", tel.Purchases)
	}
	if tel.Listings == nil || tel.Listings.H24 == nil || *tel.Listings.H24 != 2 {
		t.Fatalf("listings=%+v", tel.Listings)
	}
	if tel.Reprices == nil || tel.Reprices.H1 == nil || *tel.Reprices.H1 != 1 {
		t.Fatalf("reprices=%+v", tel.Reprices)
	}
}

func TestParseTelemetryRejectsSensitiveStrings(t *testing.T) {
	for _, raw := range []string{
		`{"detail":"C:\\Users\\me\\log.txt"}`,
		`{"lastAction":"read /home/me/file"}`,
		`{"account":"/Users/me"}`,
		`{"detail":"dbay_secret"}`,
		`{"detail":"Bearer abcdef"}`,
		`{"detail":"` + strings.Repeat("QUJD", 12) + `"}`,
	} {
		if _, err := ParseTelemetry([]byte(raw)); err == nil {
			t.Fatalf("accepted sensitive frame %q", raw)
		}
	}
}

func TestParseTelemetryTruncatesStrings(t *testing.T) {
	tel, err := ParseTelemetry([]byte(`{"account":"` + strings.Repeat("ab ", 20) + `","detail":"` +
		strings.Repeat("cd ", 67) + `","build":"` + strings.Repeat("1", 70) + `","mascotFace":"` +
		strings.Repeat("c", 20) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(tel.Account) != maxAccountLen || len(tel.Detail) != maxTextLen ||
		len(tel.Build) != maxBuildLen || len(tel.MascotFace) != maxMascotLen {
		t.Fatalf("%+v", tel)
	}
}

func TestValidators(t *testing.T) {
	if !ValidName("") || !ValidName("My Bot (2).-") || ValidName("bad/name") || ValidName("gni1_secret") {
		t.Fatal("ValidName")
	}
	if !ValidName(strings.Repeat("a ", 24)) || ValidName(strings.Repeat("a ", 25)) {
		t.Fatal("ValidName length")
	}
	if !ValidBuild("") || !ValidBuild("0.1.2-rc.1") || ValidBuild("build with space") {
		t.Fatal("ValidBuild")
	}
	if !ValidHive("") || !ValidHive("hive_1-x") || ValidHive("hive 1") {
		t.Fatal("ValidHive")
	}
	// Unknown but well-shaped capabilities are accepted; only the shape and
	// the count are bounded.
	if !ValidCaps(nil) || !ValidCaps([]string{"panel", "pause", "read_savings"}) ||
		ValidCaps([]string{"shell!"}) || ValidCaps([]string{strings.Repeat("a", 33)}) {
		t.Fatal("ValidCaps")
	}
	tooMany := make([]string, maxCapabilities+1)
	for i := range tooMany {
		tooMany[i] = "panel"
	}
	if ValidCaps(tooMany) {
		t.Fatal("ValidCaps accepted too many entries")
	}
}

// modCapabilities is the exact list the real mod advertises in its pairing
// body and hello frame (DashboardProtocol.CAPABILITIES).
var modCapabilities = []string{
	"pause", "resume", "snapshot", "panel", "swarm_enable", "swarm_disable",
	"swarm_rank", "swarm_staff", "read_savings", "data_use", "settings_analysis",
	"diagnostic_history",
}

// TestHandshakeAcceptsRealModCapabilities is the C1 regression: the relay used
// to know only four capability names, so the real mod's twelve made every
// handshake fail. A hello carrying all twelve must still be answered.
func TestHandshakeAcceptsRealModCapabilities(t *testing.T) {
	r := newWSRig(t, Options{HeartbeatSeconds: 20, MaxMessageBytes: 32768, MaxPanelInFlight: 8})
	conn, resp, err := r.dial(t, http.Header{"Authorization": {"Bearer " + r.cred}})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hello := helloFrame()
	hello["capabilities"] = modCapabilities
	if err := conn.WriteJSON(hello); err != nil {
		t.Fatal(err)
	}
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	if welcome["type"] != "welcome" {
		t.Fatalf("welcome=%v", welcome)
	}
}

func TestWSHandshakeTelemetryAndPresence(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := NewHub(st, Options{HeartbeatSeconds: 20, MaxMessageBytes: 32768, MaxPanelInFlight: 8})
	go h.Start(context.Background())
	defer h.Stop()
	ts := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	// Pair a credential directly through store.
	code, _, err := st.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst, cred, err := st.RedeemCode(code, "Bot", "0.1.2", "", []string{"panel"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?x=1", http.Header{"Authorization": {"Bearer " + cred}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteJSON(map[string]any{"type": "hello", "protocols": []int{1}, "name": "Bot", "build": "0.1.2", "hive": "", "capabilities": []string{"panel"}}); err != nil {
		t.Fatal(err)
	}
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	if welcome["type"] != "welcome" {
		t.Fatalf("welcome=%v", welcome)
	}
	if err := conn.WriteJSON(map[string]any{"type": "telemetry", "at": time.Now().UnixMilli(), "state": "SCANNING", "account": "Acc", "listed": 1, "slots": 18}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !h.Online(inst.ID) {
		t.Fatal("not online")
	}
	got, ok := st.Installation(inst.ID)
	if !ok || got.Telemetry == nil || got.Telemetry.Account != "Acc" {
		t.Fatalf("telemetry=%+v", got)
	}
}

// wsRig wires a store, a hub, and an httptest server with one paired
// installation. Tests dial it with bearer credentials.
type wsRig struct {
	dir   string
	store *store.Store
	hub   *Hub
	inst  *store.Installation
	cred  string
	ts    *httptest.Server
}

func newWSRig(t *testing.T, opts Options) *wsRig {
	t.Helper()
	return newWSRigWith(t, opts, nil)
}

// newWSRigWith is newWSRig with a hook to tweak the hub before Start, used to
// make telemetry flushing deterministic in tests.
func newWSRigWith(t *testing.T, opts Options, mutate func(*Hub)) *wsRig {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHub(st, opts)
	if mutate != nil {
		mutate(h)
	}
	go h.Start(context.Background())
	ts := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	code, _, err := st.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst, cred, err := st.RedeemCode(code, "Bot", "0.1.2", "", []string{"panel"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := &wsRig{dir: dir, store: st, hub: h, inst: inst, cred: cred, ts: ts}
	t.Cleanup(func() {
		ts.Close()
		h.Stop()
		_ = st.Close()
	})
	return r
}

// pairInstallation adds a second paired installation, used to prove that one
// installation cannot mutate another installation's commands.
func pairInstallation(t *testing.T, st *store.Store, discordID, name string) (*store.Installation, string) {
	t.Helper()
	code, _, err := st.CreateCode(discordID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst, cred, err := st.RedeemCode(code, name, "0.1.2", "", []string{"panel"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return inst, cred
}

func (r *wsRig) url() string {
	return "ws" + strings.TrimPrefix(r.ts.URL, "http")
}

func (r *wsRig) dial(t *testing.T, header http.Header) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	return websocket.DefaultDialer.Dial(r.url(), header)
}

func helloFrame() map[string]any {
	return map[string]any{"type": "hello", "protocols": []int{1}, "name": "Bot",
		"build": "0.1.2", "hive": "", "capabilities": []string{"panel"}}
}

// connect dials with the paired credential and completes the handshake.
func (r *wsRig) connect(t *testing.T) *websocket.Conn {
	t.Helper()
	return r.connectCred(t, r.cred)
}

// connectCred dials with an arbitrary credential and completes the handshake.
func (r *wsRig) connectCred(t *testing.T, cred string) *websocket.Conn {
	t.Helper()
	conn, resp, err := r.dial(t, http.Header{"Authorization": {"Bearer " + cred}})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.WriteJSON(helloFrame()); err != nil {
		t.Fatal(err)
	}
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	if welcome["type"] != "welcome" {
		t.Fatalf("welcome=%v", welcome)
	}
	return conn
}

func waitCondition(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func errCloseCode(err error) int {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return 0
}

// roundTrip sends a ping and waits for the pong. Frames are handled in order,
// so a pong proves that everything written before the ping was processed.
func roundTrip(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	if err := conn.WriteJSON(map[string]any{"type": "ping", "at": 1}); err != nil {
		t.Fatal(err)
	}
	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	if frame["type"] != "pong" {
		t.Fatalf("barrier frame=%v", frame)
	}
}

func TestNewHubFillsOptionDefaults(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := NewHub(st, Options{})
	if h.opts.HeartbeatSeconds != 20 || h.opts.TelemetryMinInterval != time.Second ||
		h.opts.MaxMessageBytes != 32768 || h.opts.PanelTimeout != 15*time.Second ||
		h.opts.MaxPanelInFlight != 8 {
		t.Fatalf("defaults=%+v", h.opts)
	}
	// Explicit values survive.
	custom := NewHub(st, Options{HeartbeatSeconds: 5, MaxMessageBytes: 1024})
	if custom.opts.HeartbeatSeconds != 5 || custom.opts.MaxMessageBytes != 1024 ||
		custom.opts.TelemetryMinInterval != time.Second {
		t.Fatalf("custom=%+v", custom.opts)
	}
}

func TestServeWSRejectsUnknownCredentialBeforeUpgrade(t *testing.T) {
	r := newWSRig(t, Options{})
	for _, header := range []http.Header{
		{},
		{"Authorization": {"Basic x"}},
		{"Authorization": {"Bearer "}},
		{"Authorization": {"Bearer gni1_not-a-real-credential"}},
	} {
		conn, resp, err := r.dial(t, header)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatalf("header %v: unexpected upgrade", header)
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("header %v: resp=%v err=%v", header, resp, err)
		}
		_ = resp.Body.Close()
	}
}

func TestServeWSRejectsBrowserOriginAfterUpgrade(t *testing.T) {
	r := newWSRig(t, Options{})
	conn, resp, err := r.dial(t, http.Header{
		"Authorization": {"Bearer " + r.cred},
		"Origin":        {"https://evil.example"},
	})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := conn.ReadMessage(); errCloseCode(err) != 4403 {
		t.Fatalf("expected 4403, got %v", err)
	}
}

func TestWSRejectsNonHelloFirstFrame(t *testing.T) {
	r := newWSRig(t, Options{})
	conn, resp, err := r.dial(t, http.Header{"Authorization": {"Bearer " + r.cred}})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteJSON(map[string]any{"type": "telemetry", "account": "Acc"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadMessage(); errCloseCode(err) != 4400 {
		t.Fatalf("expected 4400, got %v", err)
	}
}

func TestWSUnknownFrameErrorsButKeepsSocket(t *testing.T) {
	r := newWSRig(t, Options{})
	conn := r.connect(t)
	if err := conn.WriteJSON(map[string]any{"type": "nonsense"}); err != nil {
		t.Fatal(err)
	}
	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	if frame["type"] != "error" {
		t.Fatalf("frame=%v", frame)
	}
	if err := conn.WriteJSON(map[string]any{"type": "ping", "at": 42}); err != nil {
		t.Fatal(err)
	}
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	if frame["type"] != "pong" || frame["at"] != float64(42) {
		t.Fatalf("pong=%v", frame)
	}
}

func TestWSTelemetryRefusesSensitiveDetail(t *testing.T) {
	r := newWSRig(t, Options{})
	conn := r.connect(t)
	if err := conn.WriteJSON(map[string]any{"type": "telemetry", "state": "SCANNING",
		"detail": `C:\Users\me\secret.txt`}); err != nil {
		t.Fatal(err)
	}
	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	if frame["type"] != "error" {
		t.Fatalf("frame=%v", frame)
	}
	if msg, _ := frame["message"].(string); strings.Contains(msg, `C:\`) {
		t.Fatalf("error echoed the frame: %q", msg)
	}
	got, _ := r.store.Installation(r.inst.ID)
	if got.Telemetry != nil {
		t.Fatalf("sensitive telemetry stored: %+v", got.Telemetry)
	}
}

func TestWSHeartbeatSweepClosesStaleClient(t *testing.T) {
	r := newWSRig(t, Options{})
	conn := r.connect(t)
	r.hub.mu.Lock()
	c := r.hub.clients[r.inst.ID]
	r.hub.mu.Unlock()
	if c == nil {
		t.Fatal("client not tracked")
	}
	c.lastSeen.Store(time.Now().Add(-81 * time.Second).UnixMilli())
	r.hub.sweep(time.Now())
	if _, _, err := conn.ReadMessage(); errCloseCode(err) != 4408 {
		t.Fatalf("expected 4408, got %v", err)
	}
	waitCondition(t, "offline after heartbeat sweep", func() bool { return !r.hub.Online(r.inst.ID) })
}

func TestWSNewestSocketWins(t *testing.T) {
	r := newWSRig(t, Options{})
	first := r.connect(t)
	_ = r.connect(t)
	if _, _, err := first.ReadMessage(); errCloseCode(err) != 4409 {
		t.Fatalf("expected 4409, got %v", err)
	}
	if !r.hub.Online(r.inst.ID) {
		t.Fatal("new socket is not online")
	}
}

func TestCloseInstallationClosesAndMarksOffline(t *testing.T) {
	r := newWSRig(t, Options{})
	conn := r.connect(t)
	r.hub.CloseInstallation(r.inst.ID, 4403, "revoked")
	if _, _, err := conn.ReadMessage(); errCloseCode(err) != 4403 {
		t.Fatalf("expected 4403, got %v", err)
	}
	waitCondition(t, "offline", func() bool { return !r.hub.Online(r.inst.ID) })
	got, ok := r.store.Installation(r.inst.ID)
	if !ok || got.Online {
		t.Fatalf("installation still online: %+v", got)
	}
}

func TestStopFlushesTelemetry(t *testing.T) {
	r := newWSRig(t, Options{})
	conn := r.connect(t)
	if err := conn.WriteJSON(map[string]any{"type": "telemetry", "state": "SCANNING",
		"account": "FlushAcc", "listed": 2, "slots": 18}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, "telemetry in memory", func() bool {
		got, ok := r.store.Installation(r.inst.ID)
		return ok && got.Telemetry != nil && got.Telemetry.Account == "FlushAcc"
	})
	r.hub.Stop()
	reopened, err := store.Open(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, ok := reopened.Installation(r.inst.ID)
	if !ok || got.Telemetry == nil || got.Telemetry.Account != "FlushAcc" {
		t.Fatalf("telemetry not flushed: %+v", got)
	}
}

func TestHubStubsReturnOffline(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := NewHub(st, Options{})
	if _, err := h.SendCommand(1, "pause"); !errors.Is(err, ErrOffline) {
		t.Fatalf("SendCommand stub = %v", err)
	}
	if _, err := h.PanelRequest(context.Background(), 1, nil); !errors.Is(err, ErrOffline) {
		t.Fatalf("PanelRequest stub = %v", err)
	}
	if h.Updates() == nil {
		t.Fatal("nil updates channel")
	}
	h.CloseInstallation(1, 4403, "")
}

func TestWelcomeUsesHubOptions(t *testing.T) {
	opts := Options{
		HeartbeatSeconds:     7,
		TelemetryMinInterval: 1500 * time.Millisecond,
		MaxMessageBytes:      4096,
		PanelTimeout:         3 * time.Second,
	}
	w := Welcome(9, opts)
	if w["installationId"] != int64(9) || w["heartbeatSeconds"] != 7 ||
		w["telemetryMinIntervalMs"] != int64(1500) || w["maxMessageBytes"] != 4096 ||
		w["panelTimeoutMs"] != int64(3000) {
		t.Fatalf("welcome=%v", w)
	}
	// Zero options fall back to the contract defaults rather than advertising 0.
	def := Welcome(1, Options{})
	if def["heartbeatSeconds"] != 20 || def["telemetryMinIntervalMs"] != int64(1000) ||
		def["maxMessageBytes"] != 32768 || def["panelTimeoutMs"] != int64(15000) {
		t.Fatalf("default welcome=%v", def)
	}
}

func TestWSReadLimitAllowsLargePanelResult(t *testing.T) {
	r := newWSRig(t, Options{MaxMessageBytes: 32768})
	conn := r.connect(t)
	// 64 KiB is over the 32 KiB telemetry bound but well under the 1 MiB read
	// limit that Task 6 needs for panel_result frames.
	body := strings.Repeat("A", 64*1024)
	if err := conn.WriteJSON(map[string]any{"type": "panel_result", "id": "p1",
		"status": "ok", "body": body}); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn)
	if !r.hub.Online(r.inst.ID) {
		t.Fatal("large panel_result closed the socket")
	}
}

func TestWSCommandUpdatesRequireOwningInstallation(t *testing.T) {
	r := newWSRig(t, Options{})
	_, otherCred := pairInstallation(t, r.store, "u2", "Other")
	now := time.Now().UnixMilli()
	for _, c := range []store.Command{
		{ID: "cmd_ack", InstallationID: r.inst.ID, DiscordID: "u1", Command: "pause", State: "delivered", CreatedAt: now},
		{ID: "cmd_result", InstallationID: r.inst.ID, DiscordID: "u1", Command: "pause", State: "received", CreatedAt: now},
	} {
		if err := r.store.AddCommand(c); err != nil {
			t.Fatal(err)
		}
	}

	other := r.connectCred(t, otherCred)
	if err := other.WriteJSON(map[string]any{"type": "ack", "id": "cmd_ack"}); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, other)
	if got := r.store.Command("cmd_ack"); got == nil || got.State != "delivered" {
		t.Fatalf("foreign ack changed command: %+v", got)
	}
	if err := other.WriteJSON(map[string]any{"type": "result", "id": "cmd_result",
		"status": "completed"}); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, other)
	if got := r.store.Command("cmd_result"); got == nil || got.State != "received" {
		t.Fatalf("foreign result changed command: %+v", got)
	}
}

func TestWSCommandTerminalStateIsNotOverwritten(t *testing.T) {
	r := newWSRig(t, Options{})
	now := time.Now().UnixMilli()
	for _, c := range []store.Command{
		{ID: "cmd_done", InstallationID: r.inst.ID, DiscordID: "u1", Command: "pause", State: "completed", CreatedAt: now},
		{ID: "cmd_rejected", InstallationID: r.inst.ID, DiscordID: "u1", Command: "pause", State: "rejected", CreatedAt: now},
		{ID: "cmd_final_ack", InstallationID: r.inst.ID, DiscordID: "u1", Command: "pause", State: "completed", CreatedAt: now},
	} {
		if err := r.store.AddCommand(c); err != nil {
			t.Fatal(err)
		}
	}
	conn := r.connect(t)
	for _, frame := range []map[string]any{
		{"type": "result", "id": "cmd_done", "status": "rejected"},
		{"type": "result", "id": "cmd_rejected", "status": "completed"},
		{"type": "ack", "id": "cmd_final_ack"},
	} {
		if err := conn.WriteJSON(frame); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, conn)
	}
	if got := r.store.Command("cmd_done"); got == nil || got.State != "completed" {
		t.Fatalf("completed overwritten: %+v", got)
	}
	if got := r.store.Command("cmd_rejected"); got == nil || got.State != "rejected" {
		t.Fatalf("rejected overwritten: %+v", got)
	}
	if got := r.store.Command("cmd_final_ack"); got == nil || got.State != "completed" {
		t.Fatalf("ack overwrote terminal state: %+v", got)
	}
}

func TestWSCommandAckAndResultTransitions(t *testing.T) {
	r := newWSRig(t, Options{})
	if err := r.store.AddCommand(store.Command{ID: "cmd_ok", InstallationID: r.inst.ID,
		DiscordID: "u1", Command: "pause", State: "delivered", CreatedAt: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	conn := r.connect(t)
	if err := conn.WriteJSON(map[string]any{"type": "ack", "id": "cmd_ok"}); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn)
	if got := r.store.Command("cmd_ok"); got == nil || got.State != "received" {
		t.Fatalf("ack state=%+v", got)
	}
	if err := conn.WriteJSON(map[string]any{"type": "result", "id": "cmd_ok",
		"status": "completed", "reason": "ok"}); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn)
	if got := r.store.Command("cmd_ok"); got == nil || got.State != "completed" || got.Reason != "ok" {
		t.Fatalf("result state=%+v", got)
	}
}

func TestWSTelemetryCoalescesRapidFrames(t *testing.T) {
	// A very long minimum interval plus a long flush tick keeps the test
	// deterministic: frames after the first stay pending until flushTelemetry
	// is called explicitly.
	r := newWSRigWith(t, Options{TelemetryMinInterval: time.Hour}, func(h *Hub) {
		h.flushEvery = time.Hour
	})
	conn := r.connect(t)
	send := func(account string) {
		t.Helper()
		if err := conn.WriteJSON(map[string]any{"type": "telemetry", "state": "SCANNING",
			"account": account}); err != nil {
			t.Fatal(err)
		}
	}
	send("First")
	waitCondition(t, "first frame stored", func() bool {
		got, ok := r.store.Installation(r.inst.ID)
		return ok && got.Telemetry != nil && got.Telemetry.Account == "First"
	})

	send("Second")
	send("Third")
	roundTrip(t, conn)

	got, _ := r.store.Installation(r.inst.ID)
	if got.Telemetry == nil || got.Telemetry.Account != "First" {
		t.Fatalf("rapid frames were not coalesced: %+v", got.Telemetry)
	}
	r.hub.mu.Lock()
	c := r.hub.clients[r.inst.ID]
	r.hub.mu.Unlock()
	if c == nil {
		t.Fatal("client not tracked")
	}
	c.telemetryMu.Lock()
	pending := c.pendingTelemetry
	c.telemetryMu.Unlock()
	if pending == nil || pending.Account != "Third" {
		t.Fatalf("pending=%+v", pending)
	}

	r.hub.flushTelemetry()
	got, _ = r.store.Installation(r.inst.ID)
	if got.Telemetry == nil || got.Telemetry.Account != "Third" {
		t.Fatalf("latest frame not flushed: %+v", got.Telemetry)
	}
}

func TestNewHubClearsStaleOnlineFlags(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := pairInstallation(t, st, "u1", "Bot")
	if err := st.SetOnline(inst.ID, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Installation(inst.ID); !got.Online {
		t.Fatal("precondition: installation not online")
	}
	_ = NewHub(st, Options{})
	if got, _ := st.Installation(inst.ID); got.Online {
		t.Fatal("NewHub kept a stale online flag")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, _ := reopened.Installation(inst.ID); got.Online {
		t.Fatal("cleared online flag was not persisted")
	}
}

func startWS(t *testing.T, panelTimeout time.Duration) (*store.Store, *Hub, *store.Installation, *websocket.Conn, func()) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHub(st, Options{HeartbeatSeconds: 20, MaxMessageBytes: 32768,
		MaxPanelInFlight: 8, PanelTimeout: panelTimeout})
	ctx, cancel := context.WithCancel(context.Background())
	go h.Start(ctx)
	ts := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	code, _, err := st.CreateCode("u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inst, cred, err := st.RedeemCode(code, "Bot", "0.1.2", "", []string{"panel"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http"),
		http.Header{"Authorization": {"Bearer " + cred}})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(map[string]any{"type": "hello", "protocols": []int{1},
		"build": "0.1.2", "name": "Bot", "hive": "", "capabilities": []string{"panel"}}); err != nil {
		t.Fatal(err)
	}
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	cleanup := func() { conn.Close(); ts.Close(); cancel(); h.Stop(); st.Close() }
	return st, h, inst, conn, cleanup
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestCommandAckResult(t *testing.T) {
	st, h, inst, conn, cleanup := startWS(t, time.Second)
	defer cleanup()
	go func() {
		for {
			var f map[string]any
			if conn.ReadJSON(&f) != nil {
				return
			}
			if f["type"] == "command" {
				id, _ := f["id"].(string)
				conn.WriteJSON(map[string]any{"type": "ack", "id": id})
				conn.WriteJSON(map[string]any{"type": "result", "id": id,
					"status": "completed", "reason": "trading paused"})
			}
		}
	}()
	id, err := h.SendCommand(inst.ID, "pause")
	if err != nil || id == "" {
		t.Fatalf("send: %v %q", err, id)
	}
	waitFor(t, "completed command", func() bool {
		c := st.LastCommand(inst.ID)
		return c != nil && c.ID == id && c.State == "completed" && c.Reason == "trading paused"
	})
}

func TestPanelRequestMatchesID(t *testing.T) {
	_, h, inst, conn, cleanup := startWS(t, time.Second)
	defer cleanup()
	go func() {
		var f map[string]any
		if conn.ReadJSON(&f) != nil {
			return
		}
		id, _ := f["id"].(string)
		conn.WriteJSON(map[string]any{"type": "panel_result", "id": id, "status": 200,
			"contentType": "text/html; charset=utf-8", "body": "<html>ok</html>"})
	}()
	res, err := h.PanelRequest(context.Background(), inst.ID, map[string]any{"op": "page"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || !strings.Contains(string(res.Body), "ok") {
		t.Fatalf("result=%+v", res)
	}
}

func TestPanelTimeoutAndOffline(t *testing.T) {
	_, h, inst, conn, cleanup := startWS(t, 100*time.Millisecond)
	defer cleanup()
	// Leave the panel frame unanswered so the broker times out.
	go func() { var f map[string]any; _ = conn.ReadJSON(&f) }()
	if _, err := h.PanelRequest(context.Background(), inst.ID, map[string]any{"op": "page"}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
	h.CloseInstallation(inst.ID, 4403, "revoked")
	waitFor(t, "offline", func() bool { return !h.Online(inst.ID) })
	if _, err := h.PanelRequest(context.Background(), inst.ID, map[string]any{"op": "page"}); !errors.Is(err, ErrOffline) {
		t.Fatalf("expected ErrOffline, got %v", err)
	}
}

// TestCommandExpiry exercises the 30 s result deadline with a short TTL.
func TestCommandExpiry(t *testing.T) {
	r := newWSRigWith(t, Options{PanelTimeout: time.Second}, func(h *Hub) {
		h.commandTTL = 50 * time.Millisecond
	})
	conn := r.connect(t)
	id, err := r.hub.SendCommand(r.inst.ID, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	if frame["type"] != "command" || frame["id"] != id || frame["command"] != "snapshot" {
		t.Fatalf("command frame=%v", frame)
	}
	waitCondition(t, "expired command", func() bool {
		c := r.store.Command(id)
		return c != nil && c.State == "expired"
	})
}

func TestCommandDisconnectMarksUnknown(t *testing.T) {
	r := newWSRig(t, Options{})
	conn := r.connect(t)
	id, err := r.hub.SendCommand(r.inst.ID, "pause")
	if err != nil {
		t.Fatal(err)
	}
	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	waitCondition(t, "unknown command", func() bool {
		c := r.store.Command(id)
		return c != nil && c.State == "unknown"
	})
}

func TestPanelRejectsMissingCapability(t *testing.T) {
	r := newWSRig(t, Options{})
	code, _, err := r.store.CreateCode("u3", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plain, plainCred, err := r.store.RedeemCode(code, "Plain", "0.1.2", "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.connectCred(t, plainCred)
	if _, err := r.hub.PanelRequest(context.Background(), plain.ID, map[string]any{"op": "page"}); !errors.Is(err, ErrNoPanel) {
		t.Fatalf("expected ErrNoPanel, got %v", err)
	}
}

func TestPanelRejectsNinthInFlight(t *testing.T) {
	r := newWSRig(t, Options{PanelTimeout: 30 * time.Second})
	conn := r.connect(t)
	go func() {
		for {
			var f map[string]any
			if conn.ReadJSON(&f) != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			_, err := r.hub.PanelRequest(ctx, r.inst.ID, map[string]any{"op": "state"})
			results <- err
		}()
	}
	r.hub.mu.Lock()
	c := r.hub.clients[r.inst.ID]
	r.hub.mu.Unlock()
	waitCondition(t, "eight in flight", func() bool {
		c.panelMu.Lock()
		defer c.panelMu.Unlock()
		return len(c.pending) == 8
	})
	if _, err := r.hub.PanelRequest(context.Background(), r.inst.ID, map[string]any{"op": "state"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
	cancel()
	for i := 0; i < 8; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled request err=%v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pending request did not return after cancel")
		}
	}
	waitCondition(t, "pending cleared", func() bool {
		c.panelMu.Lock()
		defer c.panelMu.Unlock()
		return len(c.pending) == 0
	})
}

func TestPanelDecodesBase64(t *testing.T) {
	r := newWSRig(t, Options{PanelTimeout: time.Second})
	conn := r.connect(t)
	go func() {
		var f map[string]any
		if conn.ReadJSON(&f) != nil {
			return
		}
		id, _ := f["id"].(string)
		conn.WriteJSON(map[string]any{"type": "panel_result", "id": id, "status": 200,
			"contentType": "image/png", "encoding": "base64",
			"body": base64.StdEncoding.EncodeToString([]byte("PNGDATA"))})
	}()
	res, err := r.hub.PanelRequest(context.Background(), r.inst.ID, map[string]any{"op": "png"})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "PNGDATA" || res.Encoding != "base64" || res.ContentType != "image/png" {
		t.Fatalf("result=%+v body=%q", res, res.Body)
	}
}

func TestPanelDisconnectFailsPending(t *testing.T) {
	r := newWSRig(t, Options{PanelTimeout: 10 * time.Second})
	conn := r.connect(t)
	go func() { var f map[string]any; _ = conn.ReadJSON(&f) }()
	errCh := make(chan error, 1)
	go func() {
		_, err := r.hub.PanelRequest(context.Background(), r.inst.ID, map[string]any{"op": "state"})
		errCh <- err
	}()
	r.hub.mu.Lock()
	c := r.hub.clients[r.inst.ID]
	r.hub.mu.Unlock()
	waitCondition(t, "request pending", func() bool {
		c.panelMu.Lock()
		defer c.panelMu.Unlock()
		return len(c.pending) == 1
	})
	_ = conn.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrOffline) {
			t.Fatalf("expected ErrOffline, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending request was not failed on disconnect")
	}
}

func TestPanelSocketReplacementFailsPending(t *testing.T) {
	r := newWSRig(t, Options{PanelTimeout: 10 * time.Second})
	first := r.connect(t)
	go func() { var f map[string]any; _ = first.ReadJSON(&f) }()
	errCh := make(chan error, 1)
	go func() {
		_, err := r.hub.PanelRequest(context.Background(), r.inst.ID, map[string]any{"op": "state"})
		errCh <- err
	}()
	r.hub.mu.Lock()
	c := r.hub.clients[r.inst.ID]
	r.hub.mu.Unlock()
	waitCondition(t, "request pending", func() bool {
		c.panelMu.Lock()
		defer c.panelMu.Unlock()
		return len(c.pending) == 1
	})
	_ = r.connect(t)
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrOffline) {
			t.Fatalf("expected ErrOffline, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending request survived socket replacement")
	}
}

func TestPanelDuplicateResultIgnored(t *testing.T) {
	r := newWSRig(t, Options{})
	_ = r.connect(t)
	r.hub.mu.Lock()
	c := r.hub.clients[r.inst.ID]
	r.hub.mu.Unlock()
	ch := make(chan *PanelResult, 1)
	if err := c.registerPending("pr_dup", ch, 8); err != nil {
		t.Fatal(err)
	}
	c.resolvePanel("pr_dup", &PanelResult{Status: 200, Body: []byte("first")})
	c.resolvePanel("pr_dup", &PanelResult{Status: 500, Body: []byte("second")})
	res := <-ch
	if res.Status != 200 || string(res.Body) != "first" {
		t.Fatalf("first answer lost: %+v", res)
	}
	select {
	case extra := <-ch:
		t.Fatalf("duplicate answer delivered: %+v", extra)
	default:
	}
	c.panelMu.Lock()
	n := len(c.pending)
	c.panelMu.Unlock()
	if n != 0 {
		t.Fatalf("pending not cleaned: %d", n)
	}
}

func TestPanelCrossInstallationResultIgnored(t *testing.T) {
	r := newWSRig(t, Options{PanelTimeout: 150 * time.Millisecond})
	connA := r.connect(t)
	_, otherCred := pairInstallation(t, r.store, "u2", "Other")
	connB := r.connectCred(t, otherCred)

	idCh := make(chan string, 1)
	go func() {
		var f map[string]any
		if connA.ReadJSON(&f) == nil {
			id, _ := f["id"].(string)
			idCh <- id
		}
	}()
	errCh := make(chan error, 1)
	go func() {
		_, err := r.hub.PanelRequest(context.Background(), r.inst.ID, map[string]any{"op": "state"})
		errCh <- err
	}()
	var id string
	select {
	case id = <-idCh:
	case <-time.After(2 * time.Second):
		t.Fatal("panel request was not written")
	}
	// The other installation answers with the stolen id; it must not resolve
	// the first installation's pending call.
	if err := connB.WriteJSON(map[string]any{"type": "panel_result", "id": id,
		"status": 200, "body": "foreign"}); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, ErrTimeout) {
		t.Fatalf("cross-installation result resolved the call: %v", err)
	}
}

func TestCloseInstallationFlushesPendingTelemetry(t *testing.T) {
	r := newWSRigWith(t, Options{TelemetryMinInterval: time.Hour}, func(h *Hub) {
		h.flushEvery = time.Hour
	})
	conn := r.connect(t)
	send := func(account string) {
		t.Helper()
		if err := conn.WriteJSON(map[string]any{"type": "telemetry", "state": "SCANNING",
			"account": account}); err != nil {
			t.Fatal(err)
		}
	}
	send("First")
	waitCondition(t, "first frame stored", func() bool {
		got, ok := r.store.Installation(r.inst.ID)
		return ok && got.Telemetry != nil && got.Telemetry.Account == "First"
	})
	send("Second")
	roundTrip(t, conn)
	r.hub.CloseInstallation(r.inst.ID, 4403, "revoked")
	got, _ := r.store.Installation(r.inst.ID)
	if got.Telemetry == nil || got.Telemetry.Account != "Second" {
		t.Fatalf("pending telemetry lost on close: %+v", got.Telemetry)
	}
}

func TestSocketReplacementFlushesPendingTelemetry(t *testing.T) {
	r := newWSRigWith(t, Options{TelemetryMinInterval: time.Hour}, func(h *Hub) {
		h.flushEvery = time.Hour
	})
	first := r.connect(t)
	if err := first.WriteJSON(map[string]any{"type": "telemetry", "state": "SCANNING",
		"account": "First"}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, "first frame stored", func() bool {
		got, ok := r.store.Installation(r.inst.ID)
		return ok && got.Telemetry != nil && got.Telemetry.Account == "First"
	})
	if err := first.WriteJSON(map[string]any{"type": "telemetry", "state": "SCANNING",
		"account": "Second"}); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, first)
	_ = r.connect(t)
	waitCondition(t, "pending frame flushed on replacement", func() bool {
		got, ok := r.store.Installation(r.inst.ID)
		return ok && got.Telemetry != nil && got.Telemetry.Account == "Second"
	})
}
