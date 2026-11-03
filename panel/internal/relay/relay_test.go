package relay

import (
	"context"
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
	if !ValidCaps(nil) || !ValidCaps([]string{"panel", "pause"}) || ValidCaps([]string{"shell"}) {
		t.Fatal("ValidCaps")
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
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHub(st, opts)
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
	conn, resp, err := r.dial(t, http.Header{"Authorization": {"Bearer " + r.cred}})
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
