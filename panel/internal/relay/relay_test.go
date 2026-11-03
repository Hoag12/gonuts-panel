package relay

import (
	"strings"
	"testing"
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
