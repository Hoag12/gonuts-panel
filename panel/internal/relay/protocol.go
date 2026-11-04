// Package relay implements the panel side of the GoNuts client protocol
// (protocol 1): telemetry validation, pairing responses, and the WebSocket
// hub that carries telemetry, commands, and panel frames.
//
// Telemetry is treated as hostile input. Frames are bounded, every numeric
// field is clamped to the contract's ranges, and strings that look like
// credentials or filesystem paths are refused rather than forwarded to the
// browser.
package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"

	"gonutspanel/internal/store"
)

const (
	maxTelemetryBytes = 32768
	maxCount          = 1_000_000
	maxMoney          = 1_000_000_000_000
	maxAccountLen     = 48
	maxTextLen        = 160
	maxBuildLen       = 60
	maxMascotLen      = 16
	maxSourceLen      = 16
)

// Errors returned by the relay. The messages are safe to send to a client:
// they never contain frame contents.
var (
	ErrOffline = errors.New("relay: client is offline")
	ErrBusy    = errors.New("relay: panel request limit reached")
	ErrTimeout = errors.New("relay: panel request timed out")
	ErrNoPanel = errors.New("relay: client does not support the panel")

	errInvalidTelemetry = errors.New("relay: invalid telemetry frame")
	errSensitive        = errors.New("relay: telemetry contains sensitive data")
	errTooLarge         = errors.New("relay: telemetry frame exceeds 32768 bytes")
)

// PanelResult is the decoded answer to a panel request. Body is the already
// decoded payload; Encoding is the optional transfer encoding reported by the
// client (for example "gzip").
type PanelResult struct {
	Status      int
	ContentType string
	Body        []byte
	Encoding    string
}

var telemetryStates = map[string]bool{
	"SCANNING":       true,
	"BID_DESK":       true,
	"PREPARING_LIST": true,
	"LISTING":        true,
	"MONITORING":     true,
	"COOLDOWN":       true,
	"PAUSED":         true,
	"STOPPED":        true,
	"IDLE":           true,
	"BUYING":         true,
	"REPRICING":      true,
	"RECOVERING":     true,
	"EVADING":        true,
}

var (
	sensitiveFragments = []string{`C:\`, "/home/", "/Users/", "gni1_", "dbay_", "Bearer "}
	longTokenPattern   = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)

	namePattern  = regexp.MustCompile(`^[A-Za-z0-9 _().-]{1,48}$`)
	buildPattern = regexp.MustCompile(`^[0-9A-Za-z.+_-]{0,60}$`)
	hivePattern  = regexp.MustCompile(`^[0-9A-Za-z_-]{0,64}$`)

	// Capabilities are advisory. The real client advertises a longer list than
	// this relay consults (only "panel" is read), so the shape and count are
	// bounded but unknown names are accepted and stored as received.
	capPattern      = regexp.MustCompile(`^[a-z_]{1,32}$`)
	maxCapabilities = 32
)

// ParseTelemetry validates and clamps one telemetry frame. Unknown fields are
// ignored. It returns an error for oversized frames, non-object frames, wrong
// field types, and strings that look like credentials or local paths.
func ParseTelemetry(raw []byte) (*store.Telemetry, error) {
	if len(raw) > maxTelemetryBytes {
		return nil, errTooLarge
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, errInvalidTelemetry
	}

	t := &store.Telemetry{}

	if v, ok, err := intValue(fields, "at"); err != nil {
		return nil, err
	} else if ok {
		t.At = v
	}

	state, _, err := stringValue(fields, "state")
	if err != nil {
		return nil, err
	}
	if telemetryStates[state] {
		t.State = state
	} else {
		t.State = "UNKNOWN"
	}

	account, _, err := stringValue(fields, "account")
	if err != nil {
		return nil, err
	}
	t.Account = truncate(account, maxAccountLen)

	detail, _, err := stringValue(fields, "detail")
	if err != nil {
		return nil, err
	}
	t.Detail = truncate(detail, maxTextLen)

	build, _, err := stringValue(fields, "build")
	if err != nil {
		return nil, err
	}
	t.Build = truncate(build, maxBuildLen)

	lastAction, _, err := stringValue(fields, "lastAction")
	if err != nil {
		return nil, err
	}
	t.LastAction = truncate(lastAction, maxTextLen)

	if v, ok, err := intValue(fields, "lastActionAt"); err != nil {
		return nil, err
	} else if ok {
		t.LastActionAt = v
	}

	mascot, _, err := stringValue(fields, "mascotFace")
	if err != nil {
		return nil, err
	}
	t.MascotFace = truncate(mascot, maxMascotLen)

	if v, ok, err := intValue(fields, "listed"); err != nil {
		return nil, err
	} else if ok {
		t.Listed = clamp(v, 0, maxCount)
	}
	if v, ok, err := intValue(fields, "slots"); err != nil {
		return nil, err
	} else if ok {
		t.Slots = clamp(v, 0, maxCount)
	}
	if v, ok, err := intValue(fields, "trades"); err != nil {
		return nil, err
	} else if ok {
		t.Trades = clamp(v, 0, maxCount)
	}
	if v, ok, err := intValue(fields, "bank"); err != nil {
		return nil, err
	} else if ok {
		v = clamp(v, -maxMoney, maxMoney)
		t.Bank = &v
	}

	if t.Profit, err = parseInterval(fields, "profit", true); err != nil {
		return nil, err
	}
	if t.Revenue, err = parseInterval(fields, "revenue", true); err != nil {
		return nil, err
	}
	if t.Sales, err = parseInterval(fields, "sales", false); err != nil {
		return nil, err
	}
	if t.Purchases, err = parseInterval(fields, "purchases", false); err != nil {
		return nil, err
	}
	if t.Listings, err = parseInterval(fields, "listings", false); err != nil {
		return nil, err
	}
	if t.Reprices, err = parseInterval(fields, "reprices", false); err != nil {
		return nil, err
	}

	if m, ok, err := rawMap(fields, "swarm"); err != nil {
		return nil, err
	} else if ok {
		t.Swarm = &store.Swarm{
			Enabled:         boolValue(m, "enabled"),
			GuidanceEnabled: boolValue(m, "guidanceEnabled"),
			Eligible:        boolValue(m, "eligible"),
		}
	}
	if m, ok, err := rawMap(fields, "controls"); err != nil {
		return nil, err
	} else if ok {
		t.Controls = &store.Controls{
			Pause:    boolValue(m, "pause"),
			Resume:   boolValue(m, "resume"),
			Snapshot: boolValue(m, "snapshot"),
		}
	}

	// Check only the truncated values: whatever is stored is what can reach
	// the browser, so a secret beyond the length limit is already gone.
	if sensitive(t.Account) || sensitive(t.Detail) || sensitive(t.LastAction) {
		return nil, errSensitive
	}
	return t, nil
}

// ValidName reports whether a pairing name is acceptable. An empty name is
// valid; the store substitutes its default display name.
func ValidName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	return namePattern.MatchString(name) && !sensitive(name)
}

// ValidBuild reports whether a client build string is acceptable.
func ValidBuild(build string) bool {
	return buildPattern.MatchString(build)
}

// ValidHive reports whether a hive label is acceptable.
func ValidHive(hive string) bool {
	return hivePattern.MatchString(hive)
}

// ValidCaps reports whether caps is a bounded list of capability-shaped
// strings. Unknown capability names are tolerated: the relay only consults
// "panel", and rejecting names the mod knows about would refuse every real
// pairing. The list is a fixed-size array of bounded strings, so accepting it
// cannot grow memory or the stored JSON without limit.
func ValidCaps(caps []string) bool {
	if len(caps) > maxCapabilities {
		return false
	}
	for _, c := range caps {
		if !capPattern.MatchString(c) {
			return false
		}
	}
	return true
}

// PairResponse is the body returned to a client that successfully redeems a
// pairing code. The credential is included here and only here.
func PairResponse(base string, id int64, credential, name string) map[string]any {
	base = strings.TrimRight(base, "/")
	wsBase := base
	switch {
	case strings.HasPrefix(base, "https://"):
		wsBase = "wss://" + strings.TrimPrefix(base, "https://")
	case strings.HasPrefix(base, "http://"):
		wsBase = "ws://" + strings.TrimPrefix(base, "http://")
	}
	return map[string]any{
		"installationId":         id,
		"credential":             credential,
		"name":                   name,
		"protocol":               1,
		"wsUrl":                  wsBase + "/dashboard/ws/client",
		"checkUrl":               base + "/dashboard/api/client/check",
		"heartbeatSeconds":       20,
		"telemetryMinIntervalMs": 1000,
		"maxMessageBytes":        maxTelemetryBytes,
	}
}

func parseInterval(fields map[string]json.RawMessage, key string, money bool) (*store.Interval, error) {
	m, ok, err := rawMap(fields, key)
	if err != nil || !ok {
		return nil, err
	}
	iv := &store.Interval{}
	lo, hi := int64(0), int64(maxCount)
	if money {
		lo, hi = -maxMoney, maxMoney
	}
	for _, name := range []string{"h1", "h24"} {
		v, present, err := intValue(m, name)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		v = clamp(v, lo, hi)
		if name == "h1" {
			iv.H1 = &v
		} else {
			iv.H24 = &v
		}
	}
	if key == "profit" || key == "revenue" {
		if s, present, err := stringValue(m, "source"); err != nil {
			return nil, err
		} else if present {
			iv.Source = truncate(s, maxSourceLen)
		}
	}
	return iv, nil
}

func rawMap(fields map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool, error) {
	raw, ok := fields[key]
	if !ok || isNull(raw) {
		return nil, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false, errInvalidTelemetry
	}
	return m, true, nil
}

func stringValue(fields map[string]json.RawMessage, key string) (string, bool, error) {
	raw, ok := fields[key]
	if !ok || isNull(raw) {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, errInvalidTelemetry
	}
	return s, true, nil
}

func boolValue(fields map[string]json.RawMessage, key string) bool {
	raw, ok := fields[key]
	if !ok || isNull(raw) {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false
	}
	return b
}

func intValue(fields map[string]json.RawMessage, key string) (int64, bool, error) {
	raw, ok := fields[key]
	if !ok || isNull(raw) {
		return 0, false, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false, errInvalidTelemetry
	}
	if i, err := n.Int64(); err == nil {
		return i, true, nil
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false, errInvalidTelemetry
	}
	if f > 9e15 {
		f = 9e15
	} else if f < -9e15 {
		f = -9e15
	}
	return int64(f), true, nil
}

func isNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

func clamp(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

func sensitive(s string) bool {
	if s == "" {
		return false
	}
	for _, fragment := range sensitiveFragments {
		if strings.Contains(s, fragment) {
			return true
		}
	}
	return longTokenPattern.MatchString(s)
}
