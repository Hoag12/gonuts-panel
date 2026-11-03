// Command mockclient is a standalone mock mod for manual browser tests. It
// redeems a pairing code, connects over WebSocket, sends telemetry, answers
// commands, and serves a placeholder panel.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type pairResponse struct {
	InstallationID int64  `json:"installationId"`
	Credential     string `json:"credential"`
	WSURL          string `json:"wsUrl"`
}

type mock struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (m *mock) write(v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conn.WriteJSON(v)
}

func telemetry() map[string]any {
	return map[string]any{
		"type": "telemetry", "at": time.Now().UnixMilli(),
		"state": "SCANNING", "detail": "Evaluating configured trades", "account": "MockAccount",
		"listed": 1, "slots": 18, "bank": 128000000, "trades": 23,
		"profit":    map[string]any{"h1": 19000, "h24": 45000, "source": "booked"},
		"sales":     map[string]any{"h1": 2, "h24": 22},
		"purchases": map[string]any{"h24": 24},
		"listings":  map[string]any{"h24": 8},
		"reprices":  map[string]any{"h24": 0},
		"build":     "mock-1", "lastAction": "Evaluating configured trades", "lastActionAt": time.Now().UnixMilli(),
		"mascotFace": "WATCH", "swarm": map[string]any{"enabled": false},
		"controls": map[string]any{"pause": true, "resume": false, "snapshot": true},
	}
}

func main() {
	base := flag.String("base", "http://localhost:8080", "relay base URL")
	code := flag.String("code", "", "pairing code")
	name := flag.String("name", "Mock bot", "client label")
	flag.Parse()
	if *code == "" {
		log.Fatal("-code is required")
	}
	body, _ := json.Marshal(map[string]any{"code": *code, "protocols": []int{1}, "name": *name,
		"build": "mock-1", "hive": "mock", "capabilities": []string{"pause", "resume", "snapshot", "panel"}})
	resp, err := http.Post(*base+"/dashboard/api/pair/redeem", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		log.Fatalf("redeem: %s", resp.Status)
	}
	var pr pairResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		log.Fatal(err)
	}
	log.Printf("paired installation %d", pr.InstallationID)
	url := pr.WSURL
	if strings.HasPrefix(url, "https") {
		url = "wss" + strings.TrimPrefix(url, "http")
	}
	if strings.HasPrefix(url, "http") {
		url = "ws" + strings.TrimPrefix(url, "http")
	}
	conn, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + pr.Credential}})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	m := &mock{conn: conn}
	if err := m.write(map[string]any{"type": "hello", "protocols": []int{1}, "build": "mock-1",
		"name": *name, "hive": "mock", "capabilities": []string{"pause", "resume", "snapshot", "panel"}}); err != nil {
		log.Fatal(err)
	}
	// Send the first telemetry frame immediately; the dashboard should not
	// wait for the ten-second ticker to show a live bot.
	if err := m.write(telemetry()); err != nil {
		log.Fatal(err)
	}
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			_ = m.write(telemetry())
		}
	}()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			log.Fatal(err)
		}
		var frame map[string]any
		if json.Unmarshal(data, &frame) != nil {
			continue
		}
		switch frame["type"] {
		case "welcome":
			log.Printf("welcome: %v", frame)
		case "ping":
			_ = m.write(map[string]any{"type": "pong", "at": frame["at"]})
		case "command":
			id, _ := frame["id"].(string)
			_ = m.write(map[string]any{"type": "ack", "id": id})
			_ = m.write(map[string]any{"type": "result", "id": id, "status": "completed", "reason": ""})
			_ = m.write(telemetry())
		case "panel":
			handlePanel(m, frame)
		}
	}
}

func handlePanel(m *mock, frame map[string]any) {
	id, _ := frame["id"].(string)
	op, _ := frame["op"].(string)
	reply := map[string]any{"type": "panel_result", "id": id, "status": 200}
	switch op {
	case "page":
		reply["contentType"] = "text/html; charset=utf-8"
		reply["body"] = `<!doctype html><html><head><title>Mock panel</title></head><body style="background:#0c121b;color:#f0eee7;font-family:monospace"><h1 style="color:#f4cd7a">Mock panel</h1><p>This is the mod's panel placeholder.</p><button onclick="fetch('/act',{method:'POST',headers:{'X-GoNuts':'1','Content-Type':'application/x-www-form-urlencoded'},body:'id=ctl:start'})">Start</button></body></html>`
	case "state":
		reply["contentType"] = "application/json"
		reply["body"] = `{"pageId":"MONEY","pages":[]}`
	case "data", "change":
		reply["contentType"] = "application/json"
		reply["body"] = `{"ok":true}`
	case "act":
		reply["status"] = 204
		reply["contentType"] = "text/plain"
		reply["body"] = ""
	case "png", "icon", "asset":
		reply["status"] = 404
		reply["contentType"] = "text/plain"
		reply["body"] = "Not found"
	default:
		reply["status"] = 400
		reply["contentType"] = "text/plain"
		reply["body"] = "Bad op"
	}
	_ = m.write(reply)
}
