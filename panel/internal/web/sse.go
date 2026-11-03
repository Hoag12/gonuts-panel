package web

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// sseKeepAlive is the comment heartbeat written when no update arrives, so
// proxies and browsers never see a silent stream.
const sseKeepAlive = 25 * time.Second

// sseHub caps the number of concurrent event streams per user.
type sseHub struct {
	mu    sync.Mutex
	users map[string]int
	max   int
}

func newSSEHub(max int) *sseHub {
	return &sseHub{users: map[string]int{}, max: max}
}

// add reserves a stream slot for user. It reports false when the user already
// has max streams open.
func (h *sseHub) add(user string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.users[user] >= h.max {
		return false
	}
	h.users[user]++
	return true
}

// remove releases one stream slot for user.
func (h *sseHub) remove(user string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users[user]--
	if h.users[user] <= 0 {
		delete(h.users, user)
	}
}

// sse streams dashboard change notifications. The browser refetches
// /dashboard/api/state on every update event; the event itself carries no data.
func (s *Server) sse(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.SSE.add(sess.DiscordID) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"message": "too many tabs",
			"status":  http.StatusTooManyRequests,
		})
		return
	}
	defer s.SSE.remove(sess.DiscordID)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")

	update := func() {
		_, _ = fmt.Fprint(w, "event: update\ndata: {}\n\n")
		flusher.Flush()
	}
	update()

	ticker := time.NewTicker(sseKeepAlive)
	defer ticker.Stop()
	// A closed channel (the no-op relay's) would otherwise spin this loop; a
	// nil channel blocks forever instead.
	updates := s.Hub.Updates()
	for {
		select {
		case <-r.Context().Done():
			return
		case _, open := <-updates:
			if !open {
				updates = nil
				continue
			}
			update()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
