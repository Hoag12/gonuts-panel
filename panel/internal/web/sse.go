package web

import "sync"

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
