package ingest

import (
	"net/http"
	"sync"
	"time"
)

// OpenUploads counts a handler's open multipart uploads.
func OpenUploads(h http.Handler) int {
	hh := h.(*handler)
	hh.mu.Lock()
	defer hh.mu.Unlock()
	return len(hh.uploads)
}

// Spilled is how many bytes of out-of-order parts a session holds on disk.
func Spilled(s *Session) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spilled
}

// WithRate sets the requests a session may send per second (200 by default).
func WithRate(perSecond float64) HandlerOption { return func(h *handler) { h.rate = perSecond } }

// ManualExpiry replaces the expiry timers of reg's sessions: none fires by
// itself, and fire runs the callbacks of the timers that are not stopped, as
// if their TTL passed. Call it before the sessions are opened.
func ManualExpiry(reg *Registry) (fire func()) {
	type timer struct {
		f       func()
		stopped bool
	}
	var mu sync.Mutex
	var timers []*timer
	reg.afterFunc = func(_ time.Duration, f func()) func() bool {
		mu.Lock()
		defer mu.Unlock()
		t := &timer{f: f}
		timers = append(timers, t)
		return func() bool {
			mu.Lock()
			defer mu.Unlock()
			was := !t.stopped
			t.stopped = true
			return was
		}
	}
	return func() {
		mu.Lock()
		var due []func()
		for _, t := range timers {
			if !t.stopped {
				t.stopped = true
				due = append(due, t.f)
			}
		}
		mu.Unlock()
		for _, f := range due {
			f()
		}
	}
}
