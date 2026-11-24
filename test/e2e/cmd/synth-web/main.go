// Command synth-web is the lab's target for synthetic monitoring
// (test/e2e/manifests/synthetic.yaml). CoreDNS in each lab cluster sends
// every *.olympos-lab.test name to it, so scenarios can use names that look
// like real hosts.
//
//	GET /health              200 {"status":"ok"}
//	GET /api/items           needs "Authorization: Bearer <token>": 200 with
//	                         the items, the token echoed back and a
//	                         Set-Cookie (both must reach Olympos redacted)
//	GET /toggle?mode=M       ok (default), 500 (/health, /api/items and
//	                         /redirect answer 500) or slow (they wait 2 s)
//	GET /redirect?to=URL     302 to URL
//
//	synth-web toggle MODE    sets the mode of the server on this pod:
//	                         kubectl -n lab exec deploy/synth-web -- /synth-web toggle 500
//
// Lab only: it echoes credentials on purpose.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	addr      = ":8080"
	slowDelay = 2 * time.Second
)

var modes = map[string]bool{"ok": true, "500": true, "slow": true}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "toggle" {
		os.Exit(toggle(os.Args[2]))
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: synth-web | synth-web toggle ok|500|slow")
		os.Exit(2)
	}
	s := &server{}
	s.mode.Store("ok")
	srv := &http.Server{Addr: addr, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("synth-web listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

// toggle asks the server on this pod to switch modes.
func toggle(mode string) int {
	resp, err := http.Get("http://127.0.0.1" + addr + "/toggle?mode=" + url.QueryEscape(mode))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Print(string(b))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

type server struct {
	mode atomic.Value // string
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /toggle", s.toggle)
	mux.HandleFunc("GET /health", s.moded(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}))
	mux.HandleFunc("GET /api/items", s.moded(items))
	mux.HandleFunc("GET /redirect", s.moded(func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to")
		if to == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "to is required"})
			return
		}
		http.Redirect(w, r, to, http.StatusFound)
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	})
	return mux
}

func (s *server) toggle(w http.ResponseWriter, r *http.Request) {
	m := r.URL.Query().Get("mode")
	if !modes[m] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "mode must be ok, 500 or slow"})
		return
	}
	s.mode.Store(m)
	log.Printf("mode %s", m)
	writeJSON(w, http.StatusOK, map[string]any{"mode": m})
}

// moded applies the current mode before h.
func (s *server) moded(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch s.mode.Load().(string) {
		case "500":
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "synth-web is toggled to 500"})
			return
		case "slow":
			select {
			case <-time.After(slowDelay):
			case <-r.Context().Done():
				return
			}
		}
		h(w, r)
	}
}

// items needs a bearer token and echoes it, in a field whose name is not a
// sensitive one, so that only the credential redaction can hide it.
func items(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="synth-web"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bearer token required"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "lab-session-" + fmt.Sprint(time.Now().Unix()), Path: "/", HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]any{
		"items": []map[string]any{{"id": 1, "name": "widget", "stock": 12}, {"id": 2, "name": "gadget", "stock": 3}},
		"count": 2,
		"echo":  token,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
