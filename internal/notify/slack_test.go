package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
)

const canaryToken = "xoxb-111-222-CANARYslacktoken"

type slackCall struct {
	Auth     string
	Channel  string
	Text     string
	Blocks   string
	Metadata string
	Raw      string
}

type fakeSlack struct {
	mu    sync.Mutex
	calls []slackCall
	reply func(n int) string
}

func (f *fakeSlack) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat.postMessage") {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		// slack-go sends the bot token as the "token" form field of
		// chat.postMessage (or as a bearer header for other methods).
		auth := r.Header.Get("Authorization")
		if tok := r.Form.Get("token"); tok != "" {
			auth = "Bearer " + tok
		}
		r.Form.Del("token")
		f.mu.Lock()
		f.calls = append(f.calls, slackCall{Auth: auth, Channel: r.Form.Get("channel"), Text: r.Form.Get("text"),
			Blocks: r.Form.Get("blocks"), Metadata: r.Form.Get("metadata"), Raw: r.Form.Encode()})
		n := len(f.calls)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if f.reply != nil {
			_, _ = w.Write([]byte(f.reply(n)))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C0ABCDEF","ts":"1700000000.000100"}`))
	})
}

func (f *fakeSlack) all() []slackCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]slackCall(nil), f.calls...)
}

func newKV(t *testing.T) *secrets.LocalKeyVault {
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	if err := kv.SetSecret(context.Background(), "local", "slack-bot", []byte(canaryToken)); err != nil {
		t.Fatal(err)
	}
	return kv
}

// walk visits every JSON object in v.
func walk(v any, f func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		f(x)
		for _, c := range x {
			walk(c, f)
		}
	case []any:
		for _, c := range x {
			walk(c, f)
		}
	}
}

func TestSlackSinkBlockKit(t *testing.T) {
	fs := &fakeSlack{}
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()
	sink := &notify.SlackSink{KV: newKV(t), TokenRef: "kv://local/slack-bot", APIURL: srv.URL + "/api/", Log: quiet}
	ch := notify.Channel{ID: uuid.New(), Kind: "slack", Name: "#ops", SlackChannelID: "C0ABCDEF"}
	m := notify.Message{Key: "backup.failed:run-42", EventType: notify.BackupFailed, Title: "Backup of orders-pg <prod> failed",
		Link: "https://olympos.example/backups/runs/42", CreatedAt: time.Now(),
		Fields: map[string]string{"cluster": "prod-aks", "error": "403 on https://acct.blob.core.windows.net/c/x?sv=2024&sig=CANARYSIG999"}}
	if err := sink.Send(context.Background(), ch, m); err != nil {
		t.Fatal(err)
	}
	calls := fs.all()
	if len(calls) != 1 {
		t.Fatalf("calls: %d", len(calls))
	}
	c := calls[0]
	if c.Auth != "Bearer "+canaryToken {
		t.Fatalf("token not resolved from key vault: %q", c.Auth)
	}
	if c.Channel != "C0ABCDEF" {
		t.Fatalf("channel %q", c.Channel)
	}
	if strings.Contains(c.Raw, canaryToken) || strings.Contains(c.Raw, "CANARYSIG999") {
		t.Fatalf("secret in message body: %s", c.Raw)
	}
	if !strings.Contains(c.Blocks, "https://olympos.example/backups/runs/42") {
		t.Fatalf("link missing: %s", c.Blocks)
	}
	var blocks []any
	if err := json.Unmarshal([]byte(c.Blocks), &blocks); err != nil {
		t.Fatal(err)
	}
	var texts []string
	walk(blocks, func(o map[string]any) {
		if s, ok := o["text"].(string); ok {
			texts = append(texts, s)
		}
	})
	if all := strings.Join(texts, "\n"); !strings.Contains(all, "&lt;prod&gt;") || !strings.Contains(all, "|Open in Olympos>") {
		t.Fatalf("mrkdwn not escaped or link missing: %s", all)
	}
	walk(blocks, func(o map[string]any) {
		switch o["type"] {
		case "actions", "button", "input", "static_select", "overflow", "datepicker":
			t.Errorf("interactive element in message: %v", o)
		}
		if _, ok := o["accessory"]; ok {
			t.Errorf("accessory in message: %v", o)
		}
		if _, ok := o["action_id"]; ok {
			t.Errorf("action_id in message: %v", o)
		}
	})
	var meta struct {
		EventType    string         `json:"event_type"`
		EventPayload map[string]any `json:"event_payload"`
	}
	if err := json.Unmarshal([]byte(c.Metadata), &meta); err != nil {
		t.Fatalf("metadata: %v (%q)", err, c.Metadata)
	}
	if meta.EventType != "olympos_backup_failed" || meta.EventPayload["idempotency_key"] != "backup.failed:run-42" {
		t.Fatalf("metadata: %+v", meta)
	}
}

func TestSlackSinkNotConfigured(t *testing.T) {
	sink := &notify.SlackSink{KV: newKV(t), Log: quiet}
	err := sink.Send(context.Background(), notify.Channel{SlackChannelID: "C0ABCDEF"}, notify.Message{Title: "x"})
	if !errors.Is(err, notify.ErrSinkNotConfigured) {
		t.Fatalf("empty token ref: %v", err)
	}
	sink = &notify.SlackSink{KV: newKV(t), TokenRef: "kv://local/missing", Log: quiet}
	if err := sink.Send(context.Background(), notify.Channel{SlackChannelID: "C0ABCDEF"}, notify.Message{Title: "x"}); !errors.Is(err, notify.ErrSinkNotConfigured) {
		t.Fatalf("missing secret: %v", err)
	}
}

func TestSlackSinkReResolvesTokenAfterAuthError(t *testing.T) {
	fs := &fakeSlack{reply: func(n int) string {
		if n == 1 {
			return `{"ok":false,"error":"invalid_auth"}`
		}
		return `{"ok":true,"channel":"C0ABCDEF","ts":"1.2"}`
	}}
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()
	kv := newKV(t)
	sink := &notify.SlackSink{KV: kv, TokenRef: "kv://local/slack-bot", APIURL: srv.URL + "/api/", Log: quiet}
	ch := notify.Channel{SlackChannelID: "C0ABCDEF"}
	err := sink.Send(context.Background(), ch, notify.Message{Title: "x", EventType: "test"})
	if err == nil || !strings.Contains(err.Error(), "invalid_auth") || strings.Contains(err.Error(), canaryToken) {
		t.Fatalf("err: %v", err)
	}
	// Rotate the token in Key Vault: the next send must use the new one.
	_ = kv.SetSecret(context.Background(), "local", "slack-bot", []byte("xoxb-rotated"))
	if err := sink.Send(context.Background(), ch, notify.Message{Title: "x", EventType: "test"}); err != nil {
		t.Fatal(err)
	}
	if got := fs.all()[1].Auth; got != "Bearer xoxb-rotated" {
		t.Fatalf("rotated token not used: %q", got)
	}
}
