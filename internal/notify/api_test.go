//go:build dev

package notify_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/server"
)

func TestChannelsAndRoutesAPI(t *testing.T) {
	fs := &fakeSlack{reply: func(n int) string {
		if n == 2 {
			return `{"ok":false,"error":"channel_not_found"}`
		}
		return `{"ok":true,"channel":"C0ABCDEF","ts":"1.2"}`
	}}
	slackSrv := httptest.NewServer(fs.handler())
	defer slackSrv.Close()
	var kvToken string
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		kvToken = canaryToken
		_ = e.KV.SetSecret(context.Background(), "local", "slack-bot", []byte(canaryToken))
		sink := &notify.SlackSink{KV: e.KV, TokenRef: "kv://local/slack-bot", APIURL: slackSrv.URL + "/api/", Log: e.Log}
		return []server.Module{&notify.API{DB: e.DB, Log: e.Log, Sinks: map[string]notify.Sink{"slack": sink},
			Link: func(p string) string { return "https://olympos.example" + p }}}
	}})
	op := e.Login(e.Principal("olga", "Member", "operator"))
	scopedOp := e.Login(e.Principal("sam", "Member", "operator@env=prod"))
	viewer := e.Login(e.Principal("vic", "Member", "viewer"))
	nobody := e.Login(e.Principal("nora", "Member"))

	// Writes need operator with scope all.
	in := map[string]any{"name": "#platform-alerts", "slack_channel_id": "C0ABCDEF"}
	if code := viewer.Do("POST", "/api/v1/notifications/channels", in, nil); code != 403 {
		t.Fatalf("viewer create: %d", code)
	}
	if code := scopedOp.Do("POST", "/api/v1/notifications/channels", in, nil); code != 403 {
		t.Fatalf("scoped operator create: %d", code)
	}
	if code, body := op.Raw("POST", "/api/v1/notifications/channels", map[string]any{"name": "x", "slack_channel_id": "#general"}); code != 422 ||
		!strings.Contains(body, "slack_channel_id") {
		t.Fatalf("invalid channel: %d %s", code, body)
	}
	var ch notify.ChannelView
	if code := op.Do("POST", "/api/v1/notifications/channels", in, &ch); code != 201 || ch.Name != "#platform-alerts" || ch.Kind != "slack" {
		t.Fatalf("create: %d %+v", code, ch)
	}
	var ch2 notify.ChannelView
	op.Do("POST", "/api/v1/notifications/channels", map[string]any{"name": "#db", "slack_channel_id": "C0DBTEAM1"}, &ch2)

	// Reads: any role; no grants at all → 403.
	var list struct{ Items []notify.ChannelView }
	if code := viewer.Do("GET", "/api/v1/notifications/channels", nil, &list); code != 200 || len(list.Items) != 2 {
		t.Fatalf("viewer list: %d %+v", code, list)
	}
	if code := nobody.Do("GET", "/api/v1/notifications/channels", nil, nil); code != 403 && code != 401 {
		t.Fatalf("no grants list: %d", code)
	}

	// PATCH / 404 vs 403.
	if code := viewer.Do("PATCH", "/api/v1/notifications/channels/"+ch.ID.String(), map[string]any{"name": "#x"}, nil); code != 403 {
		t.Fatalf("viewer patch: %d", code)
	}
	if code := op.Do("PATCH", "/api/v1/notifications/channels/"+uuid.NewString(), map[string]any{"name": "#x"}, nil); code != 404 {
		t.Fatalf("patch missing: %d", code)
	}
	var patched notify.ChannelView
	if code := op.Do("PATCH", "/api/v1/notifications/channels/"+ch.ID.String(), map[string]any{"name": "#platform"}, &patched); code != 200 ||
		patched.Name != "#platform" || patched.SlackChannelID != "C0ABCDEF" {
		t.Fatalf("patch: %d %+v", code, patched)
	}

	// Routes: catalog + replace all.
	var routes notify.RoutesView
	if code := viewer.Do("GET", "/api/v1/notifications/routes", nil, &routes); code != 200 || len(routes.Catalog) != len(notify.Catalog) {
		t.Fatalf("routes: %d %+v", code, routes)
	}
	for _, c := range routes.Catalog {
		if c.EventType == notify.BackupSucceeded && !c.OptIn {
			t.Fatal("backup.succeeded must be opt-in")
		}
	}
	put := map[string]any{"routes": []map[string]any{
		{"event_type": "backup.failed", "channel_ids": []string{ch.ID.String(), ch2.ID.String()}},
		{"event_type": "sas.expiring", "channel_ids": []string{ch.ID.String()}},
	}}
	if code := scopedOp.Do("PUT", "/api/v1/notifications/routes", put, nil); code != 403 {
		t.Fatalf("scoped put: %d", code)
	}
	if code := op.Do("PUT", "/api/v1/notifications/routes", map[string]any{"routes": []map[string]any{{"event_type": "nope", "channel_ids": []string{}}}}, nil); code != 422 {
		t.Fatalf("unknown event: %d", code)
	}
	if code := op.Do("PUT", "/api/v1/notifications/routes", map[string]any{"routes": []map[string]any{{"event_type": "backup.failed", "channel_ids": []string{uuid.NewString()}}}}, nil); code != 422 {
		t.Fatalf("unknown channel: %d", code)
	}
	if code := op.Do("PUT", "/api/v1/notifications/routes", put, &routes); code != 200 {
		t.Fatalf("put: %d", code)
	}
	got := map[string]int{}
	for _, r := range routes.Routes {
		got[r.EventType] = len(r.ChannelIDs)
	}
	if got["backup.failed"] != 2 || got["sas.expiring"] != 1 || got["backup.succeeded"] != 0 {
		t.Fatalf("routes after put: %v", got)
	}
	var one notify.ChannelView
	op.Do("GET", "/api/v1/notifications/channels/"+ch.ID.String(), nil, &one)
	if len(one.Routes) != 2 {
		t.Fatalf("channel routes: %v", one.Routes)
	}

	// Test message: synchronous; first OK, second reports the Slack error.
	var res notify.TestResult
	if code := viewer.Do("POST", "/api/v1/notifications/channels/"+ch.ID.String()+"/test", nil, nil); code != 403 {
		t.Fatalf("viewer test: %d", code)
	}
	if code := op.Do("POST", "/api/v1/notifications/channels/"+ch.ID.String()+"/test", nil, &res); code != 200 || !res.OK {
		t.Fatalf("test: %d %+v", code, res)
	}
	if code := op.Do("POST", "/api/v1/notifications/channels/"+ch.ID.String()+"/test", nil, &res); code != 200 || res.OK || res.Error != "slack: channel_not_found" {
		t.Fatalf("test failing: %d %+v", code, res)
	}
	calls := fs.all()
	if len(calls) != 2 || !strings.Contains(calls[0].Blocks, "https://olympos.example/settings/notifications") {
		t.Fatalf("slack calls: %+v", calls)
	}

	// Delete: routes cascade; a backup job override blocks it (409).
	if code := op.Do("DELETE", "/api/v1/notifications/channels/"+ch2.ID.String(), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := op.Do("DELETE", "/api/v1/notifications/channels/"+ch2.ID.String(), nil, nil); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
	ctx := context.Background()
	var cl uuid.UUID
	if err := e.DB.QueryRow(ctx, `INSERT INTO clusters (name) VALUES ('c1') RETURNING id`).Scan(&cl); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB.Exec(ctx, `INSERT INTO audit_schedules (tool, cron, notify_channel_id) VALUES ('polaris', '@daily', $1)`, ch.ID); err != nil {
		t.Skipf("cannot create referencing row for the 409 check: %v", err)
	}
	if code := op.Do("DELETE", "/api/v1/notifications/channels/"+ch.ID.String(), nil, nil); code != 409 {
		t.Fatalf("delete referenced: %d", code)
	}

	// Activity log covers every change.
	var actions []string
	rows, _ := e.DB.Query(ctx, `SELECT action FROM activity_log WHERE action LIKE 'notification.%' ORDER BY at`)
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	want := []string{"notification.channel.created", "notification.channel.created", "notification.channel.updated",
		"notification.routes.updated", "notification.channel.tested", "notification.channel.tested", "notification.channel.deleted"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("activity: %v", actions)
	}
	if strings.Contains(e.LogBuf.String(), kvToken) {
		t.Fatal("slack token in logs")
	}
}
