package app

import (
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/server"
)

// Notifications (SPEC §14): outbox dispatcher on every replica (rows are
// claimed with SKIP LOCKED) and the channels/routes API.
func init() {
	Register(func(d *Deps) (Wiring, error) {
		log := d.Log.With("component", "notify")
		sinks := map[string]notify.Sink{
			"slack": &notify.SlackSink{KV: d.KV, TokenRef: d.Cfg.Slack.BotTokenRef, APIURL: d.Cfg.Slack.APIURL, Log: log},
		}
		disp := &notify.Dispatcher{DB: d.DB, Sinks: sinks, Link: d.PublicLink, Log: log}
		api := &notify.API{DB: d.DB, Log: log, Sinks: sinks, Link: d.PublicLink}
		return Wiring{Modules: []server.Module{api}, Workers: []Worker{disp.Run}}, nil
	})
}
