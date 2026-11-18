package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/slack-go/slack"

	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// SlackSink posts Block Kit messages with chat.postMessage (bot token with
// chat:write). The token is a Key Vault reference resolved at first use and
// cached in memory only; it is dropped and re-resolved after an auth error
// so rotation in Key Vault takes effect without a restart.
//
// Messages are short, link to the object, carry the idempotency key in the
// message metadata and never contain interactive elements.
type SlackSink struct {
	KV       secrets.KeyVault
	TokenRef string // kv://<vault>/<secret>
	APIURL   string // tests only; default https://slack.com/api/
	HTTP     *http.Client
	Log      *slog.Logger

	mu       sync.Mutex
	client   *slack.Client
	warnOnce sync.Once
}

func (s *SlackSink) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

func (s *SlackSink) notConfigured(reason string) error {
	s.warnOnce.Do(func() {
		s.log().Warn("slack notifications are not configured; events stay pending until a bot token is available", "reason", reason)
	})
	return fmt.Errorf("slack bot token not configured (%s): %w", reason, ErrSinkNotConfigured)
}

func (s *SlackSink) getClient(ctx context.Context) (*slack.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	if s.TokenRef == "" {
		return nil, s.notConfigured("slack.botTokenRef is empty")
	}
	b, err := secrets.Resolve(ctx, s.KV, s.TokenRef)
	if errors.Is(err, secrets.ErrSecretNotFound) {
		return nil, s.notConfigured("key vault secret not found")
	}
	if err != nil {
		return nil, fmt.Errorf("resolve slack bot token: %w", err)
	}
	token := strings.TrimSpace(string(b))
	secrets.Zero(b)
	if token == "" {
		return nil, s.notConfigured("key vault secret is empty")
	}
	opts := []slack.Option{}
	if s.APIURL != "" {
		u := s.APIURL
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		opts = append(opts, slack.OptionAPIURL(u))
	}
	hc := s.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	opts = append(opts, slack.OptionHTTPClient(hc))
	s.client = slack.New(token, opts...)
	return s.client, nil
}

func (s *SlackSink) dropClient() {
	s.mu.Lock()
	s.client = nil
	s.mu.Unlock()
}

// Send implements Sink.
func (s *SlackSink) Send(ctx context.Context, ch Channel, m Message) error {
	if ch.SlackChannelID == "" {
		return errors.New("channel has no slack_channel_id")
	}
	c, err := s.getClient(ctx)
	if err != nil {
		return err
	}
	blocks := SlackBlocks(m)
	_, _, err = c.PostMessageContext(ctx, ch.SlackChannelID,
		slack.MsgOptionText(secrets.RedactString(m.Title), false),
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionMetadata(slackMetadata(m)),
		slack.MsgOptionDisableLinkUnfurl(),
		slack.MsgOptionDisableMediaUnfurl(),
	)
	if err == nil {
		return nil
	}
	var se slack.SlackErrorResponse
	if errors.As(err, &se) {
		switch se.Err {
		case "invalid_auth", "token_revoked", "token_expired", "account_inactive", "not_authed":
			s.dropClient()
		}
		return fmt.Errorf("slack: %s", se.Err)
	}
	return fmt.Errorf("slack: %s", secrets.RedactString(err.Error()))
}

func slackMetadata(m Message) slack.SlackMetadata {
	return slack.SlackMetadata{
		EventType: "olympos_" + strings.NewReplacer(".", "_", "-", "_").Replace(m.EventType),
		EventPayload: map[string]any{
			"idempotency_key": m.Key,
			"event_type":      m.EventType,
		},
	}
}

var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func esc(s string) string { return mrkdwnEscaper.Replace(secrets.RedactString(s)) }

// SlackBlocks renders a message: one section with the title, an optional
// context with the fields, and a context with the link. No actions blocks,
// no buttons, no accessories.
func SlackBlocks(m Message) []slack.Block {
	title := esc(m.Title)
	if m.Test {
		title = ":white_check_mark: " + title
	}
	blocks := []slack.Block{
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, "*"+title+"*", false, false), nil, nil),
	}
	if len(m.Fields) > 0 {
		keys := make([]string, 0, len(m.Fields))
		for k := range m.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var els []slack.MixedElement
		for i, k := range keys {
			if i == 10 { // context blocks allow at most 10 elements
				break
			}
			els = append(els, slack.NewTextBlockObject(slack.MarkdownType, "*"+esc(k)+":* "+esc(m.Fields[k]), false, false))
		}
		blocks = append(blocks, slack.NewContextBlock("", els...))
	}
	foot := "`" + esc(m.EventType) + "`"
	if m.Link != "" && (strings.HasPrefix(m.Link, "https://") || strings.HasPrefix(m.Link, "http://")) {
		foot = "<" + strings.NewReplacer("|", "%7C", ">", "%3E", "<", "%3C").Replace(m.Link) + "|Open in Olympos> · " + foot
	}
	blocks = append(blocks, slack.NewContextBlock("", slack.NewTextBlockObject(slack.MarkdownType, foot, false, false)))
	return blocks
}
