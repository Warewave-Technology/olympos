package clickhouse

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/targettls"
)

const (
	clientName       = "olympos-backup"
	handshakeTimeout = 30 * time.Second
	// readTimeout bounds a single packet read. Long queries still deliver
	// Progress packets (interactive_delay, 100ms by default) so this only
	// fires on a stuck tunnel.
	readTimeout = 5 * time.Minute
)

// ErrNoTLS: transfer mode e2e-tls and the target has no TLS on the port.
var ErrNoTLS = errors.New("clickhouse: this target has no TLS on this port, and the native protocol would send the password in clear, " +
	"so Olympos refuses it in transfer mode e2e-tls. Enable TLS on the target (tcp_port_secure) and point the target at that port, " +
	"or, accepting that risk, set this cluster's transfer mode to compressed in Settings › Clusters & agents")

// session is one native-protocol connection to the target.
type session struct {
	client *ch.Client
	tls    bool
	// noSystemParts is set when system.parts is not readable; partitions
	// and row counts then come from the tables (_partition_id, count()).
	noSystemParts bool
}

// connect dials the target through the tunnel (ec.Dial), wraps it in TLS
// when the transfer mode is e2e-tls and performs the native handshake with
// zstd network compression (used in both transfer modes, SPEC §7).
func connect(ctx context.Context, ec backup.EngineContext, opts Options) (*session, error) {
	if ec.Dial == nil {
		return nil, errors.New("clickhouse: no tunnel dialer")
	}
	if ec.Credential == nil {
		return nil, errors.New("clickhouse: no credential")
	}
	var tlsCfg *tls.Config
	if ec.UseTLS {
		cfg, err := tlsConfig(ec, opts)
		if err != nil {
			return nil, err
		}
		tlsCfg = cfg
	}

	cred, err := ec.Credential(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: credential: %w", err)
	}
	defer zero(cred.Secret)

	raw, err := ec.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: dial: %w", err)
	}
	conn := raw
	if tlsCfg != nil {
		tc := tls.Client(raw, tlsCfg)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		var rhe tls.RecordHeaderError
		switch {
		case err != nil && errors.As(err, &rhe):
			// The target answered in plaintext: it has no TLS on this port.
			// The native protocol sends the password in clear, so e2e-tls
			// refuses (F1), like Vault. Certificate errors never fall back.
			_ = raw.Close()
			return nil, ErrNoTLS
		case err != nil:
			_ = raw.Close()
			return nil, fmt.Errorf("clickhouse: tls handshake (server name %q): %w", tlsCfg.ServerName, err)
		default:
			conn = tc
		}
	}

	user := cred.Username
	if user == "" {
		user = ch.DefaultUser
	}
	client, err := ch.Connect(ctx, conn, ch.Options{
		// All queries are fully qualified; "system" always exists, so the
		// handshake does not depend on the user's databases.
		Database: "system",
		User:     user,
		// ch-go only accepts a string: the []byte secret is zeroed when
		// connect returns, but ch-go keeps the string in its (private) client
		// hello until the session is closed and collected. It is never
		// logged or returned.
		Password:         string(cred.Secret),
		Compression:      ch.CompressionZSTD,
		ClientName:       clientName,
		ProtocolVersion:  protocolVersion,
		ReadTimeout:      readTimeout,
		HandshakeTimeout: handshakeTimeout,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clickhouse: connect: %w", err)
	}
	return &session{client: client, tls: tlsCfg != nil}, nil
}

func (s *session) close() {
	if s != nil && s.client != nil {
		_ = s.client.Close()
	}
}

func tlsConfig(ec backup.EngineContext, opts Options) (*tls.Config, error) {
	name := ec.TLSServerName
	if name == "" {
		name = ec.Target.TLSServerName
	}
	if name == "" {
		return nil, errors.New("clickhouse: TLS server name is required in e2e-tls mode")
	}
	// The configured target CA bundle (+ system roots with
	// targetTLS.systemRoots) and the per-target ca_pem.
	perTarget := strings.TrimSpace(opts.CAPEM) != ""
	if err := targettls.Usable(ec.TrustSystemRoots, perTarget); err != nil {
		return nil, err
	}
	pool := targettls.Roots(ec.TrustSystemRoots).Clone()
	if perTarget && !pool.AppendCertsFromPEM([]byte(opts.CAPEM)) {
		return nil, errors.New("clickhouse: ca_pem contains no valid certificate")
	}
	return &tls.Config{
		ServerName: name,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// schemaSettings keep secrets (passwords of external sources in engines and
// dictionaries) masked in SHOW CREATE output even if the user's profile
// allows displaying them. Not "important": ignored by servers that do not
// know the setting.
var schemaSettings = []ch.Setting{{Key: "format_display_secrets_in_show_and_select", Value: "0"}}

// queryStrings runs a query whose columns are all String and returns rows.
func (s *session) queryStrings(ctx context.Context, body string, settings ...ch.Setting) ([][]string, error) {
	var (
		res  nativeResult
		rows [][]string
	)
	collect := func() error {
		if res.rows == 0 {
			return nil
		}
		cols := make([][]string, len(res.cols))
		for i := range res.cols {
			c, err := res.stringColumn(i)
			if err != nil {
				return err
			}
			cols[i] = c
		}
		for r := 0; r < res.rows; r++ {
			row := make([]string, len(cols))
			for i := range cols {
				row[i] = cols[i][r]
			}
			rows = append(rows, row)
		}
		return nil
	}
	err := s.client.Do(ctx, ch.Query{
		Body:     body,
		Result:   &res,
		Settings: settings,
		OnResult: func(context.Context, proto.Block) error { return collect() },
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// queryValue returns the single String value of a one-row query.
func (s *session) queryValue(ctx context.Context, body string, settings ...ch.Setting) (string, error) {
	rows, err := s.queryStrings(ctx, body, settings...)
	if err != nil {
		return "", err
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return "", fmt.Errorf("expected one value, got %d rows", len(rows))
	}
	return rows[0][0], nil
}

// headerResult reads only the header of a 0-row result (names and types),
// whatever the types are.
type headerResult struct {
	names, types []string
}

func (h *headerResult) DecodeResult(rd *proto.Reader, version int, b proto.Block) error {
	if b.Rows != 0 {
		return errors.New("header query returned rows")
	}
	if h.names != nil {
		return nil
	}
	h.names = make([]string, 0, b.Columns)
	h.types = make([]string, 0, b.Columns)
	for i := 0; i < b.Columns; i++ {
		name, err := rd.Str()
		if err != nil {
			return err
		}
		typ, err := rd.Str()
		if err != nil {
			return err
		}
		if proto.FeatureCustomSerialization.In(version) {
			if _, err := rd.Bool(); err != nil {
				return err
			}
		}
		h.names = append(h.names, name)
		h.types = append(h.types, typ)
	}
	return nil
}

// selectHeader returns the names and types `SELECT *` yields for a table.
func (s *session) selectHeader(ctx context.Context, from string) ([]string, []string, error) {
	var h headerResult
	err := s.client.Do(ctx, ch.Query{
		Body:     "SELECT * FROM " + from + " LIMIT 0",
		Result:   &h,
		OnResult: func(context.Context, proto.Block) error { return nil },
	})
	if err != nil {
		return nil, nil, err
	}
	return h.names, h.types, nil
}

// streamNative runs a SELECT and writes its blocks as Native format into
// the writer returned by open (called lazily on the first non-empty block,
// so empty results produce no entry).
func (s *session) streamNative(ctx context.Context, body string, open func() (io.Writer, error)) (uint64, error) {
	var (
		res  nativeResult
		buf  proto.Buffer
		w    io.Writer
		rows uint64
	)
	err := s.client.Do(ctx, ch.Query{
		Body:   body,
		Result: &res,
		OnResult: func(context.Context, proto.Block) error {
			if res.rows == 0 {
				return nil
			}
			if w == nil {
				var err error
				if w, err = open(); err != nil {
					return err
				}
			}
			if err := writeNativeBlock(w, &buf, &res); err != nil {
				return err
			}
			rows += uint64(res.rows)
			return nil
		},
	})
	return rows, err
}

// streamRowBinary is the fallback for tables with column types the Native
// block codec cannot handle: the server serializes each row with
// formatRow('RowBinary', *) (formatRow, not formatRowNoNewline: the latter
// drops the last byte), we write a RowBinaryWithNamesAndTypes header and the
// concatenated rows. Restorable with INSERT ... FORMAT RowBinaryWithNamesAndTypes.
func (s *session) streamRowBinary(ctx context.Context, from, where string, names, types []string, open func() (io.Writer, error)) (uint64, error) {
	var (
		res  nativeResult
		w    io.Writer
		rows uint64
	)
	err := s.client.Do(ctx, ch.Query{
		Body:   "SELECT formatRow('RowBinary', *) FROM " + from + where,
		Result: &res,
		OnResult: func(context.Context, proto.Block) error {
			if res.rows == 0 {
				return nil
			}
			col, ok := res.cols[0].data.(*proto.ColStr)
			if !ok || len(res.cols) != 1 {
				return errors.New("unexpected formatRow result")
			}
			if w == nil {
				var err error
				if w, err = open(); err != nil {
					return err
				}
				if err := rowBinaryHeader(w, names, types); err != nil {
					return err
				}
			}
			for i := 0; i < col.Rows(); i++ {
				if _, err := w.Write(col.RowBytes(i)); err != nil {
					return err
				}
			}
			rows += uint64(res.rows)
			return nil
		},
	})
	return rows, err
}

// quoteIdent quotes a ClickHouse identifier with backticks.
func quoteIdent(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "`", "\\`")
	return "`" + s + "`"
}

// quoteString quotes a ClickHouse string literal.
func quoteString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

func qualified(db, table string) string { return quoteIdent(db) + "." + quoteIdent(table) }
