package clickhouse

import "sync/atomic"

// DefaultClientBin is the clickhouse binary looked up on PATH.
const DefaultClientBin = "clickhouse"

var clientBin atomic.Value

// SetClientBin sets the clickhouse binary restores run as `<bin> client`
// (config backup.clickhouseClient). Call before workers start.
func SetClientBin(bin string) {
	if bin == "" {
		bin = DefaultClientBin
	}
	clientBin.Store(bin)
}

// ClientBin is the configured clickhouse binary (a path or a name on PATH).
func ClientBin() string {
	if v, ok := clientBin.Load().(string); ok && v != "" {
		return v
	}
	return DefaultClientBin
}
