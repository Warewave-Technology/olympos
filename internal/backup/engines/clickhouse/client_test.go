package clickhouse

import "testing"

func TestClientBin(t *testing.T) {
	t.Cleanup(func() { SetClientBin("") })
	SetClientBin("")
	if got := ClientBin(); got != DefaultClientBin {
		t.Fatalf("default = %q", got)
	}
	SetClientBin("/usr/lib/olympos/bin/clickhouse")
	if got := ClientBin(); got != "/usr/lib/olympos/bin/clickhouse" {
		t.Fatalf("set = %q", got)
	}
}
