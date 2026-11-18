package main

import (
	"reflect"
	"testing"
)

func TestSplit(t *testing.T) {
	got, err := split(`"/usr/lib/postgresql/16/bin/pg_dump" -V`)
	if err != nil || !reflect.DeepEqual(got, []string{"/usr/lib/postgresql/16/bin/pg_dump", "-V"}) {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"a; rm -rf /", "a | b", "$(id)", "`id`", `"$HOME"`, "a > f", "a && b", "a\nb", "x*"} {
		if _, err := split(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
