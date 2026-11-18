package schedule

import (
	"testing"
	"time"
)

func TestParseAndNextInZone(t *testing.T) {
	s, err := Parse("0 2 * * *", "Europe/Istanbul")
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	next := s.Next(from)
	// 02:00 Istanbul (UTC+3) = 23:00 UTC previous day; after 00:00 UTC it is 23:00 UTC on the 18th.
	if want := time.Date(2026, 11, 18, 23, 0, 0, 0, time.UTC); !next.Equal(want) {
		t.Fatalf("next %v want %v", next, want)
	}
	if got := s.Between(from, from.Add(72*time.Hour), 10); len(got) != 3 {
		t.Fatalf("between: %v", got)
	}
	if _, err := Parse("bad", "UTC"); err == nil {
		t.Fatal("bad cron accepted")
	}
	if _, err := Parse("0 2 * * *", "Mars/Olympus"); err == nil {
		t.Fatal("bad zone accepted")
	}
	if d := s.Interval(from); d != 24*time.Hour {
		t.Fatalf("interval %v", d)
	}
}

func TestLockKeysUnique(t *testing.T) {
	seen := map[int64]bool{}
	for _, k := range AllLocks {
		if seen[k] {
			t.Fatalf("advisory lock key %#x used twice", k)
		}
		seen[k] = true
	}
}
