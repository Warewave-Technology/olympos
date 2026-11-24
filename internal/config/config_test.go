package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSyntheticDefaults(t *testing.T) {
	c := &Server{}
	c.defaults()
	want := Synthetic{
		RunRetention: 720 * time.Hour, AggregateRetention: 9600 * time.Hour, ExcerptRetention: 168 * time.Hour,
		MaxRequestsPerMinutePerCluster: 600, MaxRequestsPerMinutePerScenario: 120, ProbeOfflineAlertAfter: 5 * time.Minute,
	}
	if c.Synthetic != want {
		t.Fatalf("defaults %+v, want %+v", c.Synthetic, want)
	}
}

func TestSyntheticYAML(t *testing.T) {
	c := &Server{}
	if err := yaml.Unmarshal([]byte("synthetic:\n  probeOfflineAlertAfter: 10m\n  maxRequestsPerMinutePerCluster: 900\n"), c); err != nil {
		t.Fatal(err)
	}
	c.defaults()
	if c.Synthetic.ProbeOfflineAlertAfter != 10*time.Minute || c.Synthetic.MaxRequestsPerMinutePerCluster != 900 ||
		c.Synthetic.MaxRequestsPerMinutePerScenario != 120 {
		t.Fatalf("parsed %+v", c.Synthetic)
	}
	neg := Synthetic{RunRetention: -time.Hour, MaxRequestsPerMinutePerScenario: -1}
	neg.defaults()
	if errs := neg.validate(); len(errs) != 2 {
		t.Fatalf("negative values: %v", errs)
	}
}
