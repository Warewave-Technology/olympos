package metrics_test

import (
	"testing"

	"github.com/Warewave-Technology/olympos/internal/metrics"
)

func TestBackupCopiesRegistered(t *testing.T) {
	metrics.BackupCopies.WithLabelValues("offsite", "failed").Inc()
	mfs, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "olympos_backup_copies_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["destination"] == "offsite" && labels["status"] == "failed" && m.GetCounter().GetValue() == 1 {
				return
			}
		}
		t.Fatalf("olympos_backup_copies_total: %v", mf)
	}
	t.Fatal("olympos_backup_copies_total is not registered")
}
