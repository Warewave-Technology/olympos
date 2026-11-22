// Package metrics defines Olympos's Prometheus metrics (SPEC §17).
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	AgentsOnline = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "olympos_agents_online", Help: "Clusters whose agent is online.",
	})
	Tunnels = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "olympos_tunnels_open", Help: "Open tunnels on this replica.",
	})
	BackupRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "olympos_backup_runs_total", Help: "Finished backup runs by engine and status.",
	}, []string{"engine", "status"})
	BackupDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "olympos_backup_run_duration_seconds", Help: "Backup run duration.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 16),
	}, []string{"engine", "status"})
	BackupCopies = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "olympos_backup_copies_total", Help: "Finished backup copies by destination (name) and status.",
	}, []string{"destination", "status"})
	SchedulerLag = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "olympos_scheduler_lag_seconds", Help: "Delay between a run's scheduled time and when it was queued.",
	})
	OutboxBacklog = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "olympos_outbox_backlog", Help: "Undelivered notification events.",
	})
	ChangeRequests = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "olympos_change_requests", Help: "Change requests by status.",
	}, []string{"status"})
	AuditRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "olympos_audit_runs_total", Help: "Finished audit runs by tool and status.",
	}, []string{"tool", "status"})
	ImageScans = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "olympos_image_scans_total", Help: "Image scans by result.",
	}, []string{"result"})
)

// Registry holds all Olympos metrics plus Go/process collectors.
var Registry = prometheus.NewRegistry()

func init() {
	Registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		AgentsOnline, Tunnels, BackupRuns, BackupDuration, BackupCopies, SchedulerLag, OutboxBacklog, ChangeRequests, AuditRuns, ImageScans)
}
