package metrics

import "github.com/prometheus/client_golang/prometheus"

// Notification dispatcher metrics (SPEC §14, §17). OutboxBacklog lives in
// metrics.go and is refreshed by the server's metrics loop.
var (
	NotificationDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "olympos_notification_deliveries_total",
		Help: "Outbox events processed by the dispatcher, by result (delivered, no_route, retry, pending_unconfigured).",
	}, []string{"result"})
	NotificationSendDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "olympos_notification_send_duration_seconds", Help: "Duration of one sink send.",
		Buckets: prometheus.DefBuckets,
	}, []string{"kind", "status"})
)

func init() {
	Registry.MustRegister(NotificationDeliveries, NotificationSendDuration)
}
