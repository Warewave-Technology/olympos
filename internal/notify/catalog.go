package notify

// CatalogEntry describes one event type for the routing UI.
type CatalogEntry struct {
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	// OptIn is true for events that are noisy by nature and never routed
	// by default (backup.succeeded).
	OptIn bool `json:"opt_in"`
}

var descriptions = map[string]string{
	BackupFailed:        "A backup run failed.",
	BackupPartial:       "A backup was written to some of its destinations but not all.",
	BackupMissed:        "A scheduled backup run did not start (scheduler down or overlap).",
	BackupSucceeded:     "A backup run succeeded. Opt-in: noisy, off unless routed explicitly.",
	CROpened:            "A Vault change request was opened and waits for approval.",
	CRApproved:          "A change request was approved.",
	CRRejected:          "A change request was rejected.",
	CRExpired:           "A change request expired before a decision.",
	CRFailed:            "An approved change request failed to apply.",
	RestoreRequested:    "A restore request was opened and waits for approval.",
	RestoreApproved:     "A restore request was approved; the restore starts when the target's agent is connected.",
	RestoreRejected:     "A restore request was rejected.",
	RestoreStarted:      "An approved restore started writing to its target.",
	RestoreSucceeded:    "A restore finished successfully.",
	RestoreFailed:       "A restore failed (the databases it created stay on the target and are listed).",
	RestoreBreakGlass:   "An admin started a restore without a second person's approval (break-glass), with a justification.",
	VaultUnmanagedWrite: "A secret changed in Vault outside Olympos (drift).",
	AuditNewFindings:    "An audit run found new findings.",
	VulnCritical:        "A running image has a new critical vulnerability.",
	SensitiveDataFound:  "A ConfigMap holds what looks like a credential (one message per cluster and scan).",
	SecretFindings:      "The Secret inventory found unused Secrets or legacy service account tokens (one message per cluster and scan).",
	AgentOffline:        "A cluster agent has been offline for 5 minutes (configurable: agents.offlineAlertAfter).",
	AgentOnline:         "A cluster agent is back online after an agent.offline alert.",
	AgentFlapping:       "A cluster agent disconnected more than 5 times in 30 minutes.",
	GrantChanged:        "A role grant was added or revoked.",
	GrantStale:          "A grant belongs to a disabled or deleted Entra account.",
	SASExpiring:         "A destination SAS token expires soon (14 and 3 days before) or has expired.",
}

// IsOptIn reports whether an event type is opt-in.
func IsOptIn(eventType string) bool { return eventType == BackupSucceeded }

// Known reports whether eventType is in the catalog.
func Known(eventType string) bool {
	_, ok := descriptions[eventType]
	return ok
}

// CatalogEntries returns the catalog in display order.
func CatalogEntries() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(Catalog))
	for _, t := range Catalog {
		out = append(out, CatalogEntry{EventType: t, Description: descriptions[t], OptIn: IsOptIn(t)})
	}
	return out
}
