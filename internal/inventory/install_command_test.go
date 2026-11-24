package inventory

import "testing"

// P21: Install probe carries the server's OLYMPOS_AGENT_INSTALL_SETS (an
// image mirror, probe.image.*) like the Add cluster command; the probe's own
// sets come last and the token ends the command.
func TestProbeInstallCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		api  API
		want string
	}{
		{"defaults", API{},
			"helm upgrade olympos-agent oci://ghcr.io/warewave-technology/charts/olympos-agent -n olympos-system --reuse-values --set probe.enabled=true --set probe.bootstrapToken=olyb_t"},
		{"install sets", API{AgentChart: "./deploy/helm/olympos-agent", AgentSets: []string{"image.repository=mirror/olympos-agent", "probe.image.repository=mirror/olympos-probe"}},
			"helm upgrade olympos-agent ./deploy/helm/olympos-agent -n olympos-system --reuse-values --set image.repository=mirror/olympos-agent --set probe.image.repository=mirror/olympos-probe --set probe.enabled=true --set probe.bootstrapToken=olyb_t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.api.probeInstallCommand("olyb_t"); got != tc.want {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}
