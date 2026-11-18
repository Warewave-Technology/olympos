package agent

import "k8s.io/client-go/rest"

// extenders add reporters and the bench runner (M4/M5). Each feature file
// registers itself with registerExtender in an init().
var extenders []func(a *Agent, cfg Config, rc *rest.Config)

func registerExtender(f func(a *Agent, cfg Config, rc *rest.Config)) {
	extenders = append(extenders, f)
}

// Extend installs optional reporters and the bench runner.
func Extend(a *Agent, cfg Config, rc *rest.Config) {
	for _, f := range extenders {
		f(a, cfg, rc)
	}
}
