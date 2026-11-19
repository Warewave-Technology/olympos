package agent

import (
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Security review #9: only controller-made IP slices are dialled.
func TestPickEndpoint(t *testing.T) {
	port := int32(5432)
	name := "pg"
	ready := true
	slice := func(n, managedBy string, at discoveryv1.AddressType, addr string) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Name: n, Namespace: "db", Labels: map[string]string{discoveryv1.LabelServiceName: "orders", discoveryv1.LabelManagedBy: managedBy}},
			AddressType: at,
			Ports:       []discoveryv1.EndpointPort{{Name: &name, Port: &port}},
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{addr}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		}
	}
	for _, c := range []struct {
		name   string
		slices []*discoveryv1.EndpointSlice
		want   string
	}{
		{"controller slice", []*discoveryv1.EndpointSlice{slice("a", endpointSliceController, discoveryv1.AddressTypeIPv4, "10.244.1.7")}, "10.244.1.7:5432"},
		{"hand-made slice", []*discoveryv1.EndpointSlice{slice("a", "someone", discoveryv1.AddressTypeIPv4, "10.0.0.9")}, ""},
		{"FQDN slice", []*discoveryv1.EndpointSlice{slice("a", endpointSliceController, discoveryv1.AddressTypeFQDN, "db.attacker.example")}, ""},
		{"metadata address", []*discoveryv1.EndpointSlice{slice("a", endpointSliceController, discoveryv1.AddressTypeIPv4, "169.254.169.254")}, ""},
		{"loopback", []*discoveryv1.EndpointSlice{slice("a", endpointSliceController, discoveryv1.AddressTypeIPv4, "127.0.0.1")}, ""},
		{"injected next to the real one", []*discoveryv1.EndpointSlice{
			slice("z-evil", "someone", discoveryv1.AddressTypeIPv4, "10.0.0.9"),
			slice("a", endpointSliceController, discoveryv1.AddressTypeIPv6, "fd00::7")}, "[fd00::7]:5432"},
	} {
		got, err := pickEndpoint(c.slices, "db", "orders", "pg")
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
	}
}
