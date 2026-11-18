package gateway

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// TestProtoHasNoCredentialFields enforces SPEC §18: no message on the agent
// wire can carry a credential, SAS or Blob key. The bootstrap token is the
// agent's own one-time enrollment secret and is the only allowed exception.
func TestProtoHasNoCredentialFields(t *testing.T) {
	banned := []string{"password", "secret", "token", "sas", "credential", "key", "dsn", "auth"}
	allowed := map[string]bool{"olympos.v1.EnrollRequest.bootstrap_token": true,
		// The name of a ConfigMap key (F2), never its value.
		"olympos.v1.SensitiveDataItem.key": true}
	fd := pb.File_olympos_v1_gateway_proto
	msgs := fd.Messages()
	var walk func(m protoreflect.MessageDescriptor)
	walk = func(m protoreflect.MessageDescriptor) {
		fs := m.Fields()
		for i := 0; i < fs.Len(); i++ {
			f := fs.Get(i)
			full := string(f.FullName())
			name := strings.ToLower(string(f.Name()))
			if m.IsMapEntry() && f.Number() == 1 {
				// The synthetic "key" of a map entry (e.g. label keys);
				// the map field's own name is checked on its parent.
				continue
			}
			for _, b := range banned {
				if strings.Contains(name, b) && !allowed[full] {
					t.Errorf("field %s looks like a credential (%q)", full, b)
				}
			}
		}
		for i := 0; i < m.Messages().Len(); i++ {
			walk(m.Messages().Get(i))
		}
	}
	for i := 0; i < msgs.Len(); i++ {
		walk(msgs.Get(i))
	}
}

// F2: the sensitive-data report can never carry value bytes: no bytes
// fields and exactly these fields (a new field must be reviewed here).
func TestSensitiveDataReportCarriesNoValues(t *testing.T) {
	want := map[string][]string{
		"SensitiveDataItem":   {"namespace", "config_map", "key", "rule_id", "rule_description", "confidence", "value_length"},
		"SensitiveDataReport": {"rules_version", "config_maps_scanned", "items"},
	}
	for name, fields := range want {
		m := pb.File_olympos_v1_gateway_proto.Messages().ByName(protoreflect.Name(name))
		if m == nil {
			t.Fatalf("%s missing", name)
		}
		fs := m.Fields()
		if fs.Len() != len(fields) {
			t.Fatalf("%s has %d fields, want %v", name, fs.Len(), fields)
		}
		for i, f := range fields {
			fd := fs.Get(i)
			if string(fd.Name()) != f {
				t.Fatalf("%s field %d is %s, want %s", name, i, fd.Name(), f)
			}
			if fd.Kind() == protoreflect.BytesKind {
				t.Fatalf("%s.%s is bytes", name, f)
			}
		}
	}
}
