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
	allowed := map[string]bool{"olympos.v1.EnrollRequest.bootstrap_token": true}
	fd := pb.File_olympos_v1_gateway_proto
	msgs := fd.Messages()
	var walk func(m protoreflect.MessageDescriptor)
	walk = func(m protoreflect.MessageDescriptor) {
		fs := m.Fields()
		for i := 0; i < fs.Len(); i++ {
			f := fs.Get(i)
			full := string(f.FullName())
			name := strings.ToLower(string(f.Name()))
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
