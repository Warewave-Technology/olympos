package destinations

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

// The S3 can-delete warning names lifecycle rules as retention and Object
// Lock as optional, not as the way retention is done (#79).
func TestWarningsS3CanDelete(t *testing.T) {
	out := warnings(blob.KindS3, Report{CanDelete: true}, time.Now())
	if len(out) != 1 {
		t.Fatalf("warnings = %q, want one", out)
	}
	w := out[0]
	for _, want := range []string{"retention is bucket lifecycle rules", "s3:DeleteObjectVersion", "Object Lock is optional"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q lacks %q", w, want)
		}
	}
	if strings.Contains(w, "use Object Lock") {
		t.Errorf("warning %q still presents Object Lock as retention", w)
	}
}
