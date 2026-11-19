package audit

import (
	"strings"
	"testing"
)

// Security review #4: values never reach the stored raw report.
func TestRedactRawReport(t *testing.T) {
	raw := `{"resources":[
	 {"resourceID":"a","object":{"kind":"ConfigMap","metadata":{"name":"cfg","namespace":"x",
	   "annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"data\":{\"pw\":\"CANARY-1\"}}","team":"a"},
	   "managedFields":[{"fieldsV1":{"f:data":{"f:pw":{}}}}]},
	   "data":{"pw":"CANARY-2"},"binaryData":{"b":"Q0FOQVJZLTM="}}},
	 {"resourceID":"b","object":{"kind":"Deployment","metadata":{"name":"web"},"spec":{"template":{"spec":{"containers":[
	   {"name":"c","env":[{"name":"DB_PASSWORD","value":"CANARY-4"},{"name":"REF","valueFrom":{"secretKeyRef":{"name":"s","key":"k"}}}]}]}}}}}
	],"summaryDetails":{"score":71.5}}`
	out := string(RedactRawReport([]byte(raw)))
	for _, c := range []string{"CANARY-1", "CANARY-2", "Q0FOQVJZLTM=", "CANARY-4", "f:pw"} {
		if strings.Contains(out, c) {
			t.Errorf("%s survived: %s", c, out)
		}
	}
	for _, keep := range []string{`"DB_PASSWORD"`, `"secretKeyRef"`, `"team":"a"`, `71.5`, `"name":"cfg"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("%s lost: %s", keep, out)
		}
	}
	if RedactRawReport([]byte("not json")) != nil {
		t.Fatal("a report that cannot be parsed must not be stored")
	}
}
