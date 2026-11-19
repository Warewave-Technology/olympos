package audit

import (
	"bytes"
	"encoding/json"
)

// RedactRawReport removes values from a tool's raw JSON before it is stored
// (security review #4). kubescape embeds the objects it scanned, read over
// the API proxy: ConfigMap and Secret data, literal container env values and
// last-applied-configuration (a full copy of the object) would otherwise
// land in Blob storage. Findings are computed from the unredacted report;
// only the stored copy is redacted. A report that is not JSON (nothing to
// walk) means the report is not stored: nil.
func RedactRawReport(raw []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	v = redactValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return out
}

const redacted = "[redacted by Olympos]"

var dataKinds = map[string]bool{"ConfigMap": true, "Secret": true}

func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if k, _ := x["kind"].(string); dataKinds[k] {
			for _, f := range []string{"data", "binaryData", "stringData"} {
				if _, ok := x[f]; ok {
					x[f] = redacted
				}
			}
		}
		delete(x, "managedFields")
		if ann, ok := x["annotations"].(map[string]any); ok {
			if _, ok := ann["kubectl.kubernetes.io/last-applied-configuration"]; ok {
				ann["kubectl.kubernetes.io/last-applied-configuration"] = redacted
			}
		}
		if env, ok := x["env"].([]any); ok {
			for _, e := range env {
				if m, ok := e.(map[string]any); ok {
					if _, ok := m["value"]; ok {
						m["value"] = redacted
					}
				}
			}
		}
		for k, c := range x {
			x[k] = redactValue(c)
		}
		return x
	case []any:
		for i, c := range x {
			x[i] = redactValue(c)
		}
		return x
	}
	return v
}
