package audit

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/Warewave-Technology/olympos/internal/findings"
)

// Normalized is a tool report reduced to findings plus a score.
type Normalized struct {
	Findings []findings.Finding
	// Score is 0..100 (nil when the tool reported nothing scoreable).
	Score   *float64
	Summary map[string]any
}

// Severity mapping (documented in docs/audit.md via the report):
//
//	kubescape  scoreFactor ≥ 9 critical · ≥ 7 high · ≥ 4 medium · > 0 low · else info
//	polaris    danger → high · warning → medium (ignore → not a finding)
//	kube-bench FAIL scored → high · FAIL manual → medium (WARN/INFO/PASS → not findings)
func kubescapeSeverity(scoreFactor float64) string {
	switch {
	case scoreFactor >= 9:
		return "critical"
	case scoreFactor >= 7:
		return "high"
	case scoreFactor >= 4:
		return "medium"
	case scoreFactor > 0:
		return "low"
	}
	return "info"
}

func polarisSeverity(s string) string {
	switch strings.ToLower(s) {
	case "danger":
		return "high"
	case "warning":
		return "medium"
	}
	return ""
}

// resourceRef renders "<namespace>/<Kind>/<name>" or "<Kind>/<name>" for
// cluster-scoped objects.
func resourceRef(namespace, kind, name string) string {
	if namespace == "" {
		return kind + "/" + name
	}
	return namespace + "/" + kind + "/" + name
}

// ---------------------------------------------------------------- kubescape

type ksReport struct {
	SummaryDetails struct {
		Controls map[string]struct {
			ControlID   string   `json:"controlID"`
			Name        string   `json:"name"`
			ScoreFactor float64  `json:"scoreFactor"`
			Score       float64  `json:"score"`
			Compliance  *float64 `json:"complianceScore"`
		} `json:"controls"`
		Frameworks []struct {
			Name            string  `json:"name"`
			Score           float64 `json:"score"`
			ComplianceScore float64 `json:"complianceScore"`
		} `json:"frameworks"`
		Score           float64  `json:"score"`
		ComplianceScore *float64 `json:"complianceScore"`
	} `json:"summaryDetails"`
	Results []struct {
		ResourceID string `json:"resourceID"`
		Controls   []struct {
			ControlID string          `json:"controlID"`
			Name      string          `json:"name"`
			Status    json.RawMessage `json:"status"`
		} `json:"controls"`
	} `json:"results"`
	Resources []struct {
		ResourceID string `json:"resourceID"`
		Object     struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"object"`
	} `json:"resources"`
}

// ksStatus accepts both {"status":"failed"} and a bare "failed".
func ksStatus(raw json.RawMessage) string {
	var s struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(raw, &s) == nil && s.Status != "" {
		return strings.ToLower(s.Status)
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return strings.ToLower(str)
	}
	return ""
}

// ksResourceRef parses kubescape resource IDs such as
// "apps/v1/default/Deployment/nginx", "/v1/default/Pod/x" or
// "rbac.authorization.k8s.io/v1//ClusterRole/admin".
func ksResourceRef(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) >= 3 {
		n := len(parts)
		return resourceRef(parts[n-3], parts[n-2], parts[n-1])
	}
	if id == "" {
		return "cluster"
	}
	return id
}

// NormalizeKubescape parses `kubescape --format json --format-version v2`.
func NormalizeKubescape(raw []byte) (Normalized, error) {
	var r ksReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return Normalized{}, fmt.Errorf("parse kubescape report: %w", err)
	}
	refs := map[string]string{}
	for _, res := range r.Resources {
		if res.Object.Kind != "" && res.Object.Metadata.Name != "" {
			refs[res.ResourceID] = resourceRef(res.Object.Metadata.Namespace, res.Object.Kind, res.Object.Metadata.Name)
		}
	}
	var out Normalized
	failedControls := map[string]bool{}
	for _, res := range r.Results {
		ref, ok := refs[res.ResourceID]
		if !ok {
			ref = ksResourceRef(res.ResourceID)
		}
		for _, c := range res.Controls {
			if ksStatus(c.Status) != "failed" {
				continue
			}
			sum := r.SummaryDetails.Controls[c.ControlID]
			title := c.Name
			if title == "" {
				title = sum.Name
			}
			failedControls[c.ControlID] = true
			out.Findings = append(out.Findings, findings.Finding{
				ControlID: c.ControlID, ResourceRef: ref, Severity: kubescapeSeverity(sum.ScoreFactor), Title: title,
				Details: map[string]any{"resource_id": res.ResourceID, "score_factor": sum.ScoreFactor},
			})
		}
	}
	switch {
	case r.SummaryDetails.ComplianceScore != nil:
		out.Score = round1(*r.SummaryDetails.ComplianceScore)
	case len(r.SummaryDetails.Controls) > 0:
		out.Score = round1(r.SummaryDetails.Score)
	}
	fw := map[string]float64{}
	for _, f := range r.SummaryDetails.Frameworks {
		v := f.ComplianceScore
		if v == 0 {
			v = f.Score
		}
		fw[f.Name] = *round1(v)
	}
	out.Summary = map[string]any{"failed_controls": len(failedControls), "controls": len(r.SummaryDetails.Controls), "frameworks": fw}
	sortFindings(out.Findings)
	return out, nil
}

// ---------------------------------------------------------------- polaris

type plResult struct {
	ID       string `json:"ID"`
	Message  string `json:"Message"`
	Success  bool   `json:"Success"`
	Severity string `json:"Severity"`
	Category string `json:"Category"`
}

type plReport struct {
	Score   *float64 `json:"Score"`
	Results []struct {
		Name      string              `json:"Name"`
		Namespace string              `json:"Namespace"`
		Kind      string              `json:"Kind"`
		Results   map[string]plResult `json:"Results"`
		PodResult *struct {
			Name             string              `json:"Name"`
			Results          map[string]plResult `json:"Results"`
			ContainerResults []struct {
				Name    string              `json:"Name"`
				Results map[string]plResult `json:"Results"`
			} `json:"ContainerResults"`
		} `json:"PodResult"`
	} `json:"Results"`
}

// NormalizePolaris parses `polaris audit --format json`.
func NormalizePolaris(raw []byte) (Normalized, error) {
	var r plReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return Normalized{}, fmt.Errorf("parse polaris report: %w", err)
	}
	var out Normalized
	var successes, warnings, dangers int
	add := func(ref string, rs map[string]plResult) {
		for key, m := range rs {
			sev := polarisSeverity(m.Severity)
			if sev == "" {
				continue
			}
			if m.Success {
				successes++
				continue
			}
			if sev == "high" {
				dangers++
			} else {
				warnings++
			}
			id := m.ID
			if id == "" {
				id = key
			}
			out.Findings = append(out.Findings, findings.Finding{
				ControlID: id, ResourceRef: ref, Severity: sev, Title: m.Message,
				Details: map[string]any{"category": m.Category, "polaris_severity": m.Severity},
			})
		}
	}
	for _, res := range r.Results {
		ref := resourceRef(res.Namespace, res.Kind, res.Name)
		add(ref, res.Results)
		if res.PodResult != nil {
			add(ref, res.PodResult.Results)
			for _, c := range res.PodResult.ContainerResults {
				add(ref+"/container:"+c.Name, c.Results)
			}
		}
	}
	if r.Score != nil {
		out.Score = round1(*r.Score)
	} else if total := successes*2 + warnings + dangers*2; total > 0 {
		// Polaris' own formula (CountSummary.GetScore).
		out.Score = round1(float64(successes*2) / float64(total) * 100)
	}
	out.Summary = map[string]any{"successes": successes, "warnings": warnings, "dangers": dangers}
	sortFindings(out.Findings)
	return out, nil
}

// ---------------------------------------------------------------- kube-bench

type kbResult struct {
	TestNumber     string `json:"test_number"`
	TestDesc       string `json:"test_desc"`
	Status         string `json:"status"`
	Scored         bool   `json:"scored"`
	Remedy         string `json:"remediation"`
	ActualValue    string `json:"actual_value"`
	ExpectedResult string `json:"expected_result"`
	Reason         string `json:"reason"`
}

// BenchCheck is one kube-bench check on one node (node detail view).
type BenchCheck struct {
	ID          string `json:"id"`
	Section     string `json:"section"`
	SectionText string `json:"section_text"`
	NodeType    string `json:"node_type"`
	Description string `json:"description"`
	Status      string `json:"status"` // PASS | FAIL | WARN | INFO
	Scored      bool   `json:"scored"`
	Remediation string `json:"remediation"`
	Actual      string `json:"actual_value,omitempty"`
	Expected    string `json:"expected_result,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type kbControls struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Text     string `json:"text"`
	NodeType string `json:"node_type"`
	Tests    []struct {
		Section string     `json:"section"`
		Desc    string     `json:"desc"`
		Results []kbResult `json:"results"`
	} `json:"tests"`
}

// BenchNode is one node's parsed kube-bench outcome.
type BenchNode struct {
	Pass, Fail, Warn, Info int
	// ControlPlaneNA is set on managed clusters: control plane sections are
	// "Control plane N/A · managed", never counted as failed or missing.
	ControlPlaneNA bool
	Findings       []findings.Finding
	Checks         []BenchCheck
}

// controlPlaneTypes are kube-bench node_type values for control plane
// components.
var controlPlaneTypes = map[string]bool{"master": true, "controlplane": true, "etcd": true}

// NormalizeKubeBench parses `kube-bench run --json` output for one node.
// managed=true drops control plane sections (they are the provider's).
func NormalizeKubeBench(raw []byte, nodeName, benchmark string, managed bool) (BenchNode, error) {
	var controls []kbControls
	var wrapped struct {
		Controls []kbControls `json:"Controls"`
	}
	trim := strings.TrimSpace(string(raw))
	switch {
	case strings.HasPrefix(trim, "["):
		if err := json.Unmarshal(raw, &controls); err != nil {
			return BenchNode{}, fmt.Errorf("parse kube-bench output: %w", err)
		}
	default:
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return BenchNode{}, fmt.Errorf("parse kube-bench output: %w", err)
		}
		controls = wrapped.Controls
	}
	out := BenchNode{ControlPlaneNA: managed}
	ref := "node/" + nodeName
	bm := benchmarkName(benchmark)
	for _, c := range controls {
		if managed && controlPlaneTypes[strings.ToLower(c.NodeType)] {
			continue
		}
		for _, t := range c.Tests {
			for _, r := range t.Results {
				out.Checks = append(out.Checks, BenchCheck{ID: r.TestNumber, Section: t.Section, SectionText: t.Desc,
					NodeType: c.NodeType, Description: r.TestDesc, Status: strings.ToUpper(r.Status), Scored: r.Scored,
					Remediation: truncate(r.Remedy, 2000), Actual: truncate(r.ActualValue, 500),
					Expected: truncate(r.ExpectedResult, 500), Reason: truncate(r.Reason, 500)})
				switch strings.ToUpper(r.Status) {
				case "PASS":
					out.Pass++
				case "WARN":
					out.Warn++
				case "INFO":
					out.Info++
				case "FAIL":
					out.Fail++
					sev := "medium"
					if r.Scored {
						sev = "high"
					}
					out.Findings = append(out.Findings, findings.Finding{
						ControlID: bm + ":" + r.TestNumber, ResourceRef: ref, Severity: sev, Title: r.TestDesc,
						Details: map[string]any{"benchmark": bm, "section": t.Section, "node_type": c.NodeType,
							"scored": r.Scored, "remediation": truncate(r.Remedy, 1000)},
					})
				}
			}
		}
	}
	sortFindings(out.Findings)
	return out, nil
}

// ---------------------------------------------------------------- helpers

func sortFindings(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].ControlID != fs[j].ControlID {
			return fs[i].ControlID < fs[j].ControlID
		}
		return fs[i].ResourceRef < fs[j].ResourceRef
	})
}

func round1(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	r := math.Round(v*10) / 10
	return &r
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
