// Package policy reads .threat.yaml, the file a security team uses to turn
// threat check from advice into enforcement. Without a policy file the tool
// uses its developer-friendly defaults. See docs/policy.md.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/open-security-tooling/threat-model/internal/model"
)

// FileName is the policy file's name at the repository root.
const FileName = ".threat.yaml"

type Policy struct {
	Version int `json:"version"`
	// Extends is another policy file in the repo whose settings this one
	// builds on, e.g. a shared org policy vendored into the repo.
	Extends string `json:"extends,omitempty"`

	FailOn struct {
		// OpenRisk fails the check if an open threat's risk is at or above this level.
		OpenRisk string `json:"open_risk,omitempty"`
	} `json:"fail_on"`

	Changes struct {
		// RiskLowering is "warning" (default) or "error" for changes that
		// lower risk: removing threats, dismissing them, accepting them,
		// lowering their answers or overriding their risk.
		RiskLowering string `json:"risk_lowering,omitempty"`
		// Approvers must approve risk-lowering changes. The check lists
		// them; CODEOWNERS and branch protection enforce the approval.
		Approvers []string `json:"approvers,omitempty"`
	} `json:"changes"`

	Acceptance struct {
		// MaxDays limits how far ahead `until` may be.
		MaxDays int `json:"max_days,omitempty"`
	} `json:"acceptance"`

	Require struct {
		EvidenceForDone bool `json:"evidence_for_done,omitempty"`
		// TestEvidenceFor requires a test: evidence item on done mitigations
		// of threats at or above this level.
		TestEvidenceFor string `json:"test_evidence_for,omitempty"`
		// DueFor requires a due date on unfinished mitigations of open
		// threats at or above this level.
		DueFor  string `json:"due_for,omitempty"`
		Signoff bool   `json:"signoff,omitempty"`
	} `json:"require"`

	Review struct {
		// MaxAgeDays flags components with code whose review is older.
		MaxAgeDays int `json:"max_age_days,omitempty"`
	} `json:"review"`

	Catalogs struct {
		Required []string `json:"required,omitempty"`
	} `json:"catalogs"`
}

// Strict reports whether risk-lowering changes are errors.
func (p *Policy) Strict() bool { return p != nil && p.Changes.RiskLowering == "error" }

// Find loads root/.threat.yaml. It returns nil, nil if there's no policy.
func Find(root string) (*Policy, error) {
	path := filepath.Join(root, FileName)
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	return load(root, FileName, 0)
}

func load(root, rel string, depth int) (*Policy, error) {
	if depth > 3 {
		return nil, fmt.Errorf("%s: `extends` chains more than three files deep", FileName)
	}
	src, err := readInside(root, rel)
	if err != nil {
		return nil, err
	}
	p, err := Parse(src)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if p.Extends == "" {
		return p, nil
	}
	parent, err := load(root, p.Extends, depth+1)
	if err != nil {
		return nil, err
	}
	return Merge(parent, p), nil
}

var levels = []string{"low", "medium", "high", "critical"}

// Parse reads a policy file with the same strict YAML rules as model files.
func Parse(src []byte) (*Policy, error) {
	if diags := model.StrictYAML(src); diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags[0])
	}
	var generic any
	if err := yaml.Unmarshal(src, &generic); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(generic)
	if err != nil {
		return nil, err
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("isn't a valid policy: %v (see docs/policy.md for the fields)", err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("set `version: 1`")
	}
	for name, lvl := range map[string]string{"fail_on.open_risk": p.FailOn.OpenRisk, "require.test_evidence_for": p.Require.TestEvidenceFor, "require.due_for": p.Require.DueFor} {
		if lvl != "" && !slices.Contains(levels, lvl) {
			return nil, fmt.Errorf("`%s` is %q; use one of low, medium, high, critical", name, lvl)
		}
	}
	if r := p.Changes.RiskLowering; r != "" && r != "warning" && r != "error" {
		return nil, fmt.Errorf("`changes.risk_lowering` is %q; use warning or error", r)
	}
	if p.Acceptance.MaxDays < 0 || p.Review.MaxAgeDays < 0 {
		return nil, fmt.Errorf("day limits can't be negative")
	}
	return &p, nil
}

// Merge applies child's settings on top of parent's.
func Merge(parent, child *Policy) *Policy {
	out := *parent
	out.Extends = child.Extends
	if child.FailOn.OpenRisk != "" {
		out.FailOn = child.FailOn
	}
	if child.Changes.RiskLowering != "" {
		out.Changes.RiskLowering = child.Changes.RiskLowering
	}
	if len(child.Changes.Approvers) > 0 {
		out.Changes.Approvers = child.Changes.Approvers
	}
	if child.Acceptance.MaxDays > 0 {
		out.Acceptance = child.Acceptance
	}
	out.Require.EvidenceForDone = out.Require.EvidenceForDone || child.Require.EvidenceForDone
	out.Require.Signoff = out.Require.Signoff || child.Require.Signoff
	if child.Require.TestEvidenceFor != "" {
		out.Require.TestEvidenceFor = child.Require.TestEvidenceFor
	}
	if child.Require.DueFor != "" {
		out.Require.DueFor = child.Require.DueFor
	}
	if child.Review.MaxAgeDays > 0 {
		out.Review = child.Review
	}
	out.Catalogs.Required = append(append([]string{}, parent.Catalogs.Required...), child.Catalogs.Required...)
	return &out
}

// readInside reads a file that must stay inside root, even through symlinks.
func readInside(root, rel string) ([]byte, error) {
	absRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("policy file %s must be inside the repository", rel)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(absRoot, clean))
	if err != nil {
		return nil, fmt.Errorf("policy file %s doesn't exist", rel)
	}
	if r, err := filepath.Rel(absRoot, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("policy file %s points outside the repository", rel)
	}
	return os.ReadFile(real)
}
