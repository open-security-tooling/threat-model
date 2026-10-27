package check

import (
	"strings"
	"testing"
	"time"

	"github.com/open-security-tooling/threat-model/internal/edit"
	"github.com/open-security-tooling/threat-model/internal/ops"
	"github.com/open-security-tooling/threat-model/internal/policy"
)

// TestCatchesGaming replays the audit's scenario: five edits that quietly
// weaken the model must each show up when checking against the base branch.
func TestCatchesGaming(t *testing.T) {
	dir := t.TempDir()
	src := exampleCanonical(t)
	write(t, dir, "threatmodel.yaml", src)
	gitIn(t, dir, "init", "-q", "-b", "main")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	gitIn(t, dir, "checkout", "-q", "-b", "agent")

	cur := []byte(src)
	step := func(fn func(d *edit.Doc) error) {
		t.Helper()
		d, err := edit.Parse(cur)
		if err != nil {
			t.Fatal(err)
		}
		if err := fn(d); err != nil {
			t.Fatal(err)
		}
		cur = d.Bytes()
	}
	step(func(d *edit.Doc) error {
		_, err := d.Upsert("threats", "read-others-invoices", map[string]any{"status": "not-applicable", "reason": "we trust users"})
		return err
	})
	step(func(d *edit.Doc) error { return d.Delete("threats", "assistant-prompt-injection") })
	step(func(d *edit.Doc) error {
		_, err := d.Upsert("threats", "ci-dependency-steals-deploy-creds", map[string]any{"who": "privileged", "impact": "low"})
		return err
	})
	step(func(d *edit.Doc) error {
		_, err := d.Upsert("mitigations", "offer-mfa", map[string]any{"status": "done"})
		return err
	})
	step(func(d *edit.Doc) error {
		_, err := d.Upsert("threats", "credential-stuffing", map[string]any{"risk": map[string]any{"override": "low", "reason": "fine"}})
		return err
	})
	write(t, dir, "threatmodel.yaml", string(cur))

	opts := Options{Root: dir, ModelPath: "threatmodel.yaml", Base: "main", Git: &Git{Dir: dir, Env: isolatedGit}, Today: time.Now()}
	r := Run(cur, opts)
	c := codes(r)
	for _, code := range []string{"threat-dismissed", "threat-removed", "risk-lowered", "done-without-evidence", "risk-override"} {
		if len(c[code]) == 0 {
			t.Errorf("no %s finding; got %v", code, r.Findings)
		}
	}
	if r.Changes == nil || len(r.Changes.NeedsApproval) < 5 || !strings.Contains(r.Changes.Summary, "need a person") {
		t.Fatalf("changes = %+v", r.Changes)
	}
	// Without a policy or --strict they're warnings for a person to look at.
	for _, code := range []string{"threat-dismissed", "threat-removed", "risk-lowered", "done-without-evidence", "risk-override"} {
		for _, f := range c[code] {
			if f.Severity != SevWarning {
				t.Errorf("%s should be a warning without policy: %+v", code, f)
			}
		}
	}

	// A policy that makes risk-lowering an error, with approvers. (Given
	// directly: a policy file on this branch wouldn't apply to it.)
	pol, err := policy.Parse([]byte("version: 1\nchanges:\n  risk_lowering: error\n  approvers: [\"@acme/appsec\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	popts := opts
	popts.Policy = pol
	r = Run(cur, popts)
	if r.Policy == "" || len(codes(r)["risk-lowered"]) == 0 {
		t.Fatalf("policy not applied: %+v", r)
	}
	for _, f := range codes(r)["risk-lowered"] {
		if f.Severity != SevError || !strings.Contains(f.Hint, "@acme/appsec") {
			t.Errorf("finding not enforced: %+v", f)
		}
	}

	// Finishing a mitigation with evidence is a normal, unflagged change.
	clean := []byte(src)
	d, _ := edit.Parse(clean)
	if _, err := d.Upsert("mitigations", "offer-mfa", map[string]any{"status": "done", "evidence": []any{map[string]any{"test": "internal/auth/mfa_test.go#TestMFA"}}}); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "internal/auth/mfa_test.go", "func TestMFA(t *testing.T) {}")
	r = Run(d.Bytes(), opts)
	if n := len(r.Changes.NeedsApproval); n != 0 {
		t.Errorf("a genuine fix was flagged: %v", r.Changes.NeedsApproval)
	}
	if len(r.Changes.MitigationsDone) != 1 || len(r.Changes.RiskLowered) == 0 {
		t.Errorf("fix not summarised: %+v", r.Changes)
	}
}

func TestPolicyRules(t *testing.T) {
	dir := t.TempDir()
	src := exampleCanonical(t)
	write(t, dir, ".threat.yaml", `version: 1
fail_on: {open_risk: critical}
acceptance: {max_days: 30}
require: {evidence_for_done: true, due_for: high, signoff: true}
catalogs: {required: ["builtin:web"]}
`)
	r := Run([]byte(src), Options{Root: dir, Today: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)})
	c := codes(r)
	for _, code := range []string{"policy-open-risk", "policy-acceptance", "policy-due", "policy-signoff"} {
		if len(c[code]) == 0 {
			t.Errorf("no %s finding", code)
		}
	}
	if len(c["policy-catalog"]) != 0 {
		t.Error("builtin:web is used implicitly when catalogs is omitted")
	}
	if r.OK {
		t.Error("policy violations should fail")
	}

	write(t, dir, ".threat.yaml", "version: 1\nfail_on: {open_risk: severe}\n")
	if c := codes(Run([]byte(src), Options{Root: dir})); len(c["policy"]) != 1 {
		t.Errorf("bad policy not reported: %v", c)
	}
	write(t, dir, ".threat.yaml", "version: 1\nextends: ../outside.yaml\n")
	if c := codes(Run([]byte(src), Options{Root: dir})); len(c["policy"]) != 1 || !strings.Contains(c["policy"][0].Message, "inside the repository") {
		t.Errorf("extends outside repo not refused: %v", c)
	}
}

func TestDefaultsWithoutPolicy(t *testing.T) {
	src := exampleCanonical(t)
	d, _ := edit.Parse([]byte(src))
	if _, err := d.Upsert("mitigations", "random-invoice-ids", map[string]any{"due": "2026-01-01"}); err != nil {
		t.Fatal(err)
	}
	r := Run(d.Bytes(), Options{Today: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), NoPolicy: true})
	c := codes(r)
	if len(c["overdue"]) != 1 || c["overdue"][0].Severity != SevWarning {
		t.Errorf("overdue mitigation: %v", c["overdue"])
	}
	if len(c["uncovered-component"]) == 0 {
		t.Error("internet-facing component with no threats not reported (the load balancer)")
	}
	_ = ops.Load
}

func TestPolicyComesFromBase(t *testing.T) {
	dir := t.TempDir()
	src := exampleCanonical(t)
	write(t, dir, "threatmodel.yaml", src)
	write(t, dir, ".threat.yaml", "version: 1\nfail_on: {open_risk: critical}\n")
	gitIn(t, dir, "init", "-q", "-b", "main")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	gitIn(t, dir, "checkout", "-q", "-b", "relax")
	// The pull request tries to relax the policy that blocks it.
	write(t, dir, ".threat.yaml", "version: 1\n")
	opts := Options{Root: dir, ModelPath: "threatmodel.yaml", Base: "main", Git: &Git{Dir: dir, Env: isolatedGit}, Today: time.Now()}
	r := Run([]byte(src), opts)
	c := codes(r)
	if len(c["policy-open-risk"]) == 0 || len(c["policy-changed"]) != 1 || !strings.Contains(r.Policy, "from main") {
		t.Fatalf("base policy not enforced: policy=%q %v", r.Policy, c)
	}
}
