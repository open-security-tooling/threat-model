package main

import (
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-security-tooling/threat-model/internal/check"
)

// TestWorkflow runs the CLI the way a developer would on a new repo.
func TestWorkflow(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = devNull
	t.Cleanup(func() { os.Stdout = stdout; devNull.Close() })

	steps := []struct {
		args []string
		want int
	}{
		{[]string{"validate"}, exitUsage}, // no model yet
		{[]string{"init", "--name", "Demo: shop", "--agents", "AGENTS.md"}, exitOK},
		{[]string{"init"}, exitUsage},                       // already exists
		{[]string{"init", "--agents", "CLAUDE.md"}, exitOK}, // existing model: just the snippet
		{[]string{"init", "--agents", "CLAUDE.md"}, exitOK}, // and only once
		{[]string{"validate"}, exitOK},
		{[]string{"lint"}, exitOK},
		{[]string{"lint", "--json"}, exitOK},
		{[]string{"fmt", "--check"}, exitOK},
		{[]string{"suggest", "--min-risk", "high", "--limit", "2"}, exitOK},
		{[]string{"suggest", "--min-risk", "severe"}, exitUsage},
		{[]string{"suggest", "--accept", "catalog:web/resource-exhaustin", "--target", "api"}, exitUsage},
		{[]string{"suggest", "--json"}, exitOK},
		{[]string{"suggest", "--accept", "catalog:web/resource-exhaustion", "--target", "api"}, exitOK},
		{[]string{"explain", "resource-exhaustion-api"}, exitOK},
		{[]string{"explain", "resource-exhaustion-api", "--json"}, exitOK},
		{[]string{"explain", "nope"}, exitUsage},
		{[]string{"show", "--json"}, exitOK},
		{[]string{"paths", "--json"}, exitOK},
		{[]string{"paths", "--blast", "api"}, exitOK},
		{[]string{"report", "--out", "report.md"}, exitOK},
		{[]string{"check"}, exitOK},
		{[]string{"schema"}, exitOK},
		{[]string{"no-such-command"}, exitUsage},
	}
	for _, s := range steps {
		if got := run(s.args); got != s.want {
			t.Fatalf("threat %s: exit %d, want %d", strings.Join(s.args, " "), got, s.want)
		}
	}

	src, _ := os.ReadFile(filepath.Join(dir, "threatmodel.yaml"))
	if !strings.Contains(string(src), `name: "Demo: shop"`) {
		t.Errorf("name not quoted safely:\n%s", src)
	}
	if !strings.Contains(string(src), "from: catalog:web/resource-exhaustion") {
		t.Errorf("accepted suggestion missing:\n%s", src)
	}
	if claude, _ := os.ReadFile(filepath.Join(dir, "CLAUDE.md")); strings.Count(string(claude), "## Threat model") != 1 {
		t.Errorf("CLAUDE.md:\n%s", claude)
	}
	agents, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if !strings.Contains(string(agents), "Never set a threat to `accepted` yourself") {
		t.Errorf("agent instructions missing:\n%s", agents)
	}
	if rep, _ := os.ReadFile(filepath.Join(dir, "report.md")); !strings.Contains(string(rep), "# Threat model: Demo: shop") {
		t.Errorf("report:\n%s", rep)
	}

	// Breaking the file makes validate and check fail with findings.
	if err := os.WriteFile("threatmodel.yaml", []byte(strings.Replace(string(src), "to: api", "to: apii", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"validate"}); got != exitFindings {
		t.Errorf("validate on broken file: exit %d", got)
	}
	if got := run([]string{"check"}); got != exitFindings {
		t.Errorf("check on broken file: exit %d", got)
	}
}

// capture runs the CLI and returns what it printed.
func capture(t *testing.T, args ...string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	code := run(args)
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	return string(out), code
}

const example = "../../docs/examples/invoice-service.threatmodel.yaml"

func TestExplainWording(t *testing.T) {
	out, code := capture(t, "explain", "pdf-fetches-internal-urls", "--file", example)
	for _, want := range []string{
		"How hard: moderate → hard (rare access or deep expertise) after the mitigations that are done",
		"the impact is critical: the renderer's role",
		"(done: critical → high; it becomes much harder)",
		"(planned: critical → low once done; makes this impossible)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output lacks %q:\n%s", want, out)
		}
	}
	if code != exitOK || strings.Contains(out, "once done: ") || strings.Contains(out, "(done; ") {
		t.Errorf("exit %d, old wording:\n%s", code, out)
	}

	out, _ = capture(t, "explain", "public-pdf-bucket", "--file", example)
	if !strings.HasPrefix(out, "N/A") || strings.Contains(out, "UNASSESSED") {
		t.Errorf("not-applicable threat:\n%s", out)
	}
}

func TestExplainMitigation(t *testing.T) {
	out, code := capture(t, "explain", "rate-limit-login", "--file", example)
	for _, want := range []string{
		"Rate-limit login attempts", "rate-limit-login · done", "What it changes: it becomes much harder.",
		"test: internal/auth/ratelimit_test.go#TestLoginLimiter", "credential-stuffing, open: critical → high",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mitigation card lacks %q:\n%s", want, out)
		}
	}
	if code != exitOK {
		t.Errorf("exit %d", code)
	}
	out, _ = capture(t, "explain", "offer-mfa", "--file", example, "--json")
	var card mitigationCard
	if err := json.Unmarshal([]byte(out), &card); err != nil || len(card.Threats) == 0 || card.Threats[0].Summary != "critical → low once done" {
		t.Errorf("json card = %+v (%v)", card, err)
	}
}

func TestShowLabels(t *testing.T) {
	out, _ := capture(t, "show", "--file", example)
	if strings.Contains(out, "CRITICAL            ") || !strings.Contains(out, "  CRITICAL  A logged-in") || !strings.Contains(out, "  HIGH      A logged-in") {
		t.Errorf("labels not padded to their width:\n%s", out)
	}
	if !strings.Contains(out, "Not applicable:\n  N/A") {
		t.Errorf("not-applicable threats:\n%s", out)
	}
}

func TestPadIgnoresStyling(t *testing.T) {
	styled := "\x1b[1;31mHIGH\x1b[0m"
	if visibleWidth(styled) != 4 || visibleWidth("→ ✓") != 3 {
		t.Errorf("widths: %d, %d", visibleWidth(styled), visibleWidth("→ ✓"))
	}
	if got := pad(styled, 8); got != styled+"    " {
		t.Errorf("pad = %q", got)
	}
	if plural(1, "flow") != "1 flow" || plural(2, "flow") != "2 flows" || plural(2, "summary") != "2 summaries" {
		t.Error("plural")
	}
}

func TestLintWriting(t *testing.T) {
	src := []byte(`version: 1
system:
  name: Demo
components:
  - id: api
    name: API
    kind: service
threats:
  - id: ssrf
    title: Anyone could exploit SSRF (CWE-918) in the API
    affects: [api]
    status: open
  - id: explained
    title: Anyone could make our server fetch internal URLs for them (SSRF) by passing a link
    kind: tamper
    affects: [api]
    status: open
    mitigations: [vague]
mitigations:
  - id: vague
    title: Implement proper access control
    status: planned
`)
	codes := map[string]int{}
	for _, d := range lintWriting(src) {
		codes[d.Code]++
		if d.Line == 0 {
			t.Errorf("%s has no line", d.Code)
		}
	}
	want := map[string]int{"title-refs": 1, "title-acronym": 1, "no-kind": 1, "vague-mitigation": 1}
	if !maps.Equal(codes, want) {
		t.Errorf("lint codes = %v, want %v", codes, want)
	}
}

func TestGitHints(t *testing.T) {
	r := check.Result{Findings: []check.Finding{
		{Code: "git", Message: "git diff failed: fatal: ambiguous argument 'origin/main': unknown revision or path not in the working tree."},
		{Code: "git", Message: "git diff failed: fatal: not a git repository"},
	}}
	addGitHints(&r, t.TempDir(), "origin/main")
	if h := r.Findings[0].Hint; !strings.Contains(h, "fetch-depth: 0") || !strings.Contains(h, "git fetch origin main") {
		t.Errorf("hint = %q", h)
	}
	if r.Findings[1].Hint != "" {
		t.Errorf("unrelated git error got a hint: %q", r.Findings[1].Hint)
	}
}

func TestEditDistance(t *testing.T) {
	if editDistance("resource-exhaustin", "resource-exhaustion") != 1 || editDistance("", "abc") != 3 {
		t.Error("editDistance")
	}
}

func TestPrintCheckChanges(t *testing.T) {
	r := check.Result{OK: true, Policy: ".threat.yaml", Checked: []string{"format ok"}, Changes: &check.ModelChanges{
		Summary:        "This change to the threat model: +1 threat, 1 risk lowered.",
		ThreatsAdded:   []check.ThreatRef{{ID: "new-one", Title: "New", Level: "high"}},
		RiskLowered:    []check.RiskChange{{ID: "ci-deps", From: "critical", To: "low", Reason: "its who, effort or impact answers changed"}},
		StatusChanged:  []check.StatusShift{{ID: "read-others-invoices", From: "open", To: "not-applicable"}},
		NeedsApproval:  []string{"Threat `ci-deps` went from critical to low."},
		Approvers:      []string{"@org/security"},
		ThreatsRemoved: []check.ThreatRef{},
	}}
	rd, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	printCheck("threatmodel.yaml", r)
	os.Stdout = stdout
	w.Close()
	b, _ := io.ReadAll(rd)
	out := string(b)
	for _, want := range []string{
		"Policy: .threat.yaml", "Model changes: This change to the threat model",
		"+ new-one: added (high)", "↓ ci-deps: critical → low (its who, effort or impact answers changed)",
		"- read-others-invoices: open → not-applicable", "Needs a person to agree (approvers: @org/security).",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check output lacks %q:\n%s", want, out)
		}
	}
}

func TestAcronymExplainedInParenthetical(t *testing.T) {
	for _, title := range []string{
		"Anyone could make our server fetch internal URLs for them (server-side request forgery, SSRF)",
		"Another website could make users' browsers change things (cross-site request forgery, CSRF)",
		"Anyone could make our server fetch internal URLs (SSRF)",
	} {
		acr := "SSRF"
		if strings.Contains(title, "CSRF") {
			acr = "CSRF"
		}
		if !explained(title, acr) {
			t.Errorf("%q: %s not counted as explained", title, acr)
		}
	}
	if explained("Anyone could exploit SSRF in the API", "SSRF") {
		t.Error("bare acronym counted as explained")
	}
}
