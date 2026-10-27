package check

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-security-tooling/threat-model/internal/edit"
)

// isolatedGit keeps tests away from the developer's git config: no commit
// signing (which may need a hardware key touch), no hooks, fixed identity.
var isolatedGit = []string{
	"GIT_CONFIG_GLOBAL=" + os.DevNull,
	"GIT_CONFIG_NOSYSTEM=1",
	"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
	"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.DevNull}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), isolatedGit...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exampleCanonical(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../../docs/examples/invoice-service.threatmodel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := edit.Format(src)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func codes(r Result) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range r.Findings {
		out[f.Code] = append(out[f.Code], f)
	}
	return out
}

func TestExampleFindings(t *testing.T) {
	dir := t.TempDir()
	src := exampleCanonical(t)
	write(t, dir, "threatmodel.yaml", src)
	// Evidence for the done mitigations; leave one symbol missing.
	write(t, dir, "infra/ecs/pdf.tf", `http_tokens = "required"`)
	write(t, dir, "internal/auth/ratelimit.go", "type LoginLimiter struct{}")
	write(t, dir, "internal/auth/ratelimit_test.go", "func TestLoginLimiter(t *testing.T) {}")
	write(t, dir, ".github/dependabot.yml", "version: 2\n")

	r := Run([]byte(src), Options{Root: dir, Today: time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)})
	c := codes(r)
	if len(c["acceptance-expired"]) != 1 || !strings.Contains(c["acceptance-expired"][0].Message, "2027-03-31") {
		t.Errorf("expired acceptance not reported: %+v", r.Findings)
	}
	if len(c["evidence-missing"]) != 1 || !strings.Contains(c["evidence-missing"][0].Message, `"cooldown"`) {
		t.Errorf("missing symbol not reported: %+v", c["evidence-missing"])
	}
	if len(c["no-test-evidence"]) == 0 {
		t.Errorf("done mitigation without test not reported")
	}
	if r.OK {
		t.Error("result OK despite errors")
	}

	write(t, dir, ".github/dependabot.yml", "version: 2\ncooldown:\n")
	r = Run([]byte(src), Options{Root: dir, Today: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)})
	if !r.OK {
		t.Errorf("expected OK, got %+v", r.Findings)
	}
}

func TestFormatFinding(t *testing.T) {
	src := strings.Replace(exampleCanonical(t), "effect: {effort: hard}", "effect: { effort: hard }", 1)
	if c := codes(Run([]byte(src), Options{})); len(c["format"]) != 1 {
		t.Error("non-canonical file not reported")
	}
}

func TestEvidenceCantEscapeRepo(t *testing.T) {
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	write(t, parent, "secret.txt", "BEGIN PRIVATE KEY")
	write(t, repo, "ok.go", "")
	if err := os.Symlink(filepath.Join(parent, "secret.txt"), filepath.Join(repo, "link.txt")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../secret.txt", "link.txt", "/etc/passwd"} {
		if _, err := readInside(repo, rel); err == nil {
			t.Errorf("%s was readable", rel)
		}
	}
	if _, err := readInside(repo, "ok.go"); err != nil {
		t.Errorf("ok.go: %v", err)
	}
}

func TestChangesAgainstBase(t *testing.T) {
	dir := t.TempDir()
	src := exampleCanonical(t)
	write(t, dir, "threatmodel.yaml", src)
	write(t, dir, "internal/invoice/handler.go", "package invoice\n")
	write(t, dir, "README.md", "hi\n")
	gitIn(t, dir, "init", "-q", "-b", "main")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	gitIn(t, dir, "checkout", "-q", "-b", "feature")

	g := &Git{Dir: dir, Env: isolatedGit}
	opts := Options{Root: dir, ModelPath: "threatmodel.yaml", Base: "main", Git: g, Today: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}

	// Unrelated change: nothing to review.
	write(t, dir, "README.md", "changed\n")
	if c := codes(Run([]byte(src), opts)); len(c["needs-review"]) != 0 {
		t.Fatalf("unrelated change flagged: %+v", c["needs-review"])
	}

	// Touch the invoice API's code (uncommitted counts too).
	write(t, dir, "internal/invoice/handler.go", "package invoice\n// changed\n")
	r := Run([]byte(src), opts)
	nr := codes(r)["needs-review"]
	if len(nr) != 1 || nr[0].ID != "api" || len(nr[0].Threats) == 0 || nr[0].Threats[0].ID != "read-others-invoices" {
		t.Fatalf("needs-review = %+v", nr)
	}
	if nr[0].Severity != SevWarning {
		t.Error("needs-review should be a warning without --strict")
	}
	opts.Strict = true
	if Run([]byte(src), opts).OK {
		t.Error("strict mode should fail")
	}

	// Bumping reviewed in the same change clears it.
	d, _ := edit.Parse([]byte(src))
	if _, err := d.Upsert("components", "api", map[string]any{"reviewed": "2026-11-01"}); err != nil {
		t.Fatal(err)
	}
	if c := codes(Run(d.Bytes(), opts)); len(c["needs-review"]) != 0 {
		t.Errorf("reviewed bump not honoured: %+v", c["needs-review"])
	}

	// A new zone-crossing flow with no threats.
	if _, err := d.Upsert("flows", "browser-to-stripe", map[string]any{"from": "browser", "to": "stripe"}); err != nil {
		t.Fatal(err)
	}
	if c := codes(Run(d.Bytes(), opts)); len(c["uncovered-flow"]) != 1 {
		t.Errorf("new uncovered flow not reported: %+v", c)
	}
}

func TestRefValidation(t *testing.T) {
	g := &Git{Dir: t.TempDir()}
	for _, ref := range []string{"--upload-pack=evil", "-x", "a..b", "main;rm", "$(x)", ""} {
		if _, err := g.ChangedSince(ref); err == nil || !strings.Contains(err.Error(), "isn't a git ref") {
			t.Errorf("ref %q accepted: %v", ref, err)
		}
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		glob, file string
		want       bool
	}{
		{"internal/invoice/**", "internal/invoice/handler.go", true},
		{"internal/invoice/**", "internal/invoice/sub/x.go", true},
		{"internal/invoice/**", "internal/invoices/x.go", false},
		{"cmd/*/main.go", "cmd/api/main.go", true},
		{"**/*.tf", "infra/ecs/pdf.tf", true},
		{".github/workflows/**", ".github/workflows/ci.yml", true},
		{"migrations/**", "README.md", false},
	}
	for _, c := range cases {
		if got := matchAny([]string{c.glob}, c.file); got != c.want {
			t.Errorf("%s ~ %s = %v", c.glob, c.file, got)
		}
	}
}
