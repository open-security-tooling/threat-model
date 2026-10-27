// Package check runs everything CI cares about: validation, formatting,
// evidence that still exists, expired risk acceptances, and code that
// changed since the threats covering it were last reviewed.
package check

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/open-security-tooling/threat-model/internal/edit"
	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
	"github.com/open-security-tooling/threat-model/internal/policy"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

const (
	SevError   = model.SevError
	SevWarning = model.SevWarning
)

// Options configure a check run.
type Options struct {
	// Root is the repository root that code and evidence paths are relative to.
	Root string
	// ModelPath is the model file's path relative to Root, used to read the
	// base version with git.
	ModelPath string
	// Base is a git ref to compare against (e.g. origin/main). Empty means
	// "compare with each component's reviewed date using git history".
	Base string
	// Strict turns "needs review" warnings into errors.
	Strict bool
	// Today is the date used for expiry checks (defaults to now).
	Today time.Time
	// Git runs git commands; nil disables the checks that need git.
	Git *Git
	// ChangedFiles, if set, is used instead of asking git what changed
	// (for MCP callers that already know).
	ChangedFiles []string
	// Policy is the security team's policy. If nil, Run looks for
	// .threat.yaml in Root.
	Policy *policy.Policy
	// NoPolicy skips looking for a policy file.
	NoPolicy bool
}

// Finding is one result, written for a developer to act on.
type Finding struct {
	Severity string          `json:"severity"`
	Code     string          `json:"code"`
	ID       string          `json:"id,omitempty"`
	Line     int             `json:"line,omitempty"`
	Message  string          `json:"message"`
	Hint     string          `json:"hint,omitempty"`
	Threats  []RelatedThreat `json:"threats,omitempty"`
}

type RelatedThreat struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Level string `json:"level,omitempty"`
}

type Result struct {
	OK       bool      `json:"ok"`
	Errors   int       `json:"errors"`
	Warnings int       `json:"warnings"`
	Findings []Finding `json:"findings"`
	Checked  []string  `json:"checked"`
	// Changes is set when comparing with a base ref.
	Changes *ModelChanges `json:"changes,omitempty"`
	// Policy is the policy file that was applied, if any.
	Policy string `json:"policy,omitempty"`
}

// Run checks source.
func Run(source []byte, opts Options) Result {
	if opts.Today.IsZero() {
		opts.Today = time.Now()
	}
	r := &runner{opts: opts}
	switch {
	case opts.Policy != nil:
		r.policyName = "(given)"
	case opts.NoPolicy || opts.Root == "":
	case opts.Base != "" && opts.Git != nil:
		r.basePolicy()
	default:
		p, err := policy.Find(opts.Root)
		if err != nil {
			r.add(Finding{Severity: SevError, Code: "policy", Message: err.Error()})
		} else if p != nil {
			r.opts.Policy, r.policyName = p, policy.FileName
		}
	}
	r.run(source)
	return r.result()
}

type runner struct {
	opts         Options
	findings     []Finding
	checked      []string
	modelChanges *ModelChanges
	policyName   string
}

func (r *runner) add(f Finding) { r.findings = append(r.findings, f) }

// basePolicy applies the policy from the base ref, not the branch being
// checked: otherwise a pull request could relax .threat.yaml and pass its own
// check. Policy changes take effect once they're merged.
func (r *runner) basePolicy() {
	g, base := r.opts.Git, r.opts.Base
	src, err := g.Show(base, policy.FileName)
	if err != nil {
		// No policy on the base branch. A policy added by this change
		// applies once merged, so don't enforce it on itself.
		if p, _ := policy.Find(r.opts.Root); p != nil {
			r.add(Finding{Severity: SevWarning, Code: "policy-changed", Message: fmt.Sprintf("This change adds %s. It takes effect once merged; until then the base branch has no policy.", policy.FileName)})
		}
		return
	}
	p, err := policy.Parse(src)
	if err != nil {
		r.add(Finding{Severity: SevError, Code: "policy", Message: fmt.Sprintf("%s on %s: %v", policy.FileName, base, err)})
		return
	}
	if p.Extends != "" {
		// Extended files are read from the base ref too.
		if parent, err := g.Show(base, p.Extends); err == nil {
			if pp, err := policy.Parse(parent); err == nil {
				p = policy.Merge(pp, p)
			}
		}
	}
	r.opts.Policy, r.policyName = p, policy.FileName+" (from "+base+")"
	if cur, err := os.ReadFile(filepath.Join(r.opts.Root, policy.FileName)); err == nil && string(cur) != string(src) {
		r.add(Finding{Severity: SevWarning, Code: "policy-changed", Message: fmt.Sprintf("This change edits %s. The policy from %s applies until it's merged.", policy.FileName, base),
			Hint: "Policy changes should be reviewed by whoever owns it (CODEOWNERS)."})
	}
}

func (r *runner) result() Result {
	res := Result{Findings: r.findings, Checked: r.checked, Changes: r.modelChanges, Policy: r.policyName}
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return res.Findings[i].Severity == SevError && res.Findings[j].Severity != SevError
	})
	for _, f := range res.Findings {
		if f.Severity == SevError {
			res.Errors++
		} else {
			res.Warnings++
		}
	}
	res.OK = res.Errors == 0
	return res
}

func (r *runner) run(source []byte) {
	l := ops.Load(source)
	for _, d := range l.Diagnostics {
		r.add(Finding{Severity: d.Severity, Code: d.Code, Line: d.Line, Message: d.Message, Hint: d.Hint})
	}
	r.checked = append(r.checked, "schema and references")
	if l.Model == nil {
		return
	}
	m := l.Model
	if out, err := edit.Format(source); err == nil && !bytes.Equal(out, source) {
		r.add(Finding{Severity: SevError, Code: "format", Message: "The file isn't in canonical format.", Hint: "Run `threat fmt` and commit the result."})
	}
	r.checked = append(r.checked, "format")

	r.acceptances(m, l.Doc)
	r.evidence(m, l.Doc)
	r.coverage(m)
	r.rules(m, l.Doc)
	if r.opts.Git != nil || r.opts.ChangedFiles != nil {
		r.changes(m, l.Doc)
	}
}

func (r *runner) acceptances(m *model.Model, doc *model.Document) {
	today := r.opts.Today.Format(time.DateOnly)
	for i, t := range m.Threats {
		if t.Status != "accepted" || t.Accepted == nil {
			continue
		}
		if t.Accepted.Until < today {
			r.add(Finding{Severity: SevError, Code: "acceptance-expired", ID: t.ID, Line: doc.Line(fmt.Sprintf("threats[%d].accepted.until", i)),
				Message: fmt.Sprintf("Accepted risk `%s` expired on %s (accepted by %s: %q).", t.ID, t.Accepted.Until, t.Accepted.By, t.Accepted.Reason),
				Hint:    "Fix it, or have someone re-accept it with a new `until` date."})
		}
	}
	r.checked = append(r.checked, "risk acceptances")
}

func (r *runner) evidence(m *model.Model, doc *model.Document) {
	root := r.opts.Root
	if root == "" {
		return
	}
	for i, mt := range m.Mitigations {
		if mt.Status != "done" {
			continue
		}
		for j, ev := range mt.Evidence {
			if ev.Type == "link" {
				continue
			}
			file, symbol := ev.Path()
			line := doc.Line(fmt.Sprintf("mitigations[%d].evidence[%d].%s", i, j, ev.Type))
			content, err := readInside(root, file)
			if err != nil {
				r.add(Finding{Severity: SevError, Code: "evidence-missing", ID: mt.ID, Line: line,
					Message: fmt.Sprintf("Mitigation `%s` is done, but its evidence is gone: %v.", mt.ID, err),
					Hint:    "Update the evidence path, or set the mitigation back to in-progress."})
				continue
			}
			if symbol != "" && !bytes.Contains(content, []byte(symbol)) {
				r.add(Finding{Severity: SevError, Code: "evidence-missing", ID: mt.ID, Line: line,
					Message: fmt.Sprintf("Mitigation `%s` is done, but %s no longer contains %q.", mt.ID, file, symbol),
					Hint:    "Update the evidence, or set the mitigation back to in-progress."})
			}
		}
	}
	r.checked = append(r.checked, "evidence")
}

// readInside reads a file that must resolve to somewhere inside root, even
// through symlinks. Model files come from pull requests, so a path must
// never let a check read outside the repository. Only the file's presence
// and whether it contains a symbol are ever reported, never its content.
func readInside(root, rel string) ([]byte, error) {
	absRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("repository root %s not found", root)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s is outside the repository", rel)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(absRoot, clean))
	if err != nil {
		return nil, fmt.Errorf("%s doesn't exist", rel)
	}
	if inside, _ := filepath.Rel(absRoot, resolved); inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
		return nil, fmt.Errorf("%s points outside the repository", rel)
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		return nil, fmt.Errorf("%s isn't a file", rel)
	}
	if info.Size() > 10<<20 {
		return nil, fmt.Errorf("%s is too large to check", rel)
	}
	return os.ReadFile(resolved)
}

func (r *runner) coverage(m *model.Model) {
	for _, t := range m.Threats {
		if t.Status != "open" {
			continue
		}
		a := risk.Assess(m, &t)
		if risk.Rank(a.Level) >= risk.Rank("high") && len(t.Mitigations) == 0 {
			r.add(Finding{Severity: SevWarning, Code: "unmitigated", ID: t.ID,
				Message: fmt.Sprintf("%s threat `%s` is open with no mitigation planned.", title(a.Level), t.ID),
				Hint:    "Add a mitigation, even a planned one, so there's a plan."})
		}
	}
	for _, mt := range m.Mitigations {
		if mt.Status != "done" || hasTest(mt) {
			continue
		}
		for _, t := range m.Threats {
			if !slices.Contains(t.Mitigations, mt.ID) {
				continue
			}
			if a := risk.Assess(m, &t); risk.Rank(a.InherentLevel) >= risk.Rank("high") {
				r.add(Finding{Severity: SevWarning, Code: "no-test-evidence", ID: mt.ID,
					Message: fmt.Sprintf("Mitigation `%s` protects against a %s threat (`%s`) but has no test proving it works.", mt.ID, a.InherentLevel, t.ID),
					Hint:    "Add `- test: path/to/file_test.go#TestName` to its evidence."})
				break
			}
		}
	}
	r.checked = append(r.checked, "mitigation coverage")
}

func hasTest(mt model.Mitigation) bool {
	for _, ev := range mt.Evidence {
		if ev.Type == "test" {
			return true
		}
	}
	return false
}

func title(s string) string {
	if s == "" {
		return "Unassessed"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// changes reports components whose code changed since their threats were
// last reviewed.
func (r *runner) changes(m *model.Model, doc *model.Document) {
	sev := SevWarning
	if r.opts.Strict {
		sev = SevError
	}
	var base *model.Model
	changed := r.opts.ChangedFiles
	if r.opts.Base != "" && r.opts.Git != nil {
		files, err := r.opts.Git.ChangedSince(r.opts.Base)
		if err != nil {
			r.add(Finding{Severity: SevError, Code: "git", Message: err.Error()})
			return
		}
		changed = files
		if r.opts.ModelPath != "" {
			if src, err := r.opts.Git.Show(r.opts.Base, r.opts.ModelPath); err == nil {
				base = ops.Load(src).Model
			}
		}
		if base != nil {
			r.modelChanges = r.diffModels(base, m)
			r.checked = append(r.checked, "model changes")
		}
	}

	for i, c := range m.Components {
		if len(c.Code) == 0 {
			continue
		}
		var reason string
		switch {
		case changed != nil:
			var hits []string
			for _, f := range changed {
				if matchAny(c.Code, f) {
					hits = append(hits, f)
				}
			}
			if len(hits) == 0 {
				continue
			}
			// Bumping `reviewed` in the same change means someone looked.
			if base != nil {
				if bc := base.Component(c.ID); bc == nil || bc.Reviewed != c.Reviewed {
					continue
				}
			}
			reason = fmt.Sprintf("This change touches code for %q (%s)", c.Name, summarize(hits))
		case r.opts.Git != nil:
			last, err := r.opts.Git.LastChange(c.Code)
			if err != nil || last == "" || (c.Reviewed != "" && last <= c.Reviewed) {
				continue
			}
			reason = fmt.Sprintf("Code for %q changed on %s", c.Name, last)
		}
		when := "it has never been reviewed"
		if c.Reviewed != "" {
			when = "it was last reviewed " + c.Reviewed
		}
		related := relatedThreats(m, c.ID)
		r.add(Finding{Severity: sev, Code: "needs-review", ID: c.ID, Line: doc.Line(fmt.Sprintf("components[%d]", i)),
			Message: fmt.Sprintf("%s, and %s. %d threats relate to it.", reason, when, len(related)),
			Hint:    "Check those threats are still accurate, update them if not, then set `reviewed` to today's date.",
			Threats: related})
	}

	if base != nil {
		for _, f := range m.Flows {
			if base.Flow(f.ID) != nil || !m.CrossesZones(f) || len(relatedThreats(m, f.ID)) > 0 {
				continue
			}
			r.add(Finding{Severity: SevWarning, Code: "uncovered-flow", ID: f.ID,
				Message: fmt.Sprintf("New flow `%s` crosses zones and has no threats yet.", f.ID),
				Hint:    fmt.Sprintf("Run `threat suggest --flow %s`.", f.ID)})
		}
	}
	r.checked = append(r.checked, "code changes")
}

func summarize(files []string) string {
	if len(files) <= 3 {
		return strings.Join(files, ", ")
	}
	return fmt.Sprintf("%s and %d more files", strings.Join(files[:2], ", "), len(files)-2)
}

// relatedThreats are the threats affecting a component or flow, or any flow
// into or out of a component.
func relatedThreats(m *model.Model, id string) []RelatedThreat {
	targets := map[string]bool{id: true}
	for _, f := range m.Flows {
		if f.From == id || f.To == id {
			targets[f.ID] = true
		}
	}
	var out []RelatedThreat
	for i := range m.Threats {
		t := &m.Threats[i]
		if t.Status == "not-applicable" {
			continue
		}
		for _, a := range t.Affects {
			if targets[a] {
				out = append(out, RelatedThreat{ID: t.ID, Title: t.Title, Level: risk.Assess(m, t).Level})
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return risk.Rank(out[i].Level) > risk.Rank(out[j].Level) })
	return out
}
