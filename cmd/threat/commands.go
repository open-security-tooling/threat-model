package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/open-security-tooling/threat-model/internal/check"
	"github.com/open-security-tooling/threat-model/internal/export"
	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

func printDiagnostics(path string, diags []model.Diagnostic) {
	name := filepath.Base(path)
	for _, d := range diags {
		loc := name
		if d.Line > 0 {
			loc = fmt.Sprintf("%s:%d", name, d.Line)
		}
		fmt.Printf("%s %s %s", sev(d.Severity), dim(loc), d.Message)
		if d.Hint != "" {
			fmt.Printf(" %s", d.Hint)
		}
		fmt.Println()
	}
}

func cmdValidate(args []string) int { return validate("validate", args) }

// cmdLint is validate plus the writing-rule checks in lint.go.
func cmdLint(args []string) int { return validate("lint", args) }

func validate(name string, args []string) int {
	f := newFlags(name, name+" [--file threatmodel.yaml] [--json]")
	if !f.parse(args) {
		return exitUsage
	}
	path, src, ok := f.read()
	if !ok {
		return exitUsage
	}
	r := ops.Validate(src)
	if name == "lint" {
		extra := lintWriting(src)
		r.Diagnostics = model.Diagnostics(append(r.Diagnostics, extra...)).Sorted()
		r.Warnings += len(extra)
	}
	if f.json {
		printJSON(r)
	} else {
		printDiagnostics(path, r.Diagnostics)
		if r.OK {
			fmt.Printf("%s %s is valid", style("1;32", "✓"), filepath.Base(path))
			if r.Warnings > 0 {
				fmt.Printf(" (%s)", plural(r.Warnings, "warning"))
			}
			fmt.Println()
		}
	}
	if !r.OK {
		return exitFindings
	}
	return exitOK
}

func cmdFmt(args []string) int {
	f := newFlags("fmt", "fmt [--file threatmodel.yaml] [--check]")
	checkOnly := f.Bool("check", false, "don't write; exit 1 if the file isn't formatted")
	if !f.parse(args) {
		return exitUsage
	}
	path, src, ok := f.read()
	if !ok {
		return exitUsage
	}
	r, err := ops.Format(src)
	if err != nil {
		var oe *ops.Error
		if errors.As(err, &oe) {
			printDiagnostics(path, oe.Diagnostics)
		}
		fail(err)
		return exitUsage
	}
	switch {
	case f.json:
		printJSON(map[string]any{"file": path, "changed": r.Changed})
	case *checkOnly && r.Changed:
		fmt.Printf("%s %s isn't formatted. Run `threat fmt`.\n", sev("error"), filepath.Base(path))
	case r.Changed:
		fmt.Printf("Formatted %s\n", filepath.Base(path))
	}
	if r.Changed && *checkOnly {
		return exitFindings
	}
	if r.Changed {
		if err := writeAtomic(path, []byte(r.Source)); err != nil {
			fail(err)
			return exitUsage
		}
	}
	return exitOK
}

func load(f *flags) (string, ops.View, bool) {
	path, src, ok := f.read()
	if !ok {
		return "", ops.View{}, false
	}
	v, err := ops.Show(src)
	if err != nil {
		var oe *ops.Error
		if errors.As(err, &oe) {
			printDiagnostics(path, oe.Diagnostics)
		}
		fail(err)
		return "", ops.View{}, false
	}
	return path, v, true
}

func cmdShow(args []string) int {
	f := newFlags("show", "show [--file threatmodel.yaml] [--json]")
	if !f.parse(args) {
		return exitUsage
	}
	_, v, ok := load(f)
	if !ok {
		return exitUsage
	}
	if f.json {
		printJSON(v)
		return exitOK
	}
	m, s := v.Model, v.Summary
	crossing := fmt.Sprintf("%d cross zones", len(v.Crossings))
	if len(v.Crossings) == 1 {
		crossing = "1 crosses zones"
	}
	fmt.Printf("%s: %s, %s (%s), %s (%d open)\n\n", bold(m.System.Name),
		plural(s.Components, "component"), plural(s.Flows, "flow"), crossing, plural(s.Threats, "threat"), s.Open)
	type row struct{ label, text string }
	var rows, na []row
	for _, lvl := range []string{"critical", "high", "medium", "low"} {
		for _, t := range m.Threats {
			if a := v.Risks[t.ID]; a.Level == lvl && a.Assessed && !a.NotApplicable {
				rows = append(rows, row{level(lvl), t.Title + " " + dim("("+t.ID+", "+t.Status+")")})
			}
		}
	}
	for _, t := range m.Threats {
		switch a := v.Risks[t.ID]; {
		case a.NotApplicable:
			na = append(na, row{riskLabel(a), t.Title + " " + dim("("+t.ID+")")})
		case !a.Assessed:
			rows = append(rows, row{riskLabel(a), t.Title + " " + dim("("+t.ID+")")})
		}
	}
	w := 0
	for _, r := range append(rows, na...) {
		w = max(w, visibleWidth(r.label))
	}
	for _, r := range rows {
		fmt.Printf("  %s  %s\n", pad(r.label, w), r.text)
	}
	if len(na) > 0 {
		fmt.Println("\nNot applicable:")
		for _, r := range na {
			fmt.Printf("  %s  %s\n", pad(r.label, w), r.text)
		}
	}
	var open []string
	for _, mt := range m.Mitigations {
		if mt.Status != "done" {
			open = append(open, fmt.Sprintf("  [%s] %s %s", map[string]string{"planned": " ", "in-progress": "~"}[mt.Status], mt.Title, dim("("+mt.ID+")")))
		}
	}
	if len(open) > 0 {
		fmt.Printf("\nMitigations to do:\n%s\n", strings.Join(open, "\n"))
	}
	return exitOK
}

var whoText = map[string]string{
	"anyone": "anyone on the internet, no account needed", "any-user": "anyone with an account, including free sign-ups",
	"insider": "someone inside: employees, contractors, partners", "privileged": "admins or people with production access",
	"physical": "someone with the device in their hands",
}
var effortText = map[string]string{"trivial": "trivial (minutes, tools exist)", "moderate": "moderate (some skill or time)", "hard": "hard (rare access or deep expertise)"}

func cmdExplain(args []string) int {
	f := newFlags("explain", "explain <threat-or-mitigation-id> [--file threatmodel.yaml] [--json]")
	if !f.parse(args) {
		return exitUsage
	}
	if f.NArg() != 1 {
		f.Usage()
		return exitUsage
	}
	path, src, ok := f.read()
	if !ok {
		return exitUsage
	}
	if l := ops.Load(src); l.Model != nil && l.Model.Mitigation(f.Arg(0)) != nil {
		return explainMitigation(f, path, src, f.Arg(0))
	}
	r, err := ops.Explain(src, f.Arg(0))
	if err != nil {
		fail(err)
		return exitUsage
	}
	if f.json {
		printJSON(r)
		return exitOK
	}
	t, a := r.Threat, r.Risk
	fmt.Printf("%s  %s\n", riskLabel(a), bold(t.Title))
	meta := []string{t.ID, t.Status}
	if len(r.Affects) > 0 {
		meta = append(meta, "affects "+strings.Join(r.Affects, ", "))
	}
	fmt.Println("   " + dim(strings.Join(meta, " · ")))
	if len(t.Attack) > 0 {
		fmt.Println("\n" + bold("How it works"))
		for i, s := range t.Attack {
			fmt.Printf("  %d. %s\n", i+1, s)
		}
	}
	// The card shows the threat's own answers and, where mitigations that are
	// done change them, what they are now: the why-sentence uses the latter.
	in, res := a.Inherent, a.Residual
	if a.NotApplicable || a.Override || !a.Assessed {
		res = in
	}
	const after = " after the mitigations that are done"
	if t.Who != "" {
		who := whoText[in.Who]
		if res.Who != in.Who {
			who += " → " + whoText[res.Who] + after
		}
		fmt.Printf("\n%s %s\n", bold("Who could do it:"), who)
	}
	if t.Effort != "" {
		effort := effortText[in.Effort]
		if res.Effort != in.Effort {
			effort = in.Effort + " → " + effortText[res.Effort] + after
		}
		fmt.Printf("%s %s\n", bold("How hard:"), effort)
	}
	if t.Impact != "" {
		impact := in.Impact
		if t.ImpactNote != "" {
			impact += ". " + t.ImpactNote
		}
		if res.Impact != in.Impact {
			impact = in.Impact + " → " + res.Impact + after
			if t.ImpactNote != "" {
				impact += ". Without them: " + t.ImpactNote
			}
		}
		fmt.Printf("%s %s\n", bold("How bad:"), impact)
	}
	fmt.Printf("\n%s %s\n", bold("Why this risk:"), a.Why)
	if len(a.Changes) > 0 {
		fmt.Println("\n" + bold("Fixes"))
		for _, c := range a.Changes {
			fmt.Printf("  [%s] %s %s\n", statusMark[c.Status], c.Title, dim("("+changeText(c)+")"))
		}
	}
	if t.Accepted != nil {
		fmt.Printf("\n%s by %s until %s: %s\n", bold("Accepted"), t.Accepted.By, t.Accepted.Until, t.Accepted.Reason)
	}
	return exitOK
}

var statusMark = map[string]string{"done": "✓", "in-progress": "~", "planned": " "}

// changeText is "done: critical → high; it becomes much harder".
func changeText(c risk.Change) string {
	sum := c.Summary
	if sum == "" {
		sum = risk.ChangeSummary(c.From, c.To, c.Status == "done")
	}
	s := c.Status + ": " + sum
	if c.Effect != "" {
		s += "; " + c.Effect
	}
	return s
}

func cmdCheck(args []string) int {
	f := newFlags("check", "check [--file threatmodel.yaml] [--base origin/main] [--strict] [--no-policy] [--json]")
	base := f.String("base", "", "git ref to compare with; flags threats whose code changed since then")
	strict := f.Bool("strict", false, "treat \"needs review\" as an error")
	noPolicy := f.Bool("no-policy", false, "don't apply the policy file (.threat.yaml) at the repository root")
	format := f.String("format", "text", "output: text, json, github (workflow annotations), sarif (code scanning) or summary (Markdown for a pull request)")
	if !f.parse(args) {
		return exitUsage
	}
	path, src, ok := f.read()
	if !ok {
		return exitUsage
	}
	abs, _ := filepath.Abs(path)
	root := gitRoot(filepath.Dir(abs))
	opts := check.Options{Root: root, Base: *base, Strict: *strict, NoPolicy: *noPolicy, Today: time.Now()}
	if rel, err := filepath.Rel(root, abs); err == nil {
		opts.ModelPath = filepath.ToSlash(rel)
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		opts.Git = &check.Git{Dir: root}
	} else if *base != "" {
		fail(errors.New("--base needs the model to be inside a git repository"))
		return exitUsage
	}
	r := check.Run(src, opts)
	addGitHints(&r, root, *base)
	if f.json {
		*format = "json"
	}
	if *format != "text" {
		var view *ops.View
		if v, err := ops.Show(src); err == nil {
			view = &v
		}
		switch *format {
		case "json":
			printJSON(r)
		case "github":
			fmt.Print(export.GitHubAnnotations(r, opts.ModelPath))
		case "sarif":
			os.Stdout.Write(export.SARIF(r, view, opts.ModelPath))
		case "summary":
			fmt.Print(export.PRSummary(r, view))
		default:
			fail(fmt.Errorf("unknown --format %q; use text, json, github, sarif or summary", *format))
			return exitUsage
		}
		if !r.OK {
			return exitFindings
		}
		return exitOK
	}
	printCheck(filepath.Base(path), r)
	if !r.OK {
		return exitFindings
	}
	return exitOK
}

func printCheck(name string, r check.Result) {
	if r.Policy != "" {
		fmt.Printf("%s %s\n", dim("Policy:"), r.Policy)
	}
	if ch := r.Changes; ch != nil {
		fmt.Printf("%s %s\n", bold("Model changes:"), ch.Summary)
		for _, t := range ch.ThreatsAdded {
			fmt.Printf("  + %s: added (%s)\n", t.ID, levelWord(t.Level))
		}
		for _, t := range ch.ThreatsRemoved {
			fmt.Printf("  × %s: removed (%s)\n", t.ID, levelWord(t.Level))
		}
		for _, c := range ch.RiskRaised {
			fmt.Printf("  ↑ %s: %s → %s (%s)\n", c.ID, c.From, c.To, c.Reason)
		}
		for _, c := range ch.RiskLowered {
			fmt.Printf("  ↓ %s: %s → %s (%s)\n", c.ID, c.From, c.To, c.Reason)
		}
		for _, sc := range ch.StatusChanged {
			fmt.Printf("  - %s: %s → %s\n", sc.ID, sc.From, sc.To)
		}
		for _, id := range ch.MitigationsDone {
			fmt.Printf("  ✓ %s: done\n", id)
		}
		if len(ch.NeedsApproval) > 0 {
			msg := "Needs a person to agree"
			if len(ch.Approvers) > 0 {
				msg += " (approvers: " + strings.Join(ch.Approvers, ", ") + ")"
			}
			fmt.Printf("  %s %s\n", sev("warning"), msg+".")
		}
		fmt.Println()
	}
	for _, fd := range r.Findings {
		loc := name
		if fd.Line > 0 {
			loc = fmt.Sprintf("%s:%d", name, fd.Line)
		}
		fmt.Printf("%s %s %s\n", sev(fd.Severity), dim(loc), fd.Message)
		w := 0
		for _, t := range fd.Threats {
			w = max(w, visibleWidth(level(t.Level)))
		}
		for _, t := range fd.Threats {
			fmt.Printf("    %s  %s %s\n", pad(level(t.Level), w), t.Title, dim("("+t.ID+")"))
		}
		if fd.Hint != "" {
			fmt.Printf("    %s\n", dim(fd.Hint))
		}
	}
	if r.OK {
		fmt.Printf("%s %s", style("1;32", "✓"), strings.Join(r.Checked, ", "))
		if r.Warnings > 0 {
			fmt.Printf(" (%s)", plural(r.Warnings, "warning"))
		}
		fmt.Println()
	}
}

func levelWord(l string) string {
	if l == "" {
		return "not assessed"
	}
	return l
}

// missingRef matches git's complaints about a ref it doesn't have.
var missingRef = []string{"unknown revision", "bad revision", "no merge base", "not a valid object name", "invalid object name", "bad object", "ambiguous argument", "not a valid commit"}

// addGitHints explains the usual reason a --base comparison fails: the base
// ref was never fetched, as in a shallow CI checkout.
func addGitHints(r *check.Result, root, base string) {
	_, shallowErr := os.Stat(filepath.Join(root, ".git", "shallow"))
	for i, fd := range r.Findings {
		if fd.Code != "git" || fd.Hint != "" || base == "" {
			continue
		}
		msg := strings.ToLower(fd.Message)
		if shallowErr != nil && !slices.ContainsFunc(missingRef, func(s string) bool { return strings.Contains(msg, s) }) {
			continue
		}
		fetch := "git fetch"
		if remote, branch, ok := strings.Cut(base, "/"); ok && remote != "" && branch != "" {
			fetch = "git fetch " + remote + " " + branch
		}
		r.Findings[i].Hint = fmt.Sprintf("`%s` isn't available in this checkout, often because it's a shallow clone. Fetch it first (`%s`). In GitHub Actions, check out with `fetch-depth: 0`.", base, fetch)
	}
}

// gitHead returns the current commit SHA in dir, or "".
func gitHead(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gitRoot returns the repository root containing dir, or dir itself.
func gitRoot(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return dir
	}
	return strings.TrimSpace(string(out))
}

func cmdReport(args []string) int {
	f := newFlags("report", "report [--file threatmodel.yaml] [--out report.md] [--register csv|json]")
	out := f.String("out", "", "write to a file instead of stdout")
	register := f.String("register", "", "write a risk register (one row per threat) as csv or json instead of the Markdown report")
	if !f.parse(args) {
		return exitUsage
	}
	path, v, ok := load(f)
	if !ok {
		return exitUsage
	}
	md := ops.ReportMarkdown(v)
	if *register != "" {
		abs, _ := filepath.Abs(path)
		root := gitRoot(filepath.Dir(abs))
		meta := export.Meta{GeneratedAt: time.Now(), File: path, Commit: gitHead(root)}
		if rel, err := filepath.Rel(root, abs); err == nil {
			meta.File = filepath.ToSlash(rel)
		}
		rows, err := export.Register(v, meta)
		if err != nil {
			fail(err)
			return exitUsage
		}
		switch *register {
		case "csv":
			md = string(export.RegisterCSV(rows))
		case "json":
			md = string(export.RegisterJSON(rows))
		default:
			fail(fmt.Errorf("--register takes csv or json"))
			return exitUsage
		}
	}
	if *out == "" {
		fmt.Print(md)
		return exitOK
	}
	if err := writeAtomic(*out, []byte(md)); err != nil {
		fail(err)
		return exitUsage
	}
	return exitOK
}

func cmdSchema(args []string) int {
	os.Stdout.Write(model.JSONSchema())
	return exitOK
}

const agentsSnippet = `
## Threat model

This repo has a threat model in ` + "`threatmodel.yaml`" + ` (spec: https://github.com/open-security-tooling/threat-model).

- When you change code, run ` + "`threat check --base origin/main --json`" + `. If it reports
  components needing review, check whether their threats are still accurate and update
  the model in the same PR. Bump ` + "`reviewed`" + ` only after actually checking.
- When you add an internet-facing endpoint, a new data store, a new third-party
  integration or anything that crosses a zone, add it to the model and run ` + "`threat suggest`" + `.
- When you fix a threat, set the mitigation to ` + "`done`" + ` and add ` + "`evidence`" + ` (prefer a ` + "`test:`" + `).
- Write threats as "who could do what by how". No unexplained acronyms. See ` + "`threat explain`" + ` output for the style.
- Never set a threat to ` + "`accepted`" + ` yourself. Accepting risk is a human decision.
`

func cmdInit(args []string) int {
	f := newFlags("init", "init [--file threatmodel.yaml] [--name \"My service\"] [--agents AGENTS.md]")
	name := f.String("name", "", "what the model describes (default: the directory name)")
	agents := f.String("agents", "", "also add agent instructions to this file (e.g. AGENTS.md or CLAUDE.md); works on an existing model too")
	if !f.parse(args) {
		return exitUsage
	}
	path := f.file
	if path == "" {
		path = defaultFile
	}
	_, statErr := os.Stat(path)
	exists := statErr == nil
	if exists && *agents == "" {
		fail(fmt.Errorf("%s already exists. To add agent instructions to it, run `threat init --agents AGENTS.md`", path))
		return exitUsage
	}
	if !exists {
		if *name == "" {
			wd, _ := os.Getwd()
			*name = filepath.Base(wd)
		}
		r, err := ops.New(*name)
		if err != nil {
			fail(err)
			return exitUsage
		}
		if err := os.WriteFile(path, []byte(r.Source), 0o644); err != nil {
			fail(err)
			return exitUsage
		}
		fmt.Printf("Created %s.\n", path)
	} else {
		fmt.Printf("%s already exists; leaving it as it is.\n", path)
	}
	if *agents != "" {
		existing, _ := os.ReadFile(*agents)
		if strings.Contains(string(existing), "## Threat model") {
			fmt.Printf("%s already has a threat model section.\n", *agents)
		} else if err := appendFile(*agents, agentsSnippet); err != nil {
			fail(err)
			return exitUsage
		} else {
			fmt.Printf("Added agent instructions to %s.\n", *agents)
		}
	}
	if exists {
		return exitOK
	}
	fmt.Println("\nNext steps:")
	fmt.Printf("  1. Describe your system: open %s in your editor, or run `threat serve` to edit it visually.\n", path)
	fmt.Println("  2. Add `code:` paths to each component, so `threat check` notices when that code changes.")
	fmt.Println("  3. Run `threat suggest` to see the threats the library knows about for your components.")
	if *agents == "" {
		fmt.Println("  4. Run `threat init --agents AGENTS.md` so coding agents keep the model up to date.")
	}
	return exitOK
}

func appendFile(path, content string) error {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := fh.WriteString(content); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

func cmdStatus(args []string) int {
	f := newFlags("status", "status <threat-or-mitigation-id> <status> [--reason ...] [--by @you --until 2027-01-31 --reason ...]")
	reason := f.String("reason", "", "why (required for not-applicable and accepted)")
	by := f.String("by", "", "who is accepting the risk (accepted only)")
	until := f.String("until", "", "date the acceptance expires, YYYY-MM-DD (accepted only)")
	if !f.parse(args) {
		return exitUsage
	}
	if f.NArg() != 2 {
		f.Usage()
		return exitUsage
	}
	path, src, ok := f.read()
	if !ok {
		return exitUsage
	}
	req := ops.StatusRequest{ID: f.Arg(0), Status: f.Arg(1), Reason: *reason}
	if req.Status == "accepted" {
		req.Accepted = &model.Acceptance{By: *by, Reason: *reason, Until: *until}
		req.Reason = ""
	}
	// A person at the CLI may accept risk; agents go through `threat mcp`.
	r, err := ops.SetStatus(src, req, true)
	if err != nil {
		var oe *ops.Error
		if errors.As(err, &oe) {
			printDiagnostics(path, oe.Diagnostics)
		}
		fail(err)
		return exitUsage
	}
	if err := writeAtomic(path, []byte(r.Source)); err != nil {
		fail(err)
		return exitUsage
	}
	if f.json {
		printJSON(map[string]any{"ok": true, "changed": r.Changed})
	} else {
		fmt.Printf("%s is now %s.\n", req.ID, req.Status)
	}
	return exitOK
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	if strings.HasSuffix(word, "y") && !strings.HasSuffix(word, "ey") {
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	}
	return fmt.Sprintf("%d %ss", n, word)
}
