package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-security-tooling/threat-model/internal/check"
	"github.com/open-security-tooling/threat-model/internal/edit"
	"github.com/open-security-tooling/threat-model/internal/ops"
)

const example = "../../docs/examples/invoice-service.threatmodel.yaml"

// view loads the example model, applying edits first: section → id → fields.
func view(t *testing.T, edits ...func(d *edit.Doc) error) ops.View {
	t.Helper()
	src, err := os.ReadFile(example)
	if err != nil {
		t.Fatal(err)
	}
	if len(edits) > 0 {
		d, err := edit.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range edits {
			if err := e(d); err != nil {
				t.Fatal(err)
			}
		}
		src = d.Bytes()
	}
	v, err := ops.Show(src)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func upsert(section, id string, fields map[string]any) func(d *edit.Doc) error {
	return func(d *edit.Doc) error { _, err := d.Upsert(section, id, fields); return err }
}

var meta = Meta{GeneratedAt: time.Date(2026, 10, 27, 12, 0, 0, 0, time.FixedZone("CET", 3600)), Commit: "0123abcd", File: "docs/examples/invoice-service.threatmodel.yaml"}

func rowByID(t *testing.T, rows []Row, id string) Row {
	t.Helper()
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no row %s", id)
	return Row{}
}

func TestRegister(t *testing.T) {
	v := view(t)
	rows, err := Register(v, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(v.Model.Threats) {
		t.Fatalf("got %d rows for %d threats", len(rows), len(v.Model.Threats))
	}
	for i, r := range rows {
		if r.ID != v.Model.Threats[i].ID {
			t.Errorf("row %d is %s, want model order (%s)", i, r.ID, v.Model.Threats[i].ID)
		}
		if r.ModelName != v.Model.System.Name || r.Commit != "0123abcd" || r.GeneratedAt != "2026-10-27T11:00:00Z" || r.File != meta.File {
			t.Errorf("row %s meta = %q %q %q %q", r.ID, r.ModelName, r.Commit, r.GeneratedAt, r.File)
		}
	}

	r := rowByID(t, rows, "read-others-invoices")
	a := v.Risks["read-others-invoices"]
	if r.Kind != "leak" || r.Status != "open" || r.InherentLevel != a.InherentLevel || r.ResidualLevel != a.Level || r.Why != a.Why || r.Why == "" {
		t.Errorf("risk fields wrong: %+v", r)
	}
	if len(r.Components) != 1 || r.Components[0].ID != "api" || r.Components[0].Name != v.Model.Component("api").Name {
		t.Errorf("components = %+v", r.Components)
	}
	if want := v.Model.Zone(v.Model.Component("api").Zone).Name; len(r.Zones) != 1 || r.Zones[0] != want {
		t.Errorf("zones = %v, want [%s]", r.Zones, want)
	}
	if len(r.Mitigations) != 2 || r.Mitigations[0].ID != "check-invoice-owner" || r.Mitigations[0].Owner != "@rahlenjakob" || r.Mitigations[0].Status != "in-progress" {
		t.Errorf("mitigations = %+v", r.Mitigations)
	}
	if !strings.Contains(r.RefsText, "cwe: CWE-") {
		t.Errorf("refs = %q", r.RefsText)
	}
	if r.Reviewed != v.Model.Component("api").Reviewed {
		t.Errorf("reviewed = %q", r.Reviewed)
	}

	acc := rowByID(t, rows, "support-edits-without-trace")
	if acc.Accepted == nil || acc.Accepted.By == "" || acc.Accepted.Until == "" || acc.Accepted.Reason == "" {
		t.Errorf("acceptance missing: %+v", acc.Accepted)
	}
	if na := rowByID(t, rows, "public-pdf-bucket"); na.Reason == "" || na.ResidualLevel != "" {
		t.Errorf("not-applicable row: %+v", na)
	}
	// A threat on a flow is listed against the component the flow goes to.
	pdf := rowByID(t, rows, "pdf-fetches-internal-urls")
	if len(pdf.Components) != 1 || pdf.Components[0].ID != "pdf-renderer" {
		t.Errorf("flow threat components = %+v", pdf.Components)
	}
	// require-imdsv2 is done with evidence.
	if !pdf.EvidencePresent {
		t.Error("evidence_present should be true for pdf-fetches-internal-urls")
	}

	if _, err := Register(ops.View{}, meta); err == nil {
		t.Error("Register with no model should fail")
	}
}

func TestOldestReview(t *testing.T) {
	cs := []RowComponent{{Reviewed: "2026-05-01", ReviewedBy: "@a"}, {Reviewed: "2026-03-01", ReviewedBy: "@b"}}
	if d, by := oldestReview(cs); d != "2026-03-01" || by != "@b" {
		t.Errorf("got %s %s", d, by)
	}
	if d, _ := oldestReview(append(cs, RowComponent{})); d != "" {
		t.Errorf("a never-reviewed component should win, got %s", d)
	}
}

func TestRegisterCSVNeutralizesFormulas(t *testing.T) {
	evil := []string{`=HYPERLINK("https://evil.example","x")`, "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\r=1", `=cmd|' /C calc'!A0`}
	v := view(t,
		upsert("threats", "read-others-invoices", map[string]any{"title": evil[0]}),
		upsert("mitigations", "check-invoice-owner", map[string]any{"title": evil[1]}),
		upsert("mitigations", "random-invoice-ids", map[string]any{"title": evil[6]}),
	)
	rows, err := Register(v, meta)
	if err != nil {
		t.Fatal(err)
	}
	// Model validation limits what some fields can hold, so also put every
	// dangerous prefix straight into every free-text field.
	for i, e := range evil {
		rows = append(rows, Row{ID: e, Title: e, Why: e, Reason: e, Kind: e, Status: e,
			Components: []RowComponent{{Name: e}}, Zones: []string{e},
			Mitigations: []RowMitigation{{ID: e, Title: e, Status: e, Owner: e, Due: e}},
			Accepted:    &RowAcceptance{By: e, Until: e, Reason: e},
			RefsText:    e, Reviewed: e, ReviewedBy: e, ModelName: e, File: e, Commit: e, GeneratedAt: fmt.Sprint(i, e)})
	}
	out := RegisterCSV(rows)
	recs, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("CSV doesn't parse: %v", err)
	}
	if len(recs) != len(rows)+1 || strings.Join(recs[0], ",") != strings.Join(RegisterColumns, ",") {
		t.Fatalf("got %d records, header %v", len(recs), recs[0])
	}
	for i, rec := range recs {
		if len(rec) != len(RegisterColumns) {
			t.Fatalf("record %d has %d cells", i, len(rec))
		}
		for j, cell := range rec {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("record %d column %s starts with %q: %q", i, RegisterColumns[j], cell[0], cell)
			}
		}
	}
	if !bytes.Contains(out, []byte(`'=HYPERLINK(""https://evil.example"",""x"")`)) {
		t.Error("formula title wasn't kept as text with a leading apostrophe")
	}
	if !bytes.HasSuffix(out, []byte("\r\n")) {
		t.Error("CSV should use CRLF line endings")
	}
	for in, want := range map[string]string{"": "", "safe": "safe", "a=b": "a=b", "=x": "'=x", "-": "'-", "\t": "'\t"} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegisterJSON(t *testing.T) {
	rows, err := Register(view(t), meta)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int              `json:"version"`
		Threats []map[string]any `json:"threats"`
	}
	if err := json.Unmarshal(RegisterJSON(rows), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Threats) != len(rows) || doc.Threats[0]["id"] != rows[0].ID {
		t.Errorf("unexpected JSON: version %d, %d threats", doc.Version, len(doc.Threats))
	}
	if !bytes.Equal(RegisterJSON(rows), RegisterJSON(rows)) {
		t.Error("JSON isn't deterministic")
	}
	if !bytes.Contains(RegisterJSON(nil), []byte(`"threats": []`)) {
		t.Error("no rows should give an empty list, not null")
	}
}

// sampleResult has one of each kind of finding, with untrusted text in it.
func sampleResult(msg string) check.Result {
	r := check.Result{
		Findings: []check.Finding{
			{Severity: check.SevError, Code: "acceptance-expired", ID: "support-edits-without-trace", Line: 334, Message: msg, Hint: "Fix it, or re-accept it."},
			{Severity: check.SevWarning, Code: "needs-review", ID: "api", Line: 81, Message: "This change touches code for \"API\".", Hint: "Check those threats."},
			{Severity: check.SevError, Code: "policy-due", ID: "offer-mfa", Message: "Mitigation `offer-mfa` has no due date."},
			{Severity: check.SevError, Code: "format", Message: "The file isn't in canonical format."},
		},
		Changes: &check.ModelChanges{
			Summary:       "This change to the threat model: +1 threat, 1 risk lowered. 1 of these lower risk and need a person to agree.",
			ThreatsAdded:  []check.ThreatRef{{ID: "credential-stuffing", Title: msg, Level: "high"}},
			RiskLowered:   []check.RiskChange{{ID: "read-others-invoices", Title: "Read invoices", From: "high", To: "low", Reason: "its who, effort or impact answers changed"}},
			NeedsApproval: []string{"Threat `read-others-invoices` went from high to low because " + msg},
			Approvers:     []string{"@security-team", "@org/appsec"},
		},
		Policy: ".threat.yaml",
	}
	r.Errors, r.Warnings = 3, 1
	return r
}

const evilText = "Someone could <img src=x onerror=alert(1)> click [here](https://evil.example) @everyone\n::set-output name=x::y %0A`code` | cell"

func TestSARIF(t *testing.T) {
	v := view(t)
	out := SARIF(sampleResult(evilText), &v, "docs/examples/invoice-service.threatmodel.yaml")
	if !bytes.Equal(out, SARIF(sampleResult(evilText), &v, "docs/examples/invoice-service.threatmodel.yaml")) {
		t.Fatal("SARIF isn't deterministic")
	}

	var log struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string            `json:"id"`
						ShortDescription map[string]string `json:"shortDescription"`
						Help             map[string]string `json:"help"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string            `json:"ruleId"`
				RuleIndex *int              `json:"ruleIndex"`
				Level     string            `json:"level"`
				Message   map[string]string `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") || len(log.Runs) != 1 {
		t.Fatalf("version %q schema %q runs %d", log.Version, log.Schema, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "threat" || len(run.Tool.Driver.Rules) == 0 {
		t.Fatal("tool.driver.name and rules are required")
	}
	rules := map[string]int{}
	for i, r := range run.Tool.Driver.Rules {
		if r.ID == "" || r.ShortDescription["text"] == "" || r.Help["text"] == "" {
			t.Errorf("rule %d is incomplete: %+v", i, r)
		}
		if _, dup := rules[r.ID]; dup {
			t.Errorf("duplicate rule %s", r.ID)
		}
		rules[r.ID] = i
	}

	open := 0
	for _, th := range v.Model.Threats {
		if th.Status == "open" {
			open++
		}
	}
	if want := 4 + open; len(run.Results) != want {
		t.Fatalf("got %d results, want %d (4 findings + %d open threats)", len(run.Results), want, open)
	}
	levels := map[string]string{}
	for _, res := range run.Results {
		idx, ok := rules[res.RuleID]
		if !ok || res.RuleIndex == nil || *res.RuleIndex != idx {
			t.Errorf("result %s has no matching rule (index %v)", res.RuleID, res.RuleIndex)
		}
		if res.Level != "error" && res.Level != "warning" && res.Level != "note" {
			t.Errorf("result %s level %q", res.RuleID, res.Level)
		}
		if res.Message["text"] == "" || len(res.Locations) != 1 {
			t.Errorf("result %s needs a message and one location", res.RuleID)
			continue
		}
		pl := res.Locations[0].PhysicalLocation
		if pl.ArtifactLocation.URI != "docs/examples/invoice-service.threatmodel.yaml" || pl.Region.StartLine < 1 {
			t.Errorf("result %s location %+v", res.RuleID, pl)
		}
		if strings.Contains(res.Message["text"], "[here](") {
			t.Errorf("result %s message has a live link: %s", res.RuleID, res.Message["text"])
		}
		if strings.HasPrefix(res.RuleID, threatRulePrefix) {
			levels[res.Properties["id"]] = res.Level
			if want := v.Lines[res.Properties["id"]]; pl.Region.StartLine != want {
				t.Errorf("threat %s at line %d, want %d", res.Properties["id"], pl.Region.StartLine, want)
			}
		}
	}
	for _, th := range v.Model.Threats {
		if th.Status != "open" {
			if _, ok := levels[th.ID]; ok {
				t.Errorf("%s isn't open but was reported", th.ID)
			}
			continue
		}
		if got, want := levels[th.ID], threatLevel(v.Risks[th.ID].Level); got != want {
			t.Errorf("%s (%s) level %s, want %s", th.ID, v.Risks[th.ID].Level, got, want)
		}
	}
	if _, ok := rules["open-threat/leak"]; !ok {
		t.Error("expected a rule per threat kind, e.g. open-threat/leak")
	}
	// A finding with no line falls back to the item's line in the model.
	for _, res := range run.Results {
		if res.RuleID == "policy-due" && res.Locations[0].PhysicalLocation.Region.StartLine != v.Lines["offer-mfa"] {
			t.Errorf("policy-due should point at offer-mfa's line %d", v.Lines["offer-mfa"])
		}
	}

	for level, want := range map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "": "warning"} {
		if got := threatLevel(level); got != want {
			t.Errorf("threatLevel(%q) = %s, want %s", level, got, want)
		}
	}
	// Without a view, only findings are reported.
	var bare struct {
		Runs []struct {
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(SARIF(check.Result{}, nil, "threatmodel.yaml"), &bare); err != nil || bare.Runs[0].Results == nil || len(bare.Runs[0].Results) != 0 {
		t.Errorf("empty result should give an empty results list: %v", err)
	}
}

func TestGitHubAnnotationsCantInjectCommands(t *testing.T) {
	r := sampleResult(evilText)
	r.Findings[1].ID = "a,b:c"
	out := GitHubAnnotations(r, "models/a,b:c.yaml")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(r.Findings) {
		t.Fatalf("got %d lines for %d findings:\n%s", len(lines), len(r.Findings), out)
	}
	for i, l := range lines {
		want := "::warning "
		if r.Findings[i].Severity == check.SevError {
			want = "::error "
		}
		if !strings.HasPrefix(l, want) {
			t.Errorf("line %d = %q, want prefix %q", i, l, want)
		}
		if strings.ContainsAny(l, "\r") {
			t.Errorf("line %d has a raw CR", i)
		}
		// The properties end at the first "::"; nothing in them may be raw.
		props := strings.TrimPrefix(l, want)
		props = props[:strings.Index(props, "::")]
		if strings.Count(props, ",") != strings.Count(props, "=")-1 {
			t.Errorf("line %d properties were split by model text: %q", i, props)
		}
	}
	if strings.Contains(out, "\n::set-output") {
		t.Error("model text started a new workflow command")
	}
	if !strings.Contains(lines[0], "%0A::set-output name=x::y %250A") {
		t.Errorf("message not escaped as expected: %s", lines[0])
	}
	if !strings.Contains(lines[0], "file=models/a%2Cb%3Ac.yaml,line=334,title=threat check%3A acceptance-expired (support-edits-without-trace)::") {
		t.Errorf("properties not escaped as expected: %s", lines[0])
	}
	if !strings.Contains(lines[1], "title=threat check%3A needs-review (a%2Cb%3Ac)::") {
		t.Errorf("ID in title not escaped: %s", lines[1])
	}
	if strings.Contains(lines[3], "line=") {
		t.Error("a finding with no line shouldn't claim one")
	}
	if GitHubAnnotations(check.Result{}, "x.yaml") != "" {
		t.Error("no findings should print nothing")
	}
}

func TestPRSummary(t *testing.T) {
	v := view(t, upsert("threats", "read-others-invoices", map[string]any{"title": evilText}))
	md := PRSummary(sampleResult(evilText), &v)

	if !strings.HasPrefix(md, SummaryMarker+"\n") {
		t.Error("summary must start with the marker")
	}
	for _, bad := range []string{"<img", "[here]", "](https://evil.example)", "| cell", "`code`"} {
		if strings.Count(md, bad) != strings.Count(md, `\`+bad) {
			t.Errorf("summary has unescaped %q", bad)
		}
	}
	if strings.Contains(md, "@everyone") || !strings.Contains(md, "@​everyone") {
		t.Error("mentions in model text must not ping anyone")
	}
	if strings.Contains(md, "\n::set-output") {
		t.Error("newlines in model text must not survive")
	}
	for _, want := range []string{
		"❌ **3 errors, 1 warning.** Policy: `.threat.yaml`.",
		sampleResult("").Changes.Summary,
		"### What changed",
		"Added `credential-stuffing`",
		"Risk lowered: `read-others-invoices` Read invoices, high → low",
		"### Needs a person to agree",
		"One of `@security-team` or `@org/appsec` should approve",
		"### Errors", "### Warnings",
		"### Top open risks",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("summary is missing %q\n%s", want, md)
		}
	}
	if strings.Index(md, "### Errors") > strings.Index(md, "### Warnings") {
		t.Error("errors should come before warnings")
	}
	if strings.Contains(md, "<details>") {
		t.Error("short lists shouldn't be collapsed")
	}

	// Long lists fold into <details>, and very long ones are capped.
	r := check.Result{Errors: 120}
	for i := range 120 {
		r.Findings = append(r.Findings, check.Finding{Severity: check.SevError, Code: "overdue", Message: fmt.Sprintf("finding %d", i)})
	}
	md = PRSummary(r, nil)
	if !strings.Contains(md, "<details><summary>115 more errors</summary>") || !strings.Contains(md, "</details>") {
		t.Errorf("long list not collapsed:\n%s", md)
	}
	if strings.Contains(md, "finding 50") || !strings.Contains(md, "…and 70 more") {
		t.Error("list should be capped at 50 items")
	}
	if strings.Contains(md, "Top open risks") {
		t.Error("no view means no open risks section")
	}
	if md := PRSummary(check.Result{OK: true}, nil); !strings.Contains(md, "✅ **No problems found.**") {
		t.Errorf("clean result: %s", md)
	}
}
