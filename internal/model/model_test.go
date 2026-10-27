package model

import (
	"os"
	"strings"
	"testing"
)

const example = "../../docs/examples/invoice-service.threatmodel.yaml"

func mustParse(t *testing.T, src string) (*Document, Diagnostics) {
	t.Helper()
	doc, diags := Parse([]byte(src))
	if doc != nil && doc.Model != nil {
		diags = append(diags, Validate(doc)...)
	}
	return doc, diags
}

func TestExampleIsValid(t *testing.T) {
	src, err := os.ReadFile(example)
	if err != nil {
		t.Fatal(err)
	}
	doc, diags := mustParse(t, string(src))
	if len(diags) > 0 {
		for _, d := range diags {
			t.Errorf("%s", d)
		}
	}
	m := doc.Model
	if got := len(m.Threats); got != 7 {
		t.Errorf("threats = %d, want 7", got)
	}
	th := m.Threat("read-others-invoices")
	if th == nil || th.Who != "any-user" || th.Gives == nil || th.Gives.Reads[0] != "invoices" {
		t.Errorf("unexpected threat: %+v", th)
	}
	if e := m.Mitigation("check-invoice-owner").Effect; e == nil || !e.Eliminates {
		t.Errorf("effect eliminates not decoded: %+v", e)
	}
	if e := m.Mitigation("random-invoice-ids").Effect; e == nil || e.Effort != "hard" {
		t.Errorf("effect map not decoded: %+v", e)
	}
	if ev := m.Mitigation("check-invoice-owner").Evidence[1]; ev.Type != "test" || !strings.HasSuffix(ev.Target, "#TestGetInvoice_OtherAccount") {
		t.Errorf("evidence not decoded: %+v", ev)
	}
	if doc.Line("threats[0].who") == 0 {
		t.Error("no position recorded for threats[0].who")
	}
	if !m.CrossesZones(*m.Flow("browser-to-edge")) || m.CrossesZones(*m.Flow("api-to-db")) {
		t.Error("CrossesZones wrong")
	}
}

const base = `version: 1
system:
  name: Test
zones:
  - id: net
    name: Internet
    trust: untrusted
components:
  - id: api
    name: API
    kind: service
    zone: net
`

func TestDiagnostics(t *testing.T) {
	cases := []struct {
		name, src, code, contains string
		line                      int
	}{
		{"syntax", "version: 1\nsystem: [a\n", "syntax", "isn't valid YAML", 0},
		{"empty", "", "empty", "file is empty", 0},
		{"anchor", base + "data:\n  - &d {id: x, name: X, sensitivity: public}\n  - *d\n", "anchor", "Anchors and aliases", 0},
		{"tag", base + "data:\n  - id: !!str x\n    name: X\n    sensitivity: public\n", "tag", "tags", 0},
		{"multi-doc", base + "---\nversion: 1\n", "multi-doc", "one YAML document", 0},
		{"unknown field with hint", base + "    expsure: internet\n", "unknown-field", "Did you mean `exposure`?", 13},
		{"enum with hint", base + "    exposure: internt\n", "enum", "Did you mean `internet`?", 13},
		{"number needs quotes", strings.Replace(base, "name: API", "name: 1.10", 1), "type", "Put it in quotes", 10},
		{"list given as string", base + "    tech: go\n", "type", "`tech: [go]`", 13},
		{"bad date", base + "    reviewed: last week\n", "date", "like 2026-10-27", 13},
		{"missing required", "version: 1\nsystem:\n  description: x\n", "missing-field", "missing `name`", 0},
		{"unknown ref with hint", base + "flows:\n  - id: f\n    from: api\n    to: apii\n", "unknown-ref", "Did you mean `api`?", 16},
		{"wrong section ref", base + "flows:\n  - id: f\n    from: api\n    to: net\n", "unknown-ref", "which is in zones", 16},
		{"duplicate id", base + "data:\n  - id: api\n    name: X\n    sensitivity: public\n", "duplicate-id", "more than once", 0},
		{"bad id", strings.Replace(base, "id: api", "id: My API", 1), "id-format", "lowercase", 0},
		{"accepted without block", base + "threats:\n  - id: t\n    title: Someone could x\n    status: accepted\n", "accepted", "who accepted it", 0},
		{"na without reason", base + "threats:\n  - id: t\n    title: Someone could x\n    status: not-applicable\n", "reason", "without a `reason`", 0},
		{"path escape", base + "    code: [\"../../etc/**\"]\n", "path-escape", "stay inside it", 0},
		{"abs path", base + "    code: [\"/etc/passwd\"]\n", "path-escape", "stay inside it", 0},
		{"bad effect", base + "mitigations:\n  - id: m\n    title: Fix\n    status: done\n    effect: {effort: hardd}\n", "enum", "Did you mean", 0},
		{"bad evidence", base + "mitigations:\n  - id: m\n    title: Fix\n    status: done\n    evidence:\n      - file: x.go\n", "enum", "evidence type", 0},
		{"newer version", strings.Replace(base, "version: 1", "version: 2", 1), "version", "Upgrade", 0},
		{"title style", base + "threats:\n  - id: t\n    title: Broken access control\n    status: open\n", "title-style", "who could do what", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := mustParse(t, tc.src)
			for _, d := range diags {
				if d.Code == tc.code && strings.Contains(d.String(), tc.contains) {
					if tc.line != 0 && d.Line != tc.line {
						t.Errorf("found %q on line %d, want line %d", d, d.Line, tc.line)
					}
					return
				}
			}
			t.Errorf("no %s diagnostic containing %q; got:", tc.code, tc.contains)
			for _, d := range diags {
				t.Errorf("  [%s] %s", d.Code, d)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	nested := "a: " + strings.Repeat("[", 50) + strings.Repeat("]", 50) + "\n"
	if _, diags := Parse([]byte(nested)); !hasCode(diags, "too-deep") {
		t.Errorf("deep nesting not rejected: %v", diags)
	}
	lim := DefaultLimits
	lim.MaxBytes = 10
	if _, diags := ParseWithLimits([]byte(base), lim); !hasCode(diags, "too-large") {
		t.Errorf("size limit not enforced: %v", diags)
	}
}

func hasCode(ds Diagnostics, code string) bool {
	for _, d := range ds {
		if d.Code == code {
			return true
		}
	}
	return false
}

func FuzzParse(f *testing.F) {
	src, _ := os.ReadFile(example)
	f.Add(string(src))
	f.Add(base)
	f.Add("a: &x [*x]\n")
	f.Add("- - - - [")
	f.Fuzz(func(t *testing.T, s string) {
		doc, _ := Parse([]byte(s))
		if doc != nil && doc.Model != nil {
			Validate(doc)
		}
	})
}

func TestPublishedSchemaIsCurrent(t *testing.T) {
	published, err := os.ReadFile("../../schema/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(published) != string(JSONSchema()) {
		t.Fatal("schema/v1.json is out of date; run `go run ./cmd/threat schema > schema/v1.json`")
	}
}

func TestControlsFields(t *testing.T) {
	src := base + `    identity: api-role
    encrypted_at_rest: true
    monitored: false
    patching: automated
identities:
  - id: api-role
    name: API task role
    kind: role
    can:
      - {do: read, on: api}
      - {do: admin, on: nowhere}
`
	doc, diags := mustParse(t, src)
	if doc == nil || doc.Model == nil {
		t.Fatalf("not parsed: %v", diags)
	}
	c := doc.Model.Component("api")
	if c.Identity != "api-role" || c.EncryptedAtRest == nil || !*c.EncryptedAtRest || c.Monitored == nil || *c.Monitored || c.Patching != "automated" {
		t.Errorf("component controls not decoded: %+v", c)
	}
	if !hasCode(diags, "unknown-ref") {
		t.Errorf("permission on unknown target not reported: %v", diags)
	}
	_, diags = mustParse(t, base+"    monitored: yes\n")
	if !hasCode(diags, "type") {
		t.Errorf("non-boolean accepted: %v", diags)
	}
}

func TestReviewAndSignoff(t *testing.T) {
	src := base + "    reviewed: {on: 2026-10-01, by: \"@alice\"}\n    considered: {disrupt: Stateless and autoscaled}\n    managed: true\nsignoff: {by: \"@appsec\", on: 2026-10-02}\n"
	doc, diags := mustParse(t, src)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	c := doc.Model.Component("api")
	if c.Reviewed != "2026-10-01" || c.ReviewedBy != "@alice" || c.Considered["disrupt"] == "" || c.Managed == nil || doc.Model.Signoff.By != "@appsec" {
		t.Errorf("not decoded: %+v %+v", c, doc.Model.Signoff)
	}
	_, diags = mustParse(t, base+"    reviewed: 2999-01-01\n")
	if !hasCode(diags, "future-date") {
		t.Errorf("future review date accepted: %v", diags)
	}
	_, diags = mustParse(t, base+"    considered: {sleep: x}\n")
	if !hasCode(diags, "enum") {
		t.Errorf("unknown kind in considered accepted: %v", diags)
	}
}
