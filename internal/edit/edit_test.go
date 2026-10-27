package edit

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/open-security-tooling/threat-model/internal/model"
)

func canonicalExample(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile("../../docs/examples/invoice-service.threatmodel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Format(src)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// lineDiff returns lines only in a and lines only in b (as multisets).
func lineDiff(a, b string) (removed, added []string) {
	count := map[string]int{}
	for _, l := range strings.Split(a, "\n") {
		count[l]++
	}
	for _, l := range strings.Split(b, "\n") {
		if count[l] > 0 {
			count[l]--
		} else {
			added = append(added, l)
		}
	}
	for l, n := range count {
		for ; n > 0; n-- {
			removed = append(removed, l)
		}
	}
	return removed, added
}

func valid(t *testing.T, src []byte) *model.Model {
	t.Helper()
	doc, diags := model.Parse(src)
	if doc != nil && doc.Model != nil {
		diags = append(diags, model.Validate(doc)...)
	}
	if diags.HasErrors() {
		t.Fatalf("edited file is invalid: %v\n%s", diags, src)
	}
	return doc.Model
}

func edit(t *testing.T, src []byte, fn func(d *Doc) error) []byte {
	t.Helper()
	d, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := fn(d); err != nil {
		t.Fatal(err)
	}
	out := d.Bytes()
	again, err := Format(out)
	if err != nil {
		t.Fatalf("edited output doesn't parse: %v\n%s", err, out)
	}
	if string(again) != string(out) {
		t.Fatalf("edited output isn't canonical:\n%s", out)
	}
	return out
}

func TestFormatIsIdempotent(t *testing.T) {
	once := canonicalExample(t)
	twice, err := Format(once)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatal("Format is not idempotent")
	}
	valid(t, once)
}

func TestSetScalarKeepsEverythingElse(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error {
		_, err := d.Upsert("threats", "read-others-invoices", map[string]any{"status": "mitigated"})
		return err
	})
	rm, add := lineDiff(string(src), string(out))
	if len(rm) != 1 || len(add) != 1 || strings.TrimSpace(add[0]) != "status: mitigated" {
		t.Fatalf("want one changed line, got -%q +%q", rm, add)
	}
	if valid(t, out).Threat("read-others-invoices").Status != "mitigated" {
		t.Fatal("status not changed")
	}
}

func TestInlineReplaceKeepsLineComment(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error {
		_, err := d.Upsert("components", "pdf-renderer", map[string]any{"stores": []any{"pdf-task-credentials", "invoices"}})
		return err
	})
	if !strings.Contains(string(out), "stores: [pdf-task-credentials, invoices] # via the ECS task role") {
		t.Fatalf("line comment lost:\n%s", out)
	}
}

func TestAppendItemGetsBlankLine(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error {
		created, err := d.Upsert("threats", "new-threat", map[string]any{
			"title":   "Anyone could flood the signup form with fake accounts",
			"kind":    "abuse",
			"affects": []any{"api"},
			"attack":  []any{"Write a script that signs up in a loop.", "Use the accounts to send spam invoices."},
			"who":     "anyone",
			"effort":  "trivial",
			"impact":  "medium",
			"status":  "open",
		})
		if !created {
			t.Error("not reported as created")
		}
		return err
	})
	rm, add := lineDiff(string(src), string(out))
	if len(rm) != 0 {
		t.Fatalf("lines removed: %q", rm)
	}
	if len(add) != 12 || !slices.Contains(add, "") {
		t.Fatalf("want 11 new lines and a blank line, got %d: %q", len(add), add)
	}
	m := valid(t, out)
	th := m.Threat("new-threat")
	if th == nil || len(th.Attack) != 2 || th.Kind != "abuse" {
		t.Fatalf("new threat not read back: %+v", th)
	}
	// It lands at the end of threats, before mitigations.
	if strings.Index(string(out), "id: new-threat") > strings.Index(string(out), "\nmitigations:") {
		t.Fatal("new threat placed after mitigations")
	}
	if !strings.Contains(string(out), "  - id: new-threat\n    title: Anyone could flood") {
		t.Fatalf("unexpected layout:\n%s", out)
	}
}

func TestAddFieldInCanonicalPosition(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error {
		_, err := d.Upsert("components", "browser", map[string]any{"exposure": "internet"})
		return err
	})
	if !strings.Contains(string(out), "    zone: internet\n    exposure: internet\n") {
		t.Fatalf("exposure not inserted after zone:\n%s", out)
	}
	if rm, add := lineDiff(string(src), string(out)); len(rm) != 0 || len(add) != 1 {
		t.Fatalf("want one added line, got -%q +%q", rm, add)
	}
}

func TestRemoveField(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error {
		_, err := d.Upsert("components", "pdf-renderer", map[string]any{"notes": nil})
		return err
	})
	rm, add := lineDiff(string(src), string(out))
	if len(rm) != 1 || len(add) != 0 || !strings.Contains(rm[0], "notes:") {
		t.Fatalf("want notes line removed, got -%q +%q", rm, add)
	}
}

func TestReplaceBlockList(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error {
		_, err := d.Upsert("threats", "credential-stuffing", map[string]any{"attack": []any{"Try leaked passwords.", "Log in."}})
		return err
	})
	rm, add := lineDiff(string(src), string(out))
	if len(rm) != 3 || len(add) != 2 {
		t.Fatalf("want 3 steps replaced by 2, got -%q +%q", rm, add)
	}
	if got := valid(t, out).Threat("credential-stuffing").Attack; len(got) != 2 {
		t.Fatalf("attack = %q", got)
	}
}

func TestDeleteItem(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error { return d.Delete("threats", "credential-stuffing") })
	rm, add := lineDiff(string(src), string(out))
	if len(add) != 0 {
		t.Fatalf("lines added: %q", add)
	}
	if valid(t, out).Threat("credential-stuffing") != nil {
		t.Fatal("not deleted")
	}
	// The item had 22 lines plus its separating blank line.
	if len(rm) < 15 || len(rm) > 24 {
		t.Fatalf("unexpected number of removed lines: %d", len(rm))
	}
	if strings.Contains(string(out), "\n\n\n") {
		t.Fatal("left a double blank line")
	}
}

func TestCreateSectionInCanonicalPlace(t *testing.T) {
	src := []byte("version: 1\nsystem:\n  name: Tiny\n\ncomponents:\n  - id: api\n    name: API\n    kind: service\n")
	out := edit(t, src, func(d *Doc) error {
		_, err := d.Upsert("zones", "net", map[string]any{"name": "Internet", "trust": "untrusted"})
		return err
	})
	s := string(out)
	if !(strings.Index(s, "zones:") < strings.Index(s, "components:") && strings.Index(s, "system:") < strings.Index(s, "zones:")) {
		t.Fatalf("zones not placed between system and components:\n%s", s)
	}
	valid(t, out)
}

func TestLayout(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error { return d.SetLayout("api", map[string]float64{"x": 400, "y": 200}) })
	if !strings.Contains(string(out), "  api: {x: 400, y: 200}\n") {
		t.Fatalf("layout not updated:\n%s", out)
	}
	if rm, add := lineDiff(string(src), string(out)); len(rm) != 1 || len(add) != 1 {
		t.Fatalf("want one changed line, got -%q +%q", rm, add)
	}
	out = edit(t, out, func(d *Doc) error { return d.SetLayout("brand-new", map[string]float64{"x": 1, "y": 2}) })
	if !strings.Contains(string(out), "  brand-new: {x: 1, y: 2}\n") {
		t.Fatalf("layout not added:\n%s", out)
	}
	tiny := []byte("version: 1\nsystem:\n  name: Tiny\n")
	out = edit(t, tiny, func(d *Doc) error { return d.SetLayout("api", map[string]float64{"x": 1.5, "y": 2}) })
	if !strings.HasSuffix(string(out), "\nlayout:\n  api: {x: 1.5, y: 2}\n") {
		t.Fatalf("layout section not created:\n%s", out)
	}
}

func TestScalarsRoundTrip(t *testing.T) {
	tricky := []string{
		"no", "yes", "On", "null", "~", "1.10", "007", "-5", "true",
		"has: colon", "has #hash", "trailing:", "[bracket", "{brace}", "a, b", "*star", "&amp", "!bang", "%pct", "@handle",
		"'quoted'", "\"dq\"", " leading space", "tab\there", "multi\nline", "émoji 🔐", "back\\slash", "- dash", "-dash",
		"A logged-in customer could read other customers' invoices by changing the ID in the URL",
	}
	src := canonicalExample(t)
	for _, s := range tricky {
		out := edit(t, src, func(d *Doc) error {
			_, err := d.Upsert("threats", "read-others-invoices", map[string]any{"impact_note": s, "affects": []any{"api", "edge-to-api"}})
			return err
		})
		if got := valid(t, out).Threat("read-others-invoices").ImpactNote; got != s {
			t.Errorf("%q round-tripped as %q", s, got)
		}
	}
}

func TestRejectsBadInput(t *testing.T) {
	d, err := Parse(canonicalExample(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Upsert("threats", "Bad ID", nil); err == nil {
		t.Error("bad id accepted")
	}
	if _, err := d.Upsert("nope", "x", nil); err == nil {
		t.Error("unknown section accepted")
	}
	if _, err := d.Upsert("threats", "read-others-invoices", map[string]any{"id": "renamed"}); err == nil {
		t.Error("id change accepted")
	}
	if err := d.Delete("threats", "missing"); err == nil {
		t.Error("deleting a missing item succeeded")
	}
}

// FuzzUpsert sets arbitrary text on threat fields and checks the result is
// canonical, valid, and reads back exactly what was written.
func FuzzUpsert(f *testing.F) {
	src, err := os.ReadFile("../../docs/examples/invoice-service.threatmodel.yaml")
	if err != nil {
		f.Fatal(err)
	}
	canon, err := Format(src)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"no", "a: b", "#x", "- y", "[z]", "{w}", "multi\nline", "  pad  ", "\"q\"", "'s'", "\\", "\t"} {
		f.Add(s, uint8(0))
	}
	fields := []string{"title", "impact_note", "reason"}
	f.Fuzz(func(t *testing.T, s string, which uint8) {
		if s == "" || len(s) > 500 || !utf8Valid(s) {
			t.Skip()
		}
		field := fields[int(which)%len(fields)]
		d, err := Parse(canon)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Upsert("threats", "credential-stuffing", map[string]any{field: s, "attack": []any{s, "step two"}}); err != nil {
			t.Fatal(err)
		}
		out := d.Bytes()
		again, err := Format(out)
		if err != nil || string(again) != string(out) {
			t.Fatalf("not canonical after setting %s=%q (err %v):\n%s", field, s, err, out)
		}
		doc, diags := model.Parse(out)
		if diags.HasErrors() {
			t.Fatalf("invalid after setting %s=%q: %v", field, s, diags)
		}
		th := doc.Model.Threat("credential-stuffing")
		got := map[string]string{"title": th.Title, "impact_note": th.ImpactNote, "reason": th.Reason}[field]
		if s != "" && got != s || th.Attack[0] != s && s != "" {
			t.Fatalf("%s=%q read back as %q / attack %q", field, s, got, th.Attack[0])
		}
	})
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }

func TestAppendAfterSectionEmptied(t *testing.T) {
	src := []byte("version: 1\nsystem:\n  name: Tiny\n\ndata:\n  - id: a\n    name: A\n    sensitivity: public\n\nzones: [{id: z, name: Z, trust: trusted}]\n")
	out := edit(t, src, func(d *Doc) error { return d.Delete("data", "a") })
	if !strings.Contains(string(out), "data: []") {
		t.Fatalf("expected an empty list:\n%s", out)
	}
	out = edit(t, out, func(d *Doc) error {
		_, err := d.Upsert("data", "b", map[string]any{"name": "B", "sensitivity": "secret"})
		return err
	})
	if !strings.Contains(string(out), "data:\n  - id: b\n    name: B\n    sensitivity: secret\n") {
		t.Fatalf("append to emptied section:\n%s", out)
	}
	// An inline list of items becomes a block list with the new item.
	out = edit(t, out, func(d *Doc) error {
		_, err := d.Upsert("zones", "y", map[string]any{"name": "Y", "trust": "untrusted"})
		return err
	})
	m := valid(t, out)
	if len(m.Zones) != 2 || m.Zones[0].ID != "z" || m.Zones[1].ID != "y" {
		t.Fatalf("zones = %+v\n%s", m.Zones, out)
	}
}

// TestEmptyAndRefillEverySection deletes every threat, mitigation and flow
// of the example and adds new ones, checking the file stays valid throughout.
func TestEmptyAndRefillEverySection(t *testing.T) {
	src := canonicalExample(t)
	m := valid(t, src)
	out := src
	for _, th := range m.Threats {
		out = edit(t, out, func(d *Doc) error { return d.Delete("threats", th.ID) })
	}
	for _, mt := range m.Mitigations {
		out = edit(t, out, func(d *Doc) error { return d.Delete("mitigations", mt.ID) })
	}
	for _, f := range m.Flows {
		out = edit(t, out, func(d *Doc) error { return d.Delete("flows", f.ID) })
	}
	out = edit(t, out, func(d *Doc) error {
		_, err := d.Upsert("mitigations", "m1", map[string]any{"title": "Fix it", "status": "planned", "effect": "eliminates"})
		return err
	})
	out = edit(t, out, func(d *Doc) error {
		_, err := d.Upsert("flows", "f1", map[string]any{"from": "browser", "to": "api"})
		return err
	})
	out = edit(t, out, func(d *Doc) error {
		_, err := d.Upsert("threats", "t1", map[string]any{"title": "Someone could do a thing", "status": "open", "affects": []any{"f1"}, "mitigations": []any{"m1"}})
		return err
	})
	got := valid(t, out)
	if len(got.Threats) != 1 || len(got.Flows) != 1 || len(got.Mitigations) != 1 {
		t.Fatalf("refill failed:\n%s", out)
	}
}

func TestPermissionRowsAreInline(t *testing.T) {
	src := canonicalExample(t)
	out := edit(t, src, func(d *Doc) error {
		_, err := d.Upsert("identities", "new-role", map[string]any{
			"name": "New role", "kind": "role",
			"can": []any{map[string]any{"on": "db", "do": "read"}, map[string]any{"do": "invoke", "on": "api"}},
		})
		return err
	})
	if !strings.Contains(string(out), "    can:\n      - {do: read, on: db}\n      - {do: invoke, on: api}\n") {
		t.Fatalf("permission rows not written inline:\n%s", out)
	}
}
