package catalog

import (
	"os"
	"strings"
	"testing"

	"github.com/open-security-tooling/threat-model/internal/model"
)

func TestBuiltinCatalogsAreValid(t *testing.T) {
	cats, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	kinds := map[string]bool{}
	for _, c := range cats {
		total += len(c.Entries)
		for _, e := range c.Entries {
			kinds[e.Kind] = true
		}
	}
	t.Logf("%d catalogs, %d entries", len(cats), total)
	if total == 0 {
		t.Fatal("no entries")
	}
}

func example(t *testing.T) *model.Model {
	t.Helper()
	src, err := os.ReadFile("../../docs/examples/invoice-service.threatmodel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, diags := model.Parse(src)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	return doc.Model
}

func TestSuggestFillsInModelNames(t *testing.T) {
	m := example(t)
	cats, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	all := Suggest(m, cats, "")
	byFrom := map[string][]Suggestion{}
	for _, s := range all {
		byFrom[s.From] = append(byFrom[s.From], s)
		if strings.Contains(s.Threat.Title, "{") {
			t.Errorf("unfilled placeholder in %q", s.Threat.Title)
		}
	}
	// Already in the example model (from: catalog:web/object-level-access on api).
	for _, s := range byFrom["catalog:web/object-level-access"] {
		if s.Target == "api" {
			t.Error("suggested a threat the model already has")
		}
	}
	// The SSRF entry is already accepted for the PDF renderer.
	if len(byFrom["catalog:web/server-side-request-forgery"]) != 0 {
		t.Errorf("SSRF suggested again: %+v", byFrom["catalog:web/server-side-request-forgery"])
	}
	// Unauthenticated internal flow api -> pdf-renderer.
	found := false
	for _, s := range byFrom["catalog:web/unauthenticated-internal-call"] {
		if s.Target == "api-to-pdf" {
			found = true
			if !strings.Contains(s.Threat.Title, "PDF renderer") || !strings.Contains(s.Threat.Title, "Invoice API") {
				t.Errorf("names not filled in: %q", s.Threat.Title)
			}
		}
	}
	if !found {
		t.Error("no suggestion for the unauthenticated api-to-pdf flow")
	}
	t.Logf("%d suggestions for the example", len(all))
}

func TestTargetFilter(t *testing.T) {
	m := example(t)
	cats, _ := Builtin()
	for _, s := range Suggest(m, cats, "db") {
		if s.Target != "db" {
			t.Errorf("suggestion for %s when filtering on db", s.Target)
		}
	}
}

func TestParseRejectsBadEntries(t *testing.T) {
	bad := []string{
		"- id: x\n  title: Broken access control\n  kind: leak\n  applies: {component: {kind: [service]}}\n  attack: [a, b]\n  defaults: {who: anyone, effort: trivial, impact: low}\n  mitigations: [{id: m, title: M, effect: eliminates}]\n  why_it_matters: x\n",
		"- id: x\n  title: Someone could x\n  kind: leak\n  applies: {component: {kind: [servise]}}\n  attack: [a, b]\n  defaults: {who: anyone, effort: trivial, impact: low}\n  mitigations: [{id: m, title: M, effect: eliminates}]\n  why_it_matters: x\n",
		"- id: x\n  title: Someone could x {nope}\n  kind: leak\n  applies: {component: {kind: [service]}}\n  attack: [a, b]\n  defaults: {who: anyone, effort: trivial, impact: low}\n  mitigations: [{id: m, title: M, effect: eliminates}]\n  why_it_matters: x\n",
		"- &a {id: x}\n- *a\n",
		"- id: x\n  unknown: field\n",
	}
	for i, src := range bad {
		if _, err := Parse("t", []byte(src)); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestFeaturesTenancyAndAlternatives(t *testing.T) {
	m := example(t)
	cats, _ := Builtin()
	has := func(from, target string) bool {
		for _, s := range Suggest(m, cats, target) {
			if s.From == from {
				return true
			}
		}
		return false
	}
	m.System.Tenancy = ""
	if has("catalog:saas/tenant-id-from-request", "api") {
		t.Error("multi-tenant entry fired without tenancy: multi")
	}
	m.System.Tenancy = "multi"
	if !has("catalog:saas/tenant-id-from-request", "api") {
		t.Error("multi-tenant entry didn't fire with tenancy: multi")
	}
	// The API does its own login: identity entries apply through features.
	m.Component("api").Features = nil
	if has("catalog:identity/password-reset-takeover", "api") {
		t.Error("password reset entry fired without the feature")
	}
	m.Component("api").Features = []string{"login", "password-reset"}
	if !has("catalog:identity/password-reset-takeover", "api") || !has("catalog:identity/user-enumeration", "api") {
		t.Error("identity entries didn't fire on a service with login features")
	}
	// {data} prefers business data over credentials.
	for _, s := range Suggest(m, cats, "pdf-renderer") {
		if strings.Contains(s.Threat.Title, "AWS credentials") && s.From != "catalog:supply-chain/ci-secret-theft" {
			t.Errorf("title names credentials instead of business data: %q", s.Threat.Title)
		}
	}
}

func TestAppliesAlternativesParse(t *testing.T) {
	src := "- id: x\n  title: Someone could x\n  kind: leak\n  applies:\n    - component: {kind: [identity]}\n    - component: {kind: [service], features: [login]}\n  attack: [a, b]\n  defaults: {who: anyone, effort: trivial, impact: low}\n  mitigations: [{id: m, title: M, effect: eliminates}]\n  why_it_matters: x\n"
	c, err := Parse("t", []byte(src))
	if err != nil || len(c.Entries[0].Applies) != 2 {
		t.Fatalf("alternatives: %v %+v", err, c)
	}
}

func TestDuplicateDetection(t *testing.T) {
	m := example(t)
	hand := "Anyone on the internet could take over customer accounts by trying passwords leaked from other sites"
	lib := "Anyone on the internet could take over accounts on Invoice API by trying email and password pairs leaked from other sites"
	if !duplicatesHandWritten(&model.Model{Threats: []model.Threat{{Kind: "impersonate", Title: hand, Affects: []string{"x"}}}}, "impersonate", lib, []string{"x"}) {
		t.Error("near-identical titles not treated as duplicates")
	}
	tenant := "A user of one customer organisation could read or change another organisation's records on Invoice API by changing the tenant ID sent in a header, subdomain, path or request body, if Invoice API trusts it instead of the logged-in session"
	if duplicatesHandWritten(m, "leak", tenant, []string{"api"}) {
		t.Error("a different threat on the same component was treated as a duplicate")
	}
}
