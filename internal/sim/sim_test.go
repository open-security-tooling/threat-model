package sim

import (
	"os"
	"strings"
	"testing"

	"github.com/open-security-tooling/threat-model/internal/model"
)

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

func titles(p Path) string {
	var out []string
	for _, s := range p.Steps {
		out = append(out, s.ThreatID+s.Rule)
	}
	return strings.Join(out, " > ")
}

func TestPathsFromTheInternet(t *testing.T) {
	m := example(t)
	r := Paths(m, Start{Access: "anyone"}, []string{"invoices"})
	if len(r.Paths) != 1 {
		t.Fatalf("no path to invoices: %+v", r)
	}
	p := r.Paths[0]
	// Shortest explanation: sign up, then change the ID in the URL.
	if p.Weakest != "trivial" || !strings.Contains(titles(p), "signup > read-others-invoices") {
		t.Errorf("path = %s (weakest %s)", titles(p), p.Weakest)
	}
	// Checking the invoice owner removes the trivial path. Other paths remain
	// (prompt injection, credential stuffing), so it doesn't cut invoices off
	// entirely, but it should be listed as making the easiest path harder.
	found := false
	for _, f := range r.Fixes {
		if f.MitigationID == "check-invoice-owner" {
			found = true
			if len(f.Breaks) != 0 || len(f.Harder) != 1 || f.Harder[0] != "invoices" {
				t.Errorf("check-invoice-owner impact = %+v", f)
			}
		}
	}
	if !found {
		t.Errorf("check-invoice-owner not listed: %+v", r.Fixes)
	}
}

func TestFixRanking(t *testing.T) {
	m := example(t)
	// Make invoices reachable only through the IDOR, so its fix matters.
	for i := range m.Threats {
		if id := m.Threats[i].ID; id != "read-others-invoices" {
			m.Threats[i].Status = "mitigated"
		}
	}
	r := Paths(m, Start{Access: "anyone"}, []string{"invoices"})
	if len(r.Fixes) == 0 || r.Fixes[0].MitigationID != "check-invoice-owner" {
		t.Fatalf("fixes = %+v", r.Fixes)
	}
	// The planned UUID change only raises effort: it makes the path harder
	// but doesn't cut it.
	for _, f := range r.Fixes {
		if f.MitigationID == "random-invoice-ids" && (len(f.Breaks) != 0 || len(f.Harder) != 1) {
			t.Errorf("random-invoice-ids should make the path harder, not cut it: %+v", f)
		}
	}
}

func TestChainThroughControl(t *testing.T) {
	m := example(t)
	// pdf-fetches-internal-urls gives control of the PDF bucket; that should
	// chain into reading what the bucket stores.
	r := Paths(m, Start{Access: "any-user"}, []string{"pdf-task-credentials"})
	if len(r.Paths) != 1 || !strings.Contains(titles(r.Paths[0]), "pdf-fetches-internal-urls") {
		t.Fatalf("paths = %+v", r.Paths)
	}
}

func TestDoneMitigationsBlock(t *testing.T) {
	m := example(t)
	for i := range m.Mitigations {
		m.Mitigations[i].Status = "done"
	}
	r := Paths(m, Start{Access: "anyone"}, nil)
	for _, p := range r.Paths {
		for _, s := range p.Steps {
			if s.ThreatID == "read-others-invoices" || s.ThreatID == "assistant-prompt-injection" {
				t.Errorf("eliminated threat still used: %s", titles(p))
			}
		}
	}
}

func TestBlastRadius(t *testing.T) {
	m := example(t)
	// Take away the outside paths so the API's own reach shows.
	for i := range m.Threats {
		m.Threats[i].Status = "mitigated"
	}
	b := BlastRadius(m, "api")
	for _, want := range []string{"invoices", "stripe-api-key", "session-token"} {
		found := false
		for _, d := range b.Reads {
			found = found || d == want
		}
		if !found {
			t.Errorf("controlling the API should read %s; reads %v", want, b.Reads)
		}
	}
}

func TestParseStart(t *testing.T) {
	m := example(t)
	for _, ok := range []string{"anyone", "insider", "physical", "controls:api"} {
		if _, err := ParseStart(m, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"everyone", "controls:nope", ""} {
		if _, err := ParseStart(m, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDeterministic(t *testing.T) {
	m := example(t)
	first := Paths(m, Start{Access: "anyone"}, nil)
	for i := 0; i < 50; i++ {
		again := Paths(m, Start{Access: "anyone"}, nil)
		if len(again.Paths) != len(first.Paths) {
			t.Fatal("path count changed between runs")
		}
		for j := range again.Paths {
			if titles(again.Paths[j]) != titles(first.Paths[j]) {
				t.Fatalf("run %d: %s != %s", i, titles(again.Paths[j]), titles(first.Paths[j]))
			}
		}
	}
}

// Segmenting a zone should shrink what a compromised component can reach.
func TestSegmentationShrinksBlastRadius(t *testing.T) {
	m := example(t)
	// Only the database threat below is in play.
	for i := range m.Threats {
		m.Threats[i].Status = "mitigated"
	}
	// A threat that works on anything once you're on the network.
	m.Threats = append(m.Threats, model.Threat{
		ID: "db-default-password", Title: "Someone on the network could log in to the database with its default password",
		Affects: []string{"db"}, Who: "insider", Effort: "trivial", Impact: "critical", Status: "open",
		Gives: &model.Gives{Reads: []string{"invoices"}, Controls: []string{"db"}},
	})
	for i := range m.Zones {
		if m.Zones[i].ID == "aws-prod" {
			m.Zones[i].Network = "open"
		}
	}
	open := BlastRadius(m, "pdf-renderer")
	if open.Names["db"] != "Invoice database" {
		t.Errorf("names missing: %v", open.Names)
	}
	if !contains(open.Controls, "db") {
		t.Fatalf("on a flat network, the PDF renderer should reach the database: %+v", open)
	}
	for i := range m.Zones {
		if m.Zones[i].ID == "aws-prod" {
			m.Zones[i].Network = "segmented"
		}
	}
	seg := BlastRadius(m, "pdf-renderer")
	if contains(seg.Controls, "db") {
		t.Fatalf("with segmentation, the PDF renderer has no flow to the database: %+v", seg)
	}
	// The API does talk to the database, so it still reaches it.
	if api := BlastRadius(m, "api"); !contains(api.Controls, "db") {
		t.Fatalf("the API has a flow to the database and should still reach it: %+v", api)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestIdentityPermissions(t *testing.T) {
	m := example(t)
	for i := range m.Threats {
		m.Threats[i].Status = "mitigated"
	}
	// Data only the database holds, so a path to it must use the role.
	m.Data = append(m.Data, model.Data{ID: "audit-log", Name: "Audit log", Sensitivity: "confidential"})
	m.Component("db").Stores = append(m.Component("db").Stores, "audit-log")
	m.Identities = []model.Identity{{ID: "pdf-role", Name: "PDF renderer role", Kind: "role", Can: []model.Permission{{Do: "admin", On: "db"}}}}
	m.Component("pdf-renderer").Identity = "pdf-role"
	for i := range m.Zones {
		m.Zones[i].Network = "segmented"
	}
	b := BlastRadius(m, "pdf-renderer")
	if !contains(b.Controls, "db") {
		t.Fatalf("an over-broad role should hand over the database: %+v", b)
	}
	found := false
	for _, p := range b.Paths {
		for _, s := range p.Steps {
			found = found || s.Rule == "identity"
		}
	}
	if !found {
		t.Error("no step explains the identity permission")
	}
	m.Identities[0].Can = []model.Permission{{Do: "read", On: "pdf-bucket"}}
	if b := BlastRadius(m, "pdf-renderer"); contains(b.Controls, "db") {
		t.Errorf("least privilege should keep the database out of reach: %+v", b)
	}
}

func TestExfiltration(t *testing.T) {
	m := example(t)
	for i := range m.Threats {
		m.Threats[i].Status = "mitigated"
	}
	start := Start{Controls: "pdf-renderer"}
	r := Paths(m, start, []string{"invoices"})
	if len(r.Paths) != 1 || r.Paths[0].Contained || !strings.Contains(r.Paths[0].Exit, "anywhere on the internet") {
		t.Fatalf("open egress: %+v", r.Paths)
	}
	for i := range m.Zones {
		if m.Zones[i].ID == "aws-prod" {
			m.Zones[i].Egress = "restricted"
		}
	}
	r = Paths(m, start, []string{"invoices"})
	if len(r.Paths) != 1 || !r.Paths[0].Contained {
		t.Fatalf("restricted egress should contain the data: %+v", r.Paths)
	}
	// The API talks to Stripe, so data it reads still has a way out.
	r = Paths(m, Start{Controls: "api"}, []string{"stripe-api-key"})
	if len(r.Paths) != 1 || r.Paths[0].Contained {
		t.Fatalf("API reaches the internet anyway: %+v", r.Paths)
	}
}

func TestBlastMarksAlreadyReachable(t *testing.T) {
	m := example(t)
	// With the example's open threats, an outside attacker already reaches
	// the invoices; the blast radius should still list them, marked.
	b := BlastRadius(m, "pdf-renderer")
	if !contains(b.Reads, "invoices") || !contains(b.AlreadyReachable, "invoices") {
		t.Fatalf("blast = %+v", b)
	}
	if contains(b.AlreadyReachable, "pdf-task-credentials") == contains(b.Reads, "pdf-task-credentials") && !contains(b.Reads, "pdf-task-credentials") {
		t.Fatalf("pdf-task-credentials missing: %+v", b)
	}
}

func TestSigningCredentialsStayWithSender(t *testing.T) {
	m := example(t)
	for i := range m.Threats {
		m.Threats[i].Status = "mitigated"
	}
	// The CI → API flow carries deploy credentials, but over IAM: the API
	// never sees them, so controlling the API doesn't read them.
	b := BlastRadius(m, "api")
	if contains(b.Reads, "deploy-credentials") {
		t.Errorf("API shouldn't read CI's signing credentials: %v", b.Reads)
	}
	if b := BlastRadius(m, "github-actions"); !contains(b.Reads, "deploy-credentials") {
		t.Errorf("CI itself holds them: %v", b.Reads)
	}
}
