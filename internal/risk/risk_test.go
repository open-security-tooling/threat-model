package risk

import (
	"os"
	"strings"
	"testing"

	"github.com/open-security-tooling/threat-model/internal/model"
)

// The tables in docs/risk.md, spelled out so a change to either is caught.
func TestTablesMatchSpec(t *testing.T) {
	cases := []struct{ who, effort, impact, want string }{
		{"anyone", "trivial", "high", "critical"},
		{"anyone", "hard", "medium", "medium"},
		{"any-user", "trivial", "high", "critical"},
		{"any-user", "moderate", "high", "high"},
		{"any-user", "hard", "critical", "high"},
		{"insider", "trivial", "medium", "medium"},
		{"insider", "moderate", "high", "medium"},
		{"privileged", "hard", "critical", "medium"},
		{"physical", "trivial", "low", "low"},
	}
	for _, c := range cases {
		if _, got := Level(Inputs{c.who, c.effort, c.impact}); got != c.want {
			t.Errorf("%s/%s/%s = %s, want %s", c.who, c.effort, c.impact, got, c.want)
		}
	}
	for _, who := range model.WhoLevels {
		for _, e := range model.Efforts {
			for _, i := range model.Impacts {
				if _, got := Level(Inputs{who, e, i}); Rank(got) < 0 {
					t.Errorf("no risk for %s/%s/%s", who, e, i)
				}
			}
		}
	}
}

func load(t *testing.T) *model.Model {
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

func TestAssessExample(t *testing.T) {
	m := load(t)
	cases := []struct {
		id, inherent, level, planned, why string
	}{
		// open, fix in progress: residual = inherent; planned = low (eliminates)
		{"read-others-invoices", "critical", "critical", "low", "anyone who signs up could do it in minutes"},
		// IMDSv2 is done (effort → hard): any-user/hard/critical = high
		{"pdf-fetches-internal-urls", "critical", "high", "low", "It was critical before"},
		// rate limiting done (effort → hard): anyone/hard/high = high
		{"credential-stuffing", "critical", "high", "low", "rare access"},
		// pinning done (effort hard, already hard); OIDC in progress (who → privileged)
		{"ci-dependency-steals-deploy-creds", "critical", "critical", "medium", "Drops to medium"},
		{"support-edits-without-trace", "medium", "medium", "medium", "someone on the inside could do it"},
	}
	for _, c := range cases {
		a := Assess(m, m.Threat(c.id))
		if a.InherentLevel != c.inherent || a.Level != c.level || a.Planned != c.planned {
			t.Errorf("%s: inherent/level/planned = %s/%s/%s, want %s/%s/%s", c.id, a.InherentLevel, a.Level, a.Planned, c.inherent, c.level, c.planned)
		}
		if !strings.Contains(a.Why, c.why) {
			t.Errorf("%s: why %q doesn't contain %q", c.id, a.Why, c.why)
		}
	}
	if a := Assess(m, m.Threat("public-pdf-bucket")); a.Assessed || !a.NotApplicable || a.Level != "" || !strings.HasPrefix(a.Why, "Not applicable") {
		t.Errorf("not-applicable threat assessed: %+v", a)
	}
}

func TestEffectsNeverMakeThingsWorse(t *testing.T) {
	in := Inputs{"insider", "hard", "low"}
	out, _ := apply(in, false, model.Effect{Who: "anyone", Effort: "trivial", Impact: "critical"})
	if out != in {
		t.Errorf("effect worsened inputs: %+v", out)
	}
}

func TestOverride(t *testing.T) {
	m := load(t)
	th := *m.Threat("support-edits-without-trace")
	th.Risk = &model.RiskOverride{Override: "critical", Reason: "Regulators treat this as fraud."}
	a := Assess(m, &th)
	if a.Level != "critical" || !a.Override || !strings.Contains(a.Why, "set by hand") {
		t.Errorf("override not applied: %+v", a)
	}
}

func TestWhyReadsAsOneSentence(t *testing.T) {
	m := load(t)
	a := Assess(m, m.Threat("read-others-invoices"))
	want := "Critical, because anyone who signs up could do it in minutes, with no special skill; the impact is high: exposes names, addresses and amounts for every customer."
	if !strings.HasPrefix(a.Why, want) {
		t.Errorf("why = %q\nwant prefix %q", a.Why, want)
	}
	a = Assess(m, m.Threat("credential-stuffing"))
	if !strings.Contains(a.Why, "could do it, but it takes rare access") {
		t.Errorf("why = %q", a.Why)
	}
	if strings.Contains(a.Why, "..") || strings.Contains(a.Why, ": A") {
		t.Errorf("why = %q", a.Why)
	}
}

func TestLowerFirst(t *testing.T) {
	for in, want := range map[string]string{
		"Exposes names":         "exposes names",
		"AWS credentials leak":  "AWS credentials leak",
		"S3 bucket is readable": "S3 bucket is readable",
		"A customer loses data": "a customer loses data",
		"I can't think of one":  "I can't think of one",
		"Één ding":              "één ding",
		"already lowercase":     "already lowercase",
		"":                      "",
	} {
		if got := lowerFirst(in); got != want {
			t.Errorf("lowerFirst(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChangeSummary(t *testing.T) {
	m := load(t)
	got := map[string]string{}
	for _, c := range Assess(m, m.Threat("credential-stuffing")).Changes {
		got[c.MitigationID] = c.Summary
	}
	if got["rate-limit-login"] != "critical → high" || got["offer-mfa"] != "critical → low once done" {
		t.Errorf("summaries = %v", got)
	}
	if s := ChangeSummary("high", "high", true); s != "no change in risk" {
		t.Errorf("same level: %q", s)
	}
}
