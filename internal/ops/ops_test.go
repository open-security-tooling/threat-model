package ops

import (
	"encoding/json"
	"github.com/open-security-tooling/threat-model/internal/model"
	"os"
	"strings"
	"testing"
)

func example(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile("../../docs/examples/invoice-service.threatmodel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestShow(t *testing.T) {
	v, err := Show(example(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Summary.Threats != 7 || v.Summary.Components != 9 {
		t.Errorf("summary = %+v", v.Summary)
	}
	if v.Risks["read-others-invoices"].Level != "critical" {
		t.Errorf("risk = %+v", v.Risks["read-others-invoices"])
	}
	if len(v.Crossings) == 0 || v.Lines["api"] == 0 {
		t.Errorf("crossings %v lines %v", v.Crossings, v.Lines)
	}
	if got := v.Coverage["api"]["leak"]; len(got) == 0 {
		t.Errorf("coverage for api = %v", v.Coverage["api"])
	}
}

func TestUpsertRejectsInvalidResult(t *testing.T) {
	src := example(t)
	_, err := Upsert(src, "flows", "new-flow", map[string]any{"from": "api", "to": "nowhere"})
	oe, ok := err.(*Error)
	if !ok || !strings.Contains(oe.Message, "wasn't made") || len(oe.Diagnostics) == 0 {
		t.Fatalf("invalid edit not rejected: %v", err)
	}
	if !strings.Contains(oe.Diagnostics[0].Message, "nowhere") {
		t.Errorf("diagnostic doesn't name the problem: %v", oe.Diagnostics[0])
	}
}

func TestUpsertCannotAccept(t *testing.T) {
	_, err := Upsert(example(t), "threats", "read-others-invoices", map[string]any{"status": "accepted"})
	if err == nil || !strings.Contains(err.Error(), "set_status") {
		t.Fatalf("accept through upsert allowed: %v", err)
	}
}

func TestSetStatus(t *testing.T) {
	src := example(t)
	acc := StatusRequest{ID: "read-others-invoices", Status: "accepted"}
	if _, err := SetStatus(src, acc, false); err == nil || !strings.Contains(err.Error(), "human decision") {
		t.Fatalf("agent accepted a risk: %v", err)
	}
	acc.Accepted = nil
	if _, err := SetStatus(src, acc, true); err == nil {
		t.Fatal("accepted without by/reason/until")
	}
	r, err := SetStatus(src, StatusRequest{ID: "support-edits-without-trace", Status: "open"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Source, "until: 2027-03-31") {
		t.Error("accepted block not removed when reopening")
	}
	r, err = SetStatus(src, StatusRequest{ID: "random-invoice-ids", Status: "done"}, false)
	if err != nil || !r.Changed {
		t.Fatalf("mitigation status: %v", err)
	}
}

func TestDeleteRefusesDanglingRefs(t *testing.T) {
	_, err := Delete(example(t), "components", "api")
	if err == nil || !strings.Contains(err.Error(), "still used by") {
		t.Fatalf("deleting a referenced component allowed: %v", err)
	}
	r, err := Delete(example(t), "threats", "public-pdf-bucket")
	if err != nil || strings.Contains(r.Source, "public-pdf-bucket") {
		t.Fatalf("delete failed: %v", err)
	}
}

func TestCallEnvelope(t *testing.T) {
	req, _ := json.Marshal(Request{Source: string(example(t)), ID: "credential-stuffing"})
	var out struct {
		Result ExplainResult `json:"result"`
		Error  *Error        `json:"error"`
	}
	if err := json.Unmarshal(Call("explain", req), &out); err != nil || out.Error != nil {
		t.Fatalf("explain: %v %v", err, out.Error)
	}
	if out.Result.Risk.Level != "high" || len(out.Result.Mitigations) != 2 {
		t.Errorf("explain result: %+v", out.Result.Risk)
	}
	if err := json.Unmarshal(Call("nope", req), &out); err != nil || out.Error == nil {
		t.Fatal("unknown op not reported")
	}
}

func TestSuggestAcceptDismiss(t *testing.T) {
	src := example(t)
	r, err := Suggest(src, "api-to-pdf", nil)
	if err != nil || len(r.Suggestions) == 0 {
		t.Fatalf("no suggestions for api-to-pdf: %v", err)
	}
	s := r.Suggestions[0]
	acc, err := AcceptSuggestion(src, s.From, s.Target, map[string]any{"effort": "hard"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Show([]byte(acc.Source))
	if err != nil {
		t.Fatal(err)
	}
	th := v.Model.Threat(s.Threat.ID)
	if th == nil || th.Effort != "hard" || th.From != s.From || len(th.Mitigations) == 0 {
		t.Fatalf("accepted threat = %+v", th)
	}
	for _, mid := range th.Mitigations {
		if v.Model.Mitigation(mid) == nil {
			t.Errorf("mitigation %s not created", mid)
		}
	}
	// Accepted suggestions aren't suggested again.
	again, _ := Suggest([]byte(acc.Source), "api-to-pdf", nil)
	for _, x := range again.Suggestions {
		if x.From == s.From {
			t.Error("accepted suggestion suggested again")
		}
	}
	if _, err := DismissSuggestion(src, s.From, s.Target, "", nil); err == nil {
		t.Error("dismiss without reason allowed")
	}
	dis, err := DismissSuggestion(src, s.From, s.Target, "Calls are signed with a shared key.", nil)
	if err != nil {
		t.Fatal(err)
	}
	dv, _ := Show([]byte(dis.Source))
	if th := dv.Model.Threat(s.Threat.ID); th == nil || th.Status != "not-applicable" {
		t.Fatalf("dismissal not recorded: %+v", th)
	}
}

func TestNewAndSetLayouts(t *testing.T) {
	r, err := New("Shop: checkout %s # v2")
	if err != nil {
		t.Fatal(err)
	}
	v, err := Show([]byte(r.Source))
	if err != nil || v.Model.System.Name != "Shop: checkout %s # v2" {
		t.Fatalf("new model: %v %+v", err, v.Model)
	}
	if res := Validate([]byte(r.Source)); !res.OK || !res.Canonical {
		t.Fatalf("starter not valid and canonical: %+v", res)
	}
	src := example(t)
	before, _ := Show(src)
	lr, err := SetLayouts(src, map[string]map[string]float64{"api": {"x": 1, "y": 2}, "db": {"x": 3, "y": 4}, "pdf-bucket": nil})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := Show([]byte(lr.Source))
	if after.Model.Layout["api"].X != 1 || after.Model.Layout["db"].Y != 4 {
		t.Errorf("layouts not set: %+v", after.Model.Layout)
	}
	if _, ok := after.Model.Layout["pdf-bucket"]; ok || len(after.Model.Layout) != len(before.Model.Layout)-1 {
		t.Errorf("layout not removed: %+v", after.Model.Layout)
	}
}

func TestCoverageHasNoDuplicates(t *testing.T) {
	v, _ := Show(example(t))
	for comp, kinds := range v.Coverage {
		for kind, ids := range kinds {
			seen := map[string]bool{}
			for _, id := range ids {
				if seen[id] {
					t.Errorf("%s/%s lists %s twice", comp, kind, id)
				}
				seen[id] = true
			}
		}
	}
}

func TestSetSignoff(t *testing.T) {
	r, err := SetSignoff(example(t), &model.Signoff{By: "@appsec", On: "2026-10-01", Note: "Reviewed with the billing team"})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := Show([]byte(r.Source))
	if s := v.Model.Signoff; s == nil || s.By != "@appsec" || !strings.Contains(r.Source, "\nsignoff:\n  by: \"@appsec\"\n  on: 2026-10-01\n") {
		t.Fatalf("signoff not written:\n%s", r.Source)
	}
	if strings.Index(r.Source, "signoff:") > strings.Index(r.Source, "layout:") {
		t.Error("signoff should come before layout")
	}
	r, err = SetSignoff([]byte(r.Source), nil)
	if err != nil || strings.Contains(r.Source, "signoff:") {
		t.Fatalf("signoff not removed: %v", err)
	}
	if _, err := SetSignoff(example(t), &model.Signoff{By: "@x"}); err == nil {
		t.Error("signoff without a date accepted")
	}
}
