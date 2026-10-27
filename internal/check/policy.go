package check

import (
	"fmt"
	"slices"
	"time"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// rules applies the checks that need no git history: due dates, evidence,
// uncovered components, and everything the policy file asks for.
func (r *runner) rules(m *model.Model, doc *model.Document) {
	p := r.opts.Policy
	today := r.opts.Today.Format(time.DateOnly)
	errIf := func(on bool) string {
		if on {
			return SevError
		}
		return SevWarning
	}

	// Mitigations: evidence and due dates.
	for i, mt := range m.Mitigations {
		line := doc.Line(fmt.Sprintf("mitigations[%d]", i))
		if mt.Status == "done" && len(mt.Evidence) == 0 {
			r.add(Finding{Severity: errIf(p != nil && p.Require.EvidenceForDone), Code: "no-evidence", ID: mt.ID, Line: line,
				Message: fmt.Sprintf("Mitigation `%s` is done but has no evidence.", mt.ID),
				Hint:    "Add where it lives, e.g. `- code: path/to/file.go#Func` or `- test: path/to/file_test.go#TestName`."})
		}
		if mt.Status != "done" && mt.Due != "" && mt.Due < today {
			r.add(Finding{Severity: errIf(p != nil && p.Require.DueFor != ""), Code: "overdue", ID: mt.ID, Line: line,
				Message: fmt.Sprintf("Mitigation `%s` was due on %s and is still %s.", mt.ID, mt.Due, mt.Status),
				Hint:    "Finish it, or agree a new date and update `due`."})
		}
	}

	// Threats: hand-set risk, open risk above the policy limit, due dates.
	for i := range m.Threats {
		t := &m.Threats[i]
		if t.Status == "not-applicable" {
			continue
		}
		a := risk.Assess(m, t)
		line := doc.Line(fmt.Sprintf("threats[%d]", i))
		if t.Risk != nil {
			r.add(Finding{Severity: SevWarning, Code: "risk-override", ID: t.ID, Line: line,
				Message: fmt.Sprintf("Threat `%s` has its risk set by hand to %s (computed: %s): %q.", t.ID, t.Risk.Override, levelOr(a.InherentLevel), t.Risk.Reason)})
		}
		if p == nil || t.Status != "open" {
			continue
		}
		if p.FailOn.OpenRisk != "" && risk.Rank(a.Level) >= risk.Rank(p.FailOn.OpenRisk) {
			r.add(Finding{Severity: SevError, Code: "policy-open-risk", ID: t.ID, Line: line,
				Message: fmt.Sprintf("Threat `%s` is open at %s risk; policy allows nothing open at %s or above.", t.ID, a.Level, p.FailOn.OpenRisk),
				Hint:    "Finish a mitigation that lowers it, or have it accepted by someone allowed to."})
		}
		if p.Require.DueFor != "" && risk.Rank(a.Level) >= risk.Rank(p.Require.DueFor) {
			for _, mid := range t.Mitigations {
				if mt := m.Mitigation(mid); mt != nil && mt.Status != "done" && mt.Due == "" {
					r.add(Finding{Severity: SevError, Code: "policy-due", ID: mid,
						Message: fmt.Sprintf("Mitigation `%s` for %s threat `%s` has no due date.", mid, a.Level, t.ID), Hint: "Add `due: YYYY-MM-DD`."})
				}
			}
		}
		if p.Require.TestEvidenceFor != "" && risk.Rank(a.InherentLevel) >= risk.Rank(p.Require.TestEvidenceFor) {
			for _, mid := range t.Mitigations {
				if mt := m.Mitigation(mid); mt != nil && mt.Status == "done" && !hasTest(*mt) {
					r.add(Finding{Severity: SevError, Code: "policy-test-evidence", ID: mid,
						Message: fmt.Sprintf("Mitigation `%s` protects against %s threat `%s` but has no test evidence.", mid, a.InherentLevel, t.ID),
						Hint:    "Add `- test: path/to/file_test.go#TestName`."})
				}
			}
		}
	}

	// Internet-facing components nobody has thought about.
	for i, c := range m.Components {
		if c.Exposure != "internet" || len(c.Considered) > 0 || len(relatedThreats(m, c.ID)) > 0 {
			continue
		}
		r.add(Finding{Severity: SevWarning, Code: "uncovered-component", ID: c.ID, Line: doc.Line(fmt.Sprintf("components[%d]", i)),
			Message: fmt.Sprintf("%q is reachable from the internet and has no threats yet.", c.Name),
			Hint:    fmt.Sprintf("Run `threat suggest --component %s`, or record what was considered in `considered:`.", c.ID)})
	}

	if p == nil {
		return
	}
	if p.Acceptance.MaxDays > 0 {
		limit := r.opts.Today.AddDate(0, 0, p.Acceptance.MaxDays).Format(time.DateOnly)
		for _, t := range m.Threats {
			if t.Accepted != nil && t.Accepted.Until > limit {
				r.add(Finding{Severity: SevError, Code: "policy-acceptance", ID: t.ID,
					Message: fmt.Sprintf("Threat `%s` is accepted until %s; policy allows at most %d days.", t.ID, t.Accepted.Until, p.Acceptance.MaxDays)})
			}
		}
	}
	if p.Require.Signoff && m.Signoff == nil {
		r.add(Finding{Severity: SevError, Code: "policy-signoff", Message: "Policy requires a security sign-off, and the model has none.", Hint: "Add `signoff: {by: \"@reviewer\", on: YYYY-MM-DD}` after a review."})
	}
	if p.Review.MaxAgeDays > 0 {
		oldest := r.opts.Today.AddDate(0, 0, -p.Review.MaxAgeDays).Format(time.DateOnly)
		for _, c := range m.Components {
			if len(c.Code) > 0 && (c.Reviewed == "" || c.Reviewed < oldest) {
				r.add(Finding{Severity: SevError, Code: "policy-review-age", ID: c.ID,
					Message: fmt.Sprintf("%q hasn't been reviewed in the last %d days (reviewed: %s).", c.Name, p.Review.MaxAgeDays, levelOr(c.Reviewed))})
			}
		}
	}
	for _, req := range p.Catalogs.Required {
		if !usesCatalog(m, req) {
			r.add(Finding{Severity: SevError, Code: "policy-catalog", Message: fmt.Sprintf("Policy requires catalog %s, and the model doesn't use it.", req),
				Hint: fmt.Sprintf("Add `- %s` to `catalogs:`.", req)})
		}
	}
	r.checked = append(r.checked, "policy")
}

func usesCatalog(m *model.Model, req string) bool {
	if len(m.Catalogs) == 0 {
		// No catalogs listed means all built-in ones are used.
		return len(req) > len("builtin:") && req[:len("builtin:")] == "builtin:"
	}
	return slices.ContainsFunc(m.Catalogs, func(c model.CatalogRef) bool {
		return "builtin:"+c.Builtin == req || c.Path != "" && c.Path == req
	})
}
