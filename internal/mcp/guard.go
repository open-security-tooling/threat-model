package mcp

import (
	"fmt"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// update applies an edit to the model file, refusing changes that a person
// should make unless the session allows them (Options.AllowRiskLowering).
//
// The guard compares the model before and after the edit rather than
// looking at tool arguments, so every write tool is covered the same way,
// whatever route an edit takes.
func (s *server) update(fn func(src []byte) (ops.EditResult, error)) (ops.EditResult, error) {
	return s.file.update(func(src []byte) (ops.EditResult, error) {
		res, err := fn(src)
		if err != nil || !res.Changed || s.opts.AllowRiskLowering {
			return res, err
		}
		before, after := ops.Load(src).Model, ops.Load([]byte(res.Source)).Model
		if before == nil || after == nil {
			return res, nil // ops refuses edits that leave the file unreadable
		}
		if problems := needsPerson(before, after); len(problems) > 0 {
			return ops.EditResult{}, &ops.Error{Message: "This change needs a person, so it wasn't made: " + strings.Join(problems, "; ") +
				". Leave the model as it is and propose the change to the user in your reply, with your reasons; they can make it themselves."}
		}
		return res, nil
	})
}

// inherentLevel is a threat's risk from its own who/effort/impact answers,
// ignoring mitigations and overrides. It's computed for not-applicable
// threats too, so marking one not-applicable can be judged by what it was.
func inherentLevel(m *model.Model, t *model.Threat) string {
	c := *t
	if c.Status == "not-applicable" {
		c.Status = "open"
	}
	return risk.Assess(m, &c).InherentLevel
}

// needsPerson lists the changes from before to after that make the model
// look safer, or that record a human judgement.
func needsPerson(before, after *model.Model) []string {
	var out []string
	for i := range before.Threats {
		bt := &before.Threats[i]
		was := inherentLevel(before, bt)
		ct := after.Threat(bt.ID)
		if ct == nil {
			out = append(out, fmt.Sprintf("it deletes threat `%s`%s", bt.ID, levelNote(was)))
			continue
		}
		if ct.Status == "not-applicable" && bt.Status != "not-applicable" && risk.Rank(was) >= risk.Rank("high") {
			out = append(out, fmt.Sprintf("it marks threat `%s` not-applicable although its risk before mitigations is %s", ct.ID, was))
		}
		if now := inherentLevel(after, ct); was != "" && risk.Rank(now) < risk.Rank(was) {
			if now == "" {
				out = append(out, fmt.Sprintf("it leaves threat `%s` without a risk level by removing who, effort or impact (it was %s)", ct.ID, was))
			} else {
				out = append(out, fmt.Sprintf("it lowers threat `%s`'s risk before mitigations from %s to %s by changing who, effort or impact", ct.ID, was, now))
			}
		}
		switch {
		case ct.Risk != nil && (bt.Risk == nil || *ct.Risk != *bt.Risk):
			out = append(out, fmt.Sprintf("it sets threat `%s`'s risk by hand (`risk` override)", ct.ID))
		case ct.Risk == nil && bt.Risk != nil:
			from, to := risk.Assess(before, bt).Level, risk.Assess(after, ct).Level
			if risk.Rank(to) < risk.Rank(from) {
				out = append(out, fmt.Sprintf("it removes threat `%s`'s risk override, which lowers its risk from %s to %s", ct.ID, from, levelOr(to)))
			}
		}
	}
	for i := range after.Threats {
		ct := &after.Threats[i]
		if before.Threat(ct.ID) != nil {
			continue
		}
		if ct.Risk != nil {
			out = append(out, fmt.Sprintf("it sets the new threat `%s`'s risk by hand (`risk` override)", ct.ID))
		}
		// Recording a serious threat as "doesn't apply" (e.g. dismissing a
		// library suggestion) is the same judgement as dismissing it later.
		if lvl := inherentLevel(after, ct); ct.Status == "not-applicable" && risk.Rank(lvl) >= risk.Rank("high") {
			out = append(out, fmt.Sprintf("it records threat `%s` as not applicable although its risk before mitigations is %s", ct.ID, lvl))
		}
	}
	for _, c := range after.Components {
		b := before.Component(c.ID)
		if c.Reviewed != "" && (b == nil || b.Reviewed != c.Reviewed || b.ReviewedBy != c.ReviewedBy) {
			out = append(out, fmt.Sprintf("it records a review of component `%s` (`reviewed`), and a review is a person's statement", c.ID))
		}
	}
	return out
}

func levelNote(level string) string {
	if level == "" {
		return ""
	}
	return " (" + level + " risk before mitigations)"
}

func levelOr(l string) string {
	if l == "" {
		return "not assessed"
	}
	return l
}
