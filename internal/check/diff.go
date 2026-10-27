package check

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// ModelChanges summarises how the model changed since the base ref, for the
// pull request comment and for reviewers.
type ModelChanges struct {
	Summary         string        `json:"summary"`
	ThreatsAdded    []ThreatRef   `json:"threats_added"`
	ThreatsRemoved  []ThreatRef   `json:"threats_removed"`
	RiskRaised      []RiskChange  `json:"risk_raised"`
	RiskLowered     []RiskChange  `json:"risk_lowered"`
	StatusChanged   []StatusShift `json:"status_changed"`
	MitigationsDone []string      `json:"mitigations_done"`
	// NeedsApproval lists the changes that lower risk; with a policy that
	// names approvers, one of them must approve the pull request.
	NeedsApproval []string `json:"needs_approval"`
	Approvers     []string `json:"approvers,omitempty"`
}

type ThreatRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Level string `json:"level,omitempty"`
}

type RiskChange struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

type StatusShift struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	From  string `json:"from"`
	To    string `json:"to"`
}

func (c *ModelChanges) empty() bool {
	return len(c.ThreatsAdded)+len(c.ThreatsRemoved)+len(c.RiskRaised)+len(c.RiskLowered)+len(c.StatusChanged)+len(c.MitigationsDone) == 0
}

// diffModels compares the base and current models. Risk-lowering changes are
// reported as findings: the change itself may be right, but a person should
// look at it, because it's the easiest way to make a threat model lie.
func (r *runner) diffModels(base, cur *model.Model) *ModelChanges {
	ch := &ModelChanges{}
	sev := SevWarning
	if r.opts.Strict || r.opts.Policy.Strict() {
		sev = SevError
	}
	var approvers []string
	if r.opts.Policy != nil {
		approvers = r.opts.Policy.Changes.Approvers
		ch.Approvers = approvers
	}
	hint := "Make sure a person agrees with this change."
	if len(approvers) > 0 {
		hint = "This needs approval from " + strings.Join(approvers, " or ") + "."
	}
	flag := func(code, id, msg string) {
		r.add(Finding{Severity: sev, Code: code, ID: id, Message: msg, Hint: hint})
		ch.NeedsApproval = append(ch.NeedsApproval, msg)
	}

	for i := range base.Threats {
		bt := &base.Threats[i]
		ct := cur.Threat(bt.ID)
		before := risk.Assess(base, bt)
		if ct == nil {
			ch.ThreatsRemoved = append(ch.ThreatsRemoved, ThreatRef{bt.ID, bt.Title, before.Level})
			if bt.Status != "not-applicable" {
				flag("threat-removed", bt.ID, fmt.Sprintf("Threat `%s` (%s) was removed from the model.", bt.ID, levelOr(before.Level)))
			}
			continue
		}
		after := risk.Assess(cur, ct)
		if bt.Status != ct.Status {
			ch.StatusChanged = append(ch.StatusChanged, StatusShift{ct.ID, ct.Title, bt.Status, ct.Status})
			switch ct.Status {
			case "not-applicable":
				flag("threat-dismissed", ct.ID, fmt.Sprintf("Threat `%s` (%s) was marked not applicable: %q.", ct.ID, levelOr(before.InherentLevel), ct.Reason))
			case "accepted":
				by := ""
				if ct.Accepted != nil {
					by = " by " + ct.Accepted.By
				}
				flag("risk-accepted", ct.ID, fmt.Sprintf("Threat `%s` (%s) was accepted as a risk%s.", ct.ID, levelOr(after.Level), by))
			}
		}
		if ct.Risk != nil && (bt.Risk == nil || *bt.Risk != *ct.Risk) {
			flag("risk-override", ct.ID, fmt.Sprintf("Threat `%s` now has its risk set by hand to %s: %q.", ct.ID, ct.Risk.Override, ct.Risk.Reason))
		}
		// Lowering the answers themselves (who/effort/impact), as opposed to
		// finishing a mitigation, is the quiet way to make a risk go away.
		if rb, ra := risk.Rank(before.InherentLevel), risk.Rank(after.InherentLevel); ra < rb && ra >= 0 {
			rc := RiskChange{ct.ID, ct.Title, before.InherentLevel, after.InherentLevel, "its who, effort or impact answers changed"}
			ch.RiskLowered = append(ch.RiskLowered, rc)
			flag("risk-lowered", ct.ID, fmt.Sprintf("Threat `%s` went from %s to %s because %s.", ct.ID, rc.From, rc.To, rc.Reason))
		} else if rb, ra := risk.Rank(before.Level), risk.Rank(after.Level); ra < rb && ra >= 0 {
			ch.RiskLowered = append(ch.RiskLowered, RiskChange{ct.ID, ct.Title, before.Level, after.Level, "a mitigation was finished"})
		} else if ra > rb && rb >= 0 {
			ch.RiskRaised = append(ch.RiskRaised, RiskChange{ct.ID, ct.Title, before.Level, after.Level, "the model changed"})
		}
	}
	for i := range cur.Threats {
		if base.Threat(cur.Threats[i].ID) == nil {
			t := &cur.Threats[i]
			ch.ThreatsAdded = append(ch.ThreatsAdded, ThreatRef{t.ID, t.Title, risk.Assess(cur, t).Level})
		}
	}
	for _, mt := range cur.Mitigations {
		bm := base.Mitigation(mt.ID)
		if mt.Status != "done" || bm != nil && bm.Status == "done" {
			continue
		}
		ch.MitigationsDone = append(ch.MitigationsDone, mt.ID)
		if len(mt.Evidence) == 0 || bm != nil && reflect.DeepEqual(bm.Evidence, mt.Evidence) && len(bm.Evidence) == 0 {
			flag("done-without-evidence", mt.ID, fmt.Sprintf("Mitigation `%s` was marked done without any evidence.", mt.ID))
		}
	}

	// A sign-off covers the model as it was reviewed. If the model changed
	// and the sign-off didn't, it no longer covers what's there.
	if cur.Signoff != nil && base.Signoff != nil && *cur.Signoff == *base.Signoff && !ch.empty() {
		sevS := SevWarning
		if r.opts.Policy != nil && r.opts.Policy.Require.Signoff {
			sevS = SevError
		}
		r.add(Finding{Severity: sevS, Code: "signoff-stale", Message: fmt.Sprintf("The model changed since %s signed it off on %s.", cur.Signoff.By, cur.Signoff.On),
			Hint: "Ask for a new review, then update `signoff`."})
	}
	ch.Summary = summarize2(ch)
	return ch
}

func levelOr(l string) string {
	if l == "" {
		return "not assessed"
	}
	return l
}

func summarize2(ch *ModelChanges) string {
	var parts []string
	add := func(n int, one, many string) {
		if n == 1 {
			parts = append(parts, one)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf(many, n))
		}
	}
	add(len(ch.ThreatsAdded), "+1 threat", "+%d threats")
	add(len(ch.ThreatsRemoved), "-1 threat", "-%d threats")
	add(len(ch.MitigationsDone), "1 mitigation done", "%d mitigations done")
	add(len(ch.RiskLowered), "1 risk lowered", "%d risks lowered")
	add(len(ch.RiskRaised), "1 risk raised", "%d risks raised")
	add(len(ch.StatusChanged), "1 status changed", "%d statuses changed")
	if len(parts) == 0 {
		return "No changes to threats or mitigations."
	}
	s := "This change to the threat model: " + strings.Join(parts, ", ") + "."
	if n := len(ch.NeedsApproval); n > 0 {
		s += fmt.Sprintf(" %d of these lower risk and need a person to agree.", n)
	}
	return s
}
