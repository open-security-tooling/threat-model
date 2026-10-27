package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// mitigationCard is `threat explain <mitigation-id>`. It is built here from
// ops.Show; ops.Explain only takes threats so far.
type mitigationCard struct {
	Mitigation model.Mitigation `json:"mitigation"`
	// Effect is the effect in words, empty if the mitigation has none.
	Effect  string          `json:"effect,omitempty"`
	Threats []coveredThreat `json:"threats"`
	Line    int             `json:"line,omitempty"`
}

type coveredThreat struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	// Level is the threat's current (residual) risk.
	Level string `json:"level,omitempty"`
	// From and To are the threat's risk before and with this mitigation alone.
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Summary string `json:"summary"`

	label string
}

func buildMitigationCard(v ops.View, id string) (mitigationCard, bool) {
	m := v.Model
	mt := m.Mitigation(id)
	if mt == nil {
		return mitigationCard{}, false
	}
	card := mitigationCard{Mitigation: *mt, Threats: []coveredThreat{}, Line: v.Lines[mt.ID]}
	if mt.Effect != nil {
		card.Effect = risk.EffectText(*mt.Effect)
	}
	for _, t := range m.Threats {
		if !slices.Contains(t.Mitigations, mt.ID) {
			continue
		}
		a := v.Risks[t.ID]
		ct := coveredThreat{ID: t.ID, Title: t.Title, Status: t.Status, Level: a.Level, label: riskLabel(a)}
		switch {
		case a.NotApplicable:
			ct.Summary = "doesn't apply"
		case mt.Effect == nil:
			ct.Summary = "no effect set, so no change in risk"
		default:
			for _, c := range a.Changes {
				if c.MitigationID == mt.ID {
					ct.From, ct.To, ct.Summary = c.From, c.To, c.Summary
				}
			}
			if ct.Summary == "" {
				ct.Summary = risk.ChangeSummary(ct.From, ct.To, mt.Status == "done")
			}
		}
		card.Threats = append(card.Threats, ct)
	}
	return card, true
}

func explainMitigation(f *flags, path string, src []byte, id string) int {
	v, err := ops.Show(src)
	if err != nil {
		var oe *ops.Error
		if errors.As(err, &oe) {
			printDiagnostics(path, oe.Diagnostics)
		}
		fail(err)
		return exitUsage
	}
	card, _ := buildMitigationCard(v, id)
	if f.json {
		printJSON(card)
		return exitOK
	}
	mt := card.Mitigation
	fmt.Printf("[%s] %s\n", statusMark[mt.Status], bold(mt.Title))
	meta := []string{mt.ID, mt.Status}
	if mt.Owner != "" {
		meta = append(meta, "owner "+mt.Owner)
	}
	if mt.Due != "" {
		meta = append(meta, "due "+mt.Due)
	}
	fmt.Println("    " + dim(strings.Join(meta, " · ")))

	if card.Effect != "" {
		fmt.Printf("\n%s %s\n", bold("What it changes:"), card.Effect+".")
	} else {
		fmt.Printf("\n%s not said yet. Add `effect` (e.g. `effect: {effort: hard}`) so the risk can be recalculated.\n", bold("What it changes:"))
	}

	fmt.Println("\n" + bold("Evidence"))
	if len(mt.Evidence) == 0 {
		hint := "none yet."
		if mt.Status == "done" {
			hint = "none. Add `evidence` (prefer a `test:`) so `threat check` can confirm the fix is still there."
		}
		fmt.Println("  " + hint)
	}
	for _, ev := range mt.Evidence {
		fmt.Printf("  %s: %s\n", ev.Type, ev.Target)
	}

	fmt.Println("\n" + bold("Threats it covers"))
	if len(card.Threats) == 0 {
		fmt.Println("  None yet. Add its ID to a threat's `mitigations` list.")
	}
	w := 0
	for _, t := range card.Threats {
		w = max(w, visibleWidth(t.label))
	}
	for _, t := range card.Threats {
		fmt.Printf("  %s  %s %s\n", pad(t.label, w), t.Title, dim(fmt.Sprintf("(%s, %s: %s)", t.ID, t.Status, t.Summary)))
	}
	if mt.Notes != "" {
		fmt.Printf("\n%s %s\n", bold("Notes:"), mt.Notes)
	}
	return exitOK
}
