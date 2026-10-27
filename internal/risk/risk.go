// Package risk turns a threat's who/effort/impact into a risk level and a
// one-sentence explanation. The tables are part of the format spec; see
// docs/risk.md.
package risk

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/open-security-tooling/threat-model/internal/model"
)

var likelihoodTable = map[string]map[string]string{
	"anyone":     {"trivial": "likely", "moderate": "likely", "hard": "possible"},
	"any-user":   {"trivial": "likely", "moderate": "possible", "hard": "unlikely"},
	"insider":    {"trivial": "possible", "moderate": "unlikely", "hard": "unlikely"},
	"privileged": {"trivial": "unlikely", "moderate": "unlikely", "hard": "rare"},
	"physical":   {"trivial": "unlikely", "moderate": "unlikely", "hard": "rare"},
}

var riskTable = map[string]map[string]string{
	"likely":   {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"},
	"possible": {"low": "low", "medium": "medium", "high": "high", "critical": "critical"},
	"unlikely": {"low": "low", "medium": "low", "high": "medium", "critical": "high"},
	"rare":     {"low": "low", "medium": "low", "high": "low", "critical": "medium"},
}

// Levels are the risk levels from lowest to highest.
var Levels = []string{"low", "medium", "high", "critical"}

// Rank orders risk levels; unknown levels rank lowest.
func Rank(level string) int { return slices.Index(Levels, level) }

// Inputs are the three answers a risk level is computed from.
type Inputs struct {
	Who    string `json:"who"`
	Effort string `json:"effort"`
	Impact string `json:"impact"`
}

func (in Inputs) complete() bool { return in.Who != "" && in.Effort != "" && in.Impact != "" }

// Level computes likelihood and risk; both are "" if an input is missing.
func Level(in Inputs) (likelihood, level string) {
	if !in.complete() {
		return "", ""
	}
	likelihood = likelihoodTable[in.Who][in.Effort]
	return likelihood, riskTable[likelihood][in.Impact]
}

// Assessment is everything the tools show about a threat's risk.
type Assessment struct {
	ThreatID string `json:"threat"`
	Assessed bool   `json:"assessed"`
	// NotApplicable is set for threats marked not-applicable. They have no
	// risk level and are left out of risk-sorted lists.
	NotApplicable bool `json:"not_applicable,omitempty"`
	// Inherent is the risk from the threat's own answers.
	Inherent Inputs `json:"inherent"`
	// InherentLevel ignores mitigations; Level is the residual risk after
	// mitigations that are done; Planned is the risk once every linked
	// mitigation is done.
	InherentLevel string `json:"inherent_level,omitempty"`
	Level         string `json:"level,omitempty"`
	Planned       string `json:"planned,omitempty"`
	Likelihood    string `json:"likelihood,omitempty"`
	Residual      Inputs `json:"residual"`
	Eliminated    bool   `json:"eliminated,omitempty"`
	Detected      bool   `json:"detected,omitempty"`
	Override      bool   `json:"override,omitempty"`
	Why           string `json:"why"`
	// Changes describes what each mitigation does, e.g. "High → Low once ... is done".
	Changes []Change `json:"changes,omitempty"`
}

// Change is what one linked mitigation does to a threat's risk on its own,
// starting from the inherent risk.
type Change struct {
	MitigationID string `json:"mitigation"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	From         string `json:"from"`
	To           string `json:"to"`
	Effect       string `json:"effect"`
	// Summary says the change in words: "critical → high" for a mitigation
	// that's done, "critical → low once done" for one that isn't, or "no
	// change in risk".
	Summary string `json:"summary"`
}

// ChangeSummary describes a level change in words. done says whether the
// mitigation is already done.
func ChangeSummary(from, to string, done bool) string {
	switch {
	case from == "" || to == "":
		return "no risk level yet"
	case from == to:
		return "no change in risk"
	case done:
		return from + " → " + to
	}
	return from + " → " + to + " once done"
}

// Assess computes inherent, residual and planned risk for a threat.
func Assess(m *model.Model, t *model.Threat) Assessment {
	a := Assessment{ThreatID: t.ID, Inherent: Inputs{t.Who, t.Effort, t.Impact}}
	if t.Status == "not-applicable" {
		a.NotApplicable = true
		a.Why = "Not applicable: " + t.Reason
		return a
	}
	_, a.InherentLevel = Level(a.Inherent)

	done, all := a.Inherent, a.Inherent
	var doneElim, allElim, detected bool
	for _, mid := range t.Mitigations {
		mit := m.Mitigation(mid)
		if mit == nil || mit.Effect == nil {
			continue
		}
		all, allElim = apply(all, allElim, *mit.Effect)
		if mit.Status == "done" {
			done, doneElim = apply(done, doneElim, *mit.Effect)
			detected = detected || mit.Effect.Detects
		}
	}
	a.Residual, a.Eliminated, a.Detected = done, doneElim, detected
	a.Likelihood, a.Level = Level(done)
	if doneElim {
		a.Level = "low"
	}
	if _, p := Level(all); allElim {
		a.Planned = "low"
	} else {
		a.Planned = p
	}
	a.Assessed = a.Inherent.complete()

	if t.Risk != nil {
		a.Override, a.Level, a.Assessed = true, t.Risk.Override, true
		a.Why = fmt.Sprintf("%s (set by hand): %s", title(t.Risk.Override), t.Risk.Reason)
	} else {
		a.Why = explain(m, t, a)
	}
	a.Changes = changes(m, t, a.Inherent)
	return a
}

func apply(in Inputs, elim bool, e model.Effect) (Inputs, bool) {
	if e.Eliminates {
		return in, true
	}
	// An effect only ever makes things better; a mitigation that claims to
	// widen access or raise impact is ignored rather than trusted.
	if e.Who != "" && slices.Index(model.WhoLevels, e.Who) > slices.Index(model.WhoLevels, in.Who) {
		in.Who = e.Who
	}
	if e.Effort != "" && slices.Index(model.Efforts, e.Effort) > slices.Index(model.Efforts, in.Effort) {
		in.Effort = e.Effort
	}
	if e.Impact != "" && (in.Impact == "" || slices.Index(model.Impacts, e.Impact) < slices.Index(model.Impacts, in.Impact)) {
		in.Impact = e.Impact
	}
	return in, elim
}

func changes(m *model.Model, t *model.Threat, inherent Inputs) []Change {
	_, from := Level(inherent)
	var out []Change
	for _, mid := range t.Mitigations {
		mit := m.Mitigation(mid)
		if mit == nil || mit.Effect == nil {
			continue
		}
		in, elim := apply(inherent, false, *mit.Effect)
		_, to := Level(in)
		if elim {
			to = "low"
		}
		out = append(out, Change{MitigationID: mit.ID, Title: mit.Title, Status: mit.Status, From: from, To: to,
			Effect: EffectText(*mit.Effect), Summary: ChangeSummary(from, to, mit.Status == "done")})
	}
	return out
}

// EffectText says what a mitigation's effect does, e.g. "it becomes much
// harder".
func EffectText(e model.Effect) string {
	switch {
	case e.Eliminates:
		return "makes this impossible"
	case e.Detects:
		return "lets you notice it happening"
	}
	var parts []string
	if e.Who != "" {
		parts = append(parts, "only "+whoPhrase[e.Who]+" could do it")
	}
	if e.Effort != "" {
		parts = append(parts, "it becomes "+effortWord[e.Effort])
	}
	if e.Impact != "" {
		parts = append(parts, "the damage drops to "+e.Impact)
	}
	return strings.Join(parts, " and ")
}

var whoPhrase = map[string]string{
	"anyone":     "anyone on the internet",
	"any-user":   "anyone with an account",
	"insider":    "someone on the inside",
	"privileged": "an admin or someone with production access",
	"physical":   "someone with the device in their hands",
}

var whoSubject = map[string]string{
	"anyone":     "anyone on the internet could do it",
	"any-user":   "anyone who signs up could do it",
	"insider":    "someone on the inside could do it",
	"privileged": "only an admin or someone with production access could do it",
	"physical":   "only someone with the device in their hands could do it",
}

var effortPhrase = map[string]string{
	"trivial":  "in minutes, with no special skill",
	"moderate": "with some skill and time",
	"hard":     ", but it takes rare access or deep expertise",
}

var effortWord = map[string]string{"trivial": "trivial", "moderate": "harder", "hard": "much harder"}

var impactPhrase = map[string]string{
	"low":      "the damage is minor",
	"medium":   "it would hurt some users or cause a recoverable outage",
	"high":     "it would seriously hurt many users or the business",
	"critical": "everything is at stake",
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// explain builds the "why this risk" sentence from the residual inputs.
func explain(m *model.Model, t *model.Threat, a Assessment) string {
	if !a.Assessed {
		var missing []string
		for _, f := range []struct{ n, v string }{{"who could do it", t.Who}, {"how hard it is", t.Effort}, {"how bad it is", t.Impact}} {
			if f.v == "" {
				missing = append(missing, f.n)
			}
		}
		return "Not assessed yet: say " + strings.Join(missing, ", ") + "."
	}
	if a.Eliminated {
		return "Low: a mitigation that's done makes this impossible."
	}
	in := a.Residual
	impact := impactPhrase[in.Impact]
	if note := strings.TrimSpace(t.ImpactNote); note != "" && in.Impact == t.Impact {
		impact = lowerFirst(strings.TrimRight(note, ". "))
	}
	effort := effortPhrase[in.Effort]
	if !strings.HasPrefix(effort, ",") {
		effort = " " + effort
	}
	s := fmt.Sprintf("%s, because %s%s; the impact is %s: %s.", title(a.Level), whoSubject[in.Who], effort, in.Impact, impact)
	if a.Level != a.InherentLevel && a.InherentLevel != "" {
		s += fmt.Sprintf(" (It was %s before the mitigations that are done.)", a.InherentLevel)
	}
	if a.Detected {
		s += " You'd find out if it happened."
	}
	if a.Planned != "" && a.Planned != a.Level {
		s += fmt.Sprintf(" Drops to %s once the planned mitigations are done.", a.Planned)
	}
	return s
}

// lowerFirst lowercases the first letter of a note spliced in mid-sentence,
// unless it starts an acronym or name like "AWS", "S3" or "I".
func lowerFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError || !unicode.IsUpper(r) {
		return s
	}
	next, _ := utf8.DecodeRuneInString(s[n:])
	if unicode.IsUpper(next) || unicode.IsDigit(next) {
		return s // "AWS credentials", "S3 bucket"
	}
	if r != 'A' && (n == len(s) || !unicode.IsLetter(next) && next != '\'') {
		return s // a one-letter word such as "I"
	}
	return string(unicode.ToLower(r)) + s[n:]
}
