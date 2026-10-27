// Package sim simulates an attacker moving through a model by chaining open
// threats: attack paths to sensitive data, the blast radius of a compromised
// component, and which fixes break the most paths. See docs/simulation.md.
//
// The attacker's position only ever grows (more access, more components
// controlled, more data read), so the search is a fixpoint over facts. Each
// fact remembers the threat that first produced it, which is how paths are
// explained step by step.
package sim

import (
	"fmt"
	"slices"
	"sort"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// Access levels in increasing order of power. "physical" is separate and
// only held when the simulation starts with it.
var accessOrder = []string{"anyone", "any-user", "insider", "privileged"}

func rank(who string) int { return slices.Index(accessOrder, who) }

type factKind string

const (
	factAccess   factKind = "access"
	factControls factKind = "controls"
	factReads    factKind = "reads"
	factChanges  factKind = "changes"
)

type fact struct {
	Kind factKind
	ID   string
}

// Step is one link in an attack path.
type Step struct {
	ThreatID string   `json:"threat,omitempty"`
	Title    string   `json:"title"`
	Effort   string   `json:"effort,omitempty"`
	Gains    []string `json:"gains"`
	// Rule is set for steps that follow from the model's structure rather
	// than a threat, e.g. "controlling a component reads what it stores".
	Rule string `json:"rule,omitempty"`
}

type Path struct {
	Target     string `json:"target"`
	TargetName string `json:"target_name"`
	Steps      []Step `json:"steps"`
	// Weakest is the hardest step's effort; paths of only trivial steps
	// are the most urgent.
	Weakest string `json:"weakest"`
	// Exit says how the data leaves; Contained means nothing lets it out.
	Exit      string `json:"exit"`
	Contained bool   `json:"contained,omitempty"`
}

type FixImpact struct {
	MitigationID string `json:"mitigation"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	// Breaks lists data the attacker could no longer reach at all.
	Breaks []string `json:"breaks"`
	// Harder lists data still reachable, but only through harder steps.
	Harder []string `json:"harder"`
}

type Result struct {
	From        string      `json:"from"`
	Paths       []Path      `json:"paths"`
	Unreachable []string    `json:"unreachable"`
	Fixes       []FixImpact `json:"fixes"`
}

// Start describes where the attacker begins: an access level, or control
// of a component ("controls:<id>").
type Start struct {
	Access   string
	Controls string
}

func (s Start) String() string {
	if s.Controls != "" {
		return "controls:" + s.Controls
	}
	return s.Access
}

// ParseStart reads "anyone", "any-user", ..., or "controls:<component>".
func ParseStart(m *model.Model, s string) (Start, error) {
	if id, ok := cut(s, "controls:"); ok {
		if m.Component(id) == nil {
			return Start{}, fmt.Errorf("there's no component %q", id)
		}
		return Start{Controls: id}, nil
	}
	if s == "physical" || rank(s) >= 0 {
		return Start{Access: s}, nil
	}
	return Start{}, fmt.Errorf("start from one of anyone, any-user, insider, privileged, physical, or controls:<component>")
}

func cut(s, prefix string) (string, bool) {
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

// Paths finds how an attacker starting at start could reach each target
// (data IDs). With no targets, every confidential or secret data item is a
// target.
func Paths(m *model.Model, start Start, targets []string) Result {
	if len(targets) == 0 {
		for _, d := range m.Data {
			if d.Sensitivity == "confidential" || d.Sensitivity == "secret" {
				targets = append(targets, d.ID)
			}
		}
	}
	res := Result{From: start.String(), Paths: []Path{}, Unreachable: []string{}, Fixes: []FixImpact{}}
	s := run(m, start, nil)
	reached := map[string]bool{}
	for _, t := range targets {
		if p, ok := s.path(fact{factReads, t}); ok {
			p.Target, p.TargetName = t, dataName(m, t)
			p.Exit, p.Contained = s.exit(fact{factReads, t})
			res.Paths = append(res.Paths, p)
			reached[t] = true
		} else {
			res.Unreachable = append(res.Unreachable, t)
		}
	}
	sort.SliceStable(res.Paths, func(i, j int) bool {
		if res.Paths[i].Contained != res.Paths[j].Contained {
			return !res.Paths[i].Contained
		}
		ei, ej := slices.Index(model.Efforts, res.Paths[i].Weakest), slices.Index(model.Efforts, res.Paths[j].Weakest)
		if ei != ej {
			return ei < ej
		}
		return len(res.Paths[i].Steps) < len(res.Paths[j].Steps)
	})

	// Which mitigations, if done, would cut paths?
	for _, mt := range m.Mitigations {
		if mt.Status == "done" {
			continue
		}
		after := run(m, start, &mt.ID)
		breaks, harder := []string{}, []string{}
		for _, p := range res.Paths {
			if !reached[p.Target] {
				continue
			}
			np, ok := after.path(fact{factReads, p.Target})
			switch {
			case !ok:
				breaks = append(breaks, p.Target)
			case slices.Index(model.Efforts, np.Weakest) > slices.Index(model.Efforts, p.Weakest):
				harder = append(harder, p.Target)
			}
		}
		if len(breaks)+len(harder) > 0 {
			res.Fixes = append(res.Fixes, FixImpact{MitigationID: mt.ID, Title: mt.Title, Status: mt.Status, Breaks: breaks, Harder: harder})
		}
	}
	sort.SliceStable(res.Fixes, func(i, j int) bool {
		if len(res.Fixes[i].Breaks) != len(res.Fixes[j].Breaks) {
			return len(res.Fixes[i].Breaks) > len(res.Fixes[j].Breaks)
		}
		return len(res.Fixes[i].Harder) > len(res.Fixes[j].Harder)
	})
	return res
}

// Blast is everything an attacker who controls one component could reach.
// AlreadyReachable lists the parts anyone on the internet could reach
// anyway, so the view can show what compromising this component adds.
type Blast struct {
	Component        string            `json:"component"`
	Reads            []string          `json:"reads"`
	Changes          []string          `json:"changes"`
	Controls         []string          `json:"controls"`
	AlreadyReachable []string          `json:"already_reachable"`
	Names            map[string]string `json:"names"`
	Paths            []Path            `json:"paths"`
}

// BlastRadius computes what controlling a component lets an attacker reach.
func BlastRadius(m *model.Model, component string) Blast {
	s := run(m, Start{Controls: component}, nil)
	baseline := run(m, Start{Access: "anyone"}, nil)
	b := Blast{Component: component, Reads: []string{}, Changes: []string{}, Controls: []string{}, AlreadyReachable: []string{}, Names: map[string]string{}, Paths: []Path{}}
	already := map[string]bool{}
	for f := range s.facts {
		var list *[]string
		switch f.Kind {
		case factReads:
			list = &b.Reads
		case factChanges:
			list = &b.Changes
		case factControls:
			if f.ID == component {
				continue
			}
			list = &b.Controls
		default:
			continue
		}
		*list = append(*list, f.ID)
		b.Names[f.ID] = targetName(m, f.ID)
		if baseline.has(f) && !already[f.ID] {
			already[f.ID] = true
			b.AlreadyReachable = append(b.AlreadyReachable, f.ID)
		}
	}
	b.Names[component] = name(m, component)
	for _, l := range []*[]string{&b.Reads, &b.Changes, &b.Controls, &b.AlreadyReachable} {
		sort.Strings(*l)
	}
	for _, d := range b.Reads {
		if p, ok := s.path(fact{factReads, d}); ok {
			p.Target, p.TargetName = d, dataName(m, d)
			p.Exit, p.Contained = s.exit(fact{factReads, d})
			b.Paths = append(b.Paths, p)
		}
	}
	return b
}

// --- the search ---

type provenance struct {
	step  Step
	needs []fact
}

type state struct {
	m      *model.Model
	facts  map[fact]*provenance
	start  Start
	skip   *string // mitigation to treat as done (what-if)
	access int
	phys   bool
}

func (s *state) has(f fact) bool { _, ok := s.facts[f]; return ok }

func (s *state) add(f fact, p *provenance) bool {
	if s.has(f) {
		return false
	}
	s.facts[f] = p
	if f.Kind == factAccess && rank(f.ID) > s.access {
		s.access = rank(f.ID)
	}
	return true
}

func run(m *model.Model, start Start, whatIfDone *string) *state {
	s := &state{m: m, facts: map[fact]*provenance{}, start: start, skip: whatIfDone, access: -1}
	switch {
	case start.Controls != "":
		s.add(fact{factControls, start.Controls}, &provenance{step: Step{Title: "Start: the attacker controls " + name(m, start.Controls), Rule: "start"}})
		s.add(fact{factAccess, "anyone"}, &provenance{step: Step{Title: "Start", Rule: "start"}})
	case start.Access == "physical":
		s.phys = true
		s.add(fact{factAccess, "anyone"}, &provenance{step: Step{Title: "Start: someone with the device in their hands", Rule: "start"}})
	default:
		s.add(fact{factAccess, start.Access}, &provenance{step: Step{Title: "Start: " + startText[start.Access], Rule: "start"}})
	}
	// Anyone can usually sign up, if the system has user accounts at all.
	if s.access == rank("anyone") && hasUserAccounts(m) {
		s.add(fact{factAccess, "any-user"}, &provenance{
			step:  Step{Title: "Sign up for an account", Effort: "trivial", Gains: []string{"has an account"}, Rule: "signup"},
			needs: []fact{{factAccess, "anyone"}},
		})
	}
	for changed := true; changed; {
		changed = s.applyRules()
		for i := range m.Threats {
			if s.applyThreat(&m.Threats[i]) {
				changed = true
			}
		}
	}
	return s
}

var startText = map[string]string{
	"anyone": "anyone on the internet", "any-user": "a logged-in user", "insider": "someone on the inside", "privileged": "an admin",
}

func hasUserAccounts(m *model.Model) bool {
	for _, a := range m.Actors {
		if a.Access == "any-user" {
			return true
		}
	}
	return false
}

// applyRules derives facts from the model's structure.
func (s *state) applyRules() bool {
	m, changed := s.m, false
	// Visit facts in a fixed order so the same model always gives the same paths.
	var controlled []fact
	for f := range s.facts {
		if f.Kind == factControls {
			controlled = append(controlled, f)
		}
	}
	sort.Slice(controlled, func(i, j int) bool { return controlled[i].ID < controlled[j].ID })
	for _, f := range controlled {
		c := m.Component(f.ID)
		if c == nil {
			continue
		}
		for _, d := range c.Stores {
			if s.add(fact{factReads, d}, &provenance{step: Step{Title: name(m, c.ID) + " stores " + dataName(m, d), Gains: []string{"reads " + dataName(m, d)}, Rule: "stores"}, needs: []fact{f}}) {
				changed = true
			}
		}
		for _, fl := range m.Flows {
			if fl.From != c.ID && fl.To != c.ID {
				continue
			}
			for _, d := range fl.Carries {
				// Credentials used to sign requests (cloud IAM, mutual TLS)
				// aren't handed to the receiver, so it can't read them.
				if fl.To == c.ID && (fl.Auth == "iam" || fl.Auth == "mtls") {
					if di := m.DataItem(d); di != nil && di.Sensitivity == "secret" {
						continue
					}
				}
				if s.add(fact{factReads, d}, &provenance{step: Step{Title: fmt.Sprintf("%s sends or receives %s (%s)", name(m, c.ID), dataName(m, d), fl.ID), Gains: []string{"reads " + dataName(m, d)}, Rule: "flow"}, needs: []fact{f}}) {
					changed = true
				}
			}
		}
		// The attacker can do whatever the component's identity is allowed to.
		if idn := m.IdentityItem(c.Identity); idn != nil {
			for _, perm := range idn.Can {
				for _, g := range permissionGains(m, perm) {
					step := Step{Title: fmt.Sprintf("%s runs as %s, which can %s %s", name(m, c.ID), idn.Name, perm.Do, targetName(m, perm.On)), Gains: []string{describe(m, g)}, Rule: "identity"}
					if s.add(g, &provenance{step: step, needs: []fact{f}}) {
						changed = true
					}
				}
			}
		}
		// Controlling something inside a trusted, flat network puts you on
		// the inside. Segmentation is what stops this.
		if z := m.Zone(c.Zone); z != nil && z.Trust == "trusted" && !z.Segmented() {
			if s.add(fact{factAccess, "insider"}, &provenance{step: Step{Title: "Running code inside " + z.Name, Gains: []string{"is on the inside"}, Rule: "zone"}, needs: []fact{f}}) {
				changed = true
			}
		}
	}
	return changed
}

func (s *state) mitigationDone(id string) bool {
	if s.skip != nil && *s.skip == id {
		return true
	}
	mt := s.m.Mitigation(id)
	return mt != nil && mt.Status == "done"
}

// effective returns a threat's who and effort after done mitigations, and
// whether it's been made impossible.
func (s *state) effective(t *model.Threat) (who, effort string, eliminated bool) {
	in := risk.Inputs{Who: t.Who, Effort: t.Effort, Impact: t.Impact}
	for _, mid := range t.Mitigations {
		mt := s.m.Mitigation(mid)
		if mt == nil || mt.Effect == nil || !s.mitigationDone(mid) {
			continue
		}
		e := mt.Effect
		if e.Eliminates {
			return "", "", true
		}
		if e.Who != "" && rank(e.Who) > rank(in.Who) {
			in.Who = e.Who
		}
		if e.Effort != "" && slices.Index(model.Efforts, e.Effort) > slices.Index(model.Efforts, in.Effort) {
			in.Effort = e.Effort
		}
	}
	return in.Who, in.Effort, false
}

func (s *state) applyThreat(t *model.Threat) bool {
	if t.Status != "open" && t.Status != "accepted" || t.Gives == nil {
		return false
	}
	who, effort, eliminated := s.effective(t)
	if eliminated {
		return false
	}
	reach, foothold, ok := s.reachable(t)
	if !ok {
		return false
	}
	var needs []fact
	switch {
	case who == "physical":
		if !s.phys {
			return false
		}
	case who == "":
		return false
	case rank(who) <= s.access:
		needs = append(needs, fact{factAccess, s.levelFact(who)})
	case foothold && rank(who) <= rank("insider"):
		// Code running on a component that can reach the target is "on the
		// network" for it, which is what insider-level threats require.
	default:
		return false
	}
	needs = append(needs, reach...)

	g, m := t.Gives, s.m
	var gains []fact
	for _, d := range g.Reads {
		gains = append(gains, fact{factReads, d})
	}
	for _, d := range g.Changes {
		gains = append(gains, fact{factChanges, d})
	}
	for _, c := range g.Controls {
		gains = append(gains, fact{factControls, c})
	}
	if g.Access != "" && rank(g.Access) > s.access {
		gains = append(gains, fact{factAccess, g.Access})
	}
	var labels []string
	for _, f := range gains {
		if !s.has(f) {
			labels = append(labels, describe(m, f))
		}
	}
	if len(labels) == 0 {
		return false
	}
	p := &provenance{step: Step{ThreatID: t.ID, Title: t.Title, Effort: effort, Gains: labels}, needs: needs}
	changed := false
	for _, f := range gains {
		if s.add(f, p) {
			changed = true
		}
	}
	return changed
}

// levelFact returns the held access fact that satisfies who.
func (s *state) levelFact(who string) string {
	best := ""
	for f := range s.facts {
		if f.Kind == factAccess && rank(f.ID) >= rank(who) && (best == "" || rank(f.ID) < rank(best)) {
			best = f.ID
		}
	}
	return best
}

// reachable reports whether the attacker can get at one of the threat's
// targets, which held facts make that possible, and whether it's through a
// foothold (a controlled component that can reach the target).
func (s *state) reachable(t *model.Threat) (needs []fact, foothold, ok bool) {
	m := s.m
	for _, a := range t.Affects {
		comps := []string{a}
		if f := m.Flow(a); f != nil {
			comps = []string{f.From, f.To}
		}
		for _, cid := range comps {
			c := m.Component(cid)
			if c == nil {
				continue
			}
			if s.has(fact{factControls, cid}) {
				return []fact{{factControls, cid}}, true, true
			}
			if exposedToOutsiders(m, c) {
				return nil, false, true
			}
			z := m.Zone(c.Zone)
			if !z.Segmented() {
				if s.access >= rank("insider") {
					return []fact{{factAccess, s.levelFact("insider")}}, false, true
				}
				// On a flat network, a foothold anywhere in the zone reaches everything in it.
				if f, ok := s.controlsIn(c.Zone); ok {
					return []fact{{factControls, f}}, true, true
				}
			}
			// A controlled component whose identity has rights on the target reaches it.
			if via, ok := s.identityReaches(cid); ok {
				return []fact{{factControls, via}}, true, true
			}
			for _, fl := range m.Flows {
				var other string
				switch {
				case fl.To == cid:
					other = fl.From
				case fl.From == cid:
					other = fl.To
				default:
					continue
				}
				if s.has(fact{factControls, other}) {
					return []fact{{factControls, other}}, true, true
				}
				// Data passed along by an exposed component reaches its neighbours.
				if oc := m.Component(other); oc != nil && exposedToOutsiders(m, oc) {
					return nil, false, true
				}
			}
		}
	}
	return nil, false, false
}

// permissionGains turns one permission into facts.
func permissionGains(m *model.Model, p model.Permission) []fact {
	var data []string
	if d := m.DataItem(p.On); d != nil {
		data = []string{d.ID}
	} else if c := m.Component(p.On); c != nil {
		data = c.Stores
	}
	var out []fact
	switch p.Do {
	case "read":
		for _, d := range data {
			out = append(out, fact{factReads, d})
		}
	case "write":
		for _, d := range data {
			out = append(out, fact{factChanges, d})
		}
	case "admin":
		if m.Component(p.On) != nil {
			out = append(out, fact{factControls, p.On})
		}
		for _, d := range data {
			out = append(out, fact{factReads, d}, fact{factChanges, d})
		}
	}
	return out
}

// identityReaches returns a controlled component whose identity has any
// permission on target.
func (s *state) identityReaches(target string) (string, bool) {
	var ids []string
	for f := range s.facts {
		if f.Kind != factControls {
			continue
		}
		c := s.m.Component(f.ID)
		if c == nil {
			continue
		}
		if idn := s.m.IdentityItem(c.Identity); idn != nil {
			for _, p := range idn.Can {
				if p.On == target {
					ids = append(ids, c.ID)
				}
			}
		}
	}
	if len(ids) == 0 {
		return "", false
	}
	sort.Strings(ids)
	return ids[0], true
}

func targetName(m *model.Model, id string) string {
	if d := m.DataItem(id); d != nil {
		return d.Name
	}
	return name(m, id)
}

// exit says how data the attacker reads actually leaves the system, or that
// it's contained because nothing lets it out.
func (s *state) exit(f fact) (how string, contained bool) {
	p := s.facts[f]
	if p == nil {
		return "", false
	}
	if p.step.Rule == "" || len(p.needs) == 0 || p.needs[0].Kind != factControls {
		return "The attacker receives it directly.", false
	}
	m := s.m
	c := m.Component(p.needs[0].ID)
	if c == nil {
		return "", false
	}
	if exposedToOutsiders(m, c) {
		return fmt.Sprintf("Sent back out through %s, which is reachable from the internet.", c.Name), false
	}
	z := m.Zone(c.Zone)
	if !z.EgressRestricted() {
		return fmt.Sprintf("Sent out by %s, which can connect anywhere on the internet.", c.Name), false
	}
	for _, fl := range m.Flows {
		if fl.From != c.ID {
			continue
		}
		if to := m.Component(fl.To); to != nil {
			if tz := m.Zone(to.Zone); to.Kind == "third-party" || tz != nil && tz.Trust != "trusted" {
				return fmt.Sprintf("Sent out over %s to %s, which outbound restrictions allow.", fl.ID, to.Name), false
			}
		}
	}
	return fmt.Sprintf("Contained: %s can read it, but outbound traffic from %s is restricted and none of its flows leave the network.", c.Name, z.Name), true
}

// controlsIn returns a component the attacker controls in the given zone.
func (s *state) controlsIn(zone string) (string, bool) {
	if zone == "" {
		return "", false
	}
	var ids []string
	for f := range s.facts {
		if f.Kind == factControls {
			if c := s.m.Component(f.ID); c != nil && c.Zone == zone {
				ids = append(ids, f.ID)
			}
		}
	}
	if len(ids) == 0 {
		return "", false
	}
	sort.Strings(ids)
	return ids[0], true
}

func exposedToOutsiders(m *model.Model, c *model.Component) bool {
	if c.Exposure == "internet" {
		return true
	}
	z := m.Zone(c.Zone)
	return z != nil && z.Trust == "untrusted"
}

// path reconstructs the steps that produced f, in order.
func (s *state) path(target fact) (Path, bool) {
	if !s.has(target) {
		return Path{}, false
	}
	var steps []Step
	seen := map[*provenance]bool{}
	var visit func(f fact)
	visit = func(f fact) {
		p := s.facts[f]
		if p == nil || seen[p] {
			return
		}
		seen[p] = true
		for _, n := range p.needs {
			visit(n)
		}
		if p.step.Rule != "start" {
			steps = append(steps, p.step)
		}
	}
	visit(target)
	weakest := "trivial"
	for _, st := range steps {
		if slices.Index(model.Efforts, st.Effort) > slices.Index(model.Efforts, weakest) {
			weakest = st.Effort
		}
	}
	return Path{Steps: steps, Weakest: weakest}, true
}

func name(m *model.Model, id string) string {
	if c := m.Component(id); c != nil {
		return c.Name
	}
	return id
}

func dataName(m *model.Model, id string) string {
	if d := m.DataItem(id); d != nil {
		return d.Name
	}
	return id
}

func describe(m *model.Model, f fact) string {
	switch f.Kind {
	case factReads:
		return "reads " + dataName(m, f.ID)
	case factChanges:
		return "changes " + dataName(m, f.ID)
	case factControls:
		return "controls " + name(m, f.ID)
	}
	return "has " + f.ID + " access"
}
