package catalog

import (
	"slices"
	"sort"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// Suggestion is a library entry matched to one component or flow, already
// filled in with the model's names.
type Suggestion struct {
	// From is what an accepted threat records: catalog:<catalog>/<entry>.
	From string `json:"from"`
	// Level is the risk the suggested threat would have with its default answers.
	Level        string             `json:"level"`
	Target       string             `json:"target"`
	TargetName   string             `json:"target_name"`
	Threat       model.Threat       `json:"threat"`
	Mitigations  []model.Mitigation `json:"mitigations"`
	Advice       map[string]string  `json:"advice,omitempty"`
	WhyItMatters string             `json:"why_it_matters"`
}

// Suggest matches catalogs against the model. Entries already accepted or
// dismissed for a target aren't suggested again. If target is set, only
// suggestions for that component or flow are returned.
func Suggest(m *model.Model, cats []Catalog, target string) []Suggestion {
	var out []Suggestion
	for _, c := range cats {
		for _, e := range c.Entries {
			from := "catalog:" + c.Name + "/" + e.ID
			// An entry can list alternative conditions; suggest it once per target.
			seen := map[string]bool{}
			add := func(s Suggestion) {
				if !seen[s.Target] {
					seen[s.Target] = true
					out = append(out, s)
				}
			}
			for _, ap := range e.Applies {
				if cc := ap.Component; cc != nil {
					for i := range m.Components {
						comp := &m.Components[i]
						if (target == "" || target == comp.ID) && matchComponent(m, cc, comp) && !considered(m, from, comp.ID) {
							add(fill(m, e, from, comp.ID, vars{component: comp.Name, data: dataName(m, handled(m, comp), wantsConfidential(cc)), zone: zoneName(m, comp.Zone)}, comp.Tech))
						}
					}
				}
				if ic := ap.Identity; ic != nil {
					for i := range m.Identities {
						idn := &m.Identities[i]
						users := identityUsers(m, idn.ID)
						if len(users) == 0 || (target != "" && target != idn.ID) || !matchIdentity(ic, idn, users) || consideredFor(m, from, users) {
							continue
						}
						first := m.Component(users[0])
						sg := fill(m, e, from, idn.ID, vars{component: first.Name, data: dataName(m, handled(m, first), true), zone: zoneName(m, first.Zone), identity: idn.Name}, nil)
						sg.TargetName = idn.Name
						sg.Threat.Affects = users
						add(sg)
					}
				}
				if fc := ap.Flow; fc != nil {
					for i := range m.Flows {
						f := &m.Flows[i]
						if (target == "" || target == f.ID) && matchFlow(m, fc, f) && !considered(m, from, f.ID) {
							dest := behind(m, m.Component(f.To))
							// Advice can be for either end: the caller's
							// language or the receiver's platform.
							tech := append(append([]string{}, dest.Tech...), m.Component(f.From).Tech...)
							add(fill(m, e, from, f.ID, vars{component: dest.Name, from: name(m, f.From), to: dest.Name, flow: f.ID, data: dataName(m, f.Carries, true), zone: zoneName(m, dest.Zone)}, tech))
						}
					}
				}
			}
		}
	}
	return dedupe(m, out)
}

// handled is the data a component stores, sends or receives.
func handled(m *model.Model, c *model.Component) []string {
	out := append([]string{}, c.Stores...)
	for _, f := range m.Flows {
		if f.From == c.ID || f.To == c.ID {
			out = append(out, f.Carries...)
		}
	}
	return out
}

// identityRights is "none" if the component has no identity in the model,
// "admin" if its identity has admin rights, and "scoped" otherwise.
func identityRights(m *model.Model, c *model.Component) string {
	idn := m.IdentityItem(c.Identity)
	if idn == nil {
		return "none"
	}
	for _, p := range idn.Can {
		if p.Do == "admin" {
			return "admin"
		}
	}
	return "scoped"
}

// duplicatesHandWritten reports whether the model already has a threat of
// the same kind on the target that says much the same thing, e.g. a
// hand-written "credential stuffing" threat when the library suggests one.
func duplicatesHandWritten(m *model.Model, kind, title string, targets []string) bool {
	words := titleWords(title)
	for _, t := range m.Threats {
		if t.Kind != kind || !overlaps(t.Affects, targets) {
			continue
		}
		other := titleWords(t.Title)
		shared := 0
		for w := range words {
			if other[w] {
				shared++
			}
		}
		// Jaccard similarity: shared words over all distinct words. Half
		// or more means the two titles describe the same threat.
		if union := len(words) + len(other) - shared; union > 0 && shared*2 >= union {
			return true
		}
	}
	return false
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

var stopWords = map[string]bool{"a": true, "an": true, "the": true, "could": true, "by": true, "to": true, "of": true, "in": true, "on": true, "and": true, "or": true, "if": true, "it": true, "its": true, "their": true, "they": true, "from": true, "with": true, "for": true, "is": true, "be": true, "that": true, "other": true, "someone": true, "anyone": true}

func titleWords(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') }) {
		if len(w) > 2 && !stopWords[w] {
			out[strings.TrimSuffix(w, "s")] = true
		}
	}
	return out
}

// identityUsers lists the components that run as an identity.
func identityUsers(m *model.Model, id string) []string {
	var out []string
	for _, c := range m.Components {
		if c.Identity == id {
			out = append(out, c.ID)
		}
	}
	return out
}

func matchIdentity(c *IdentityCond, idn *model.Identity, users []string) bool {
	if !anyOf(c.Kind, idn.Kind) {
		return false
	}
	if len(c.Can) > 0 {
		has := false
		for _, p := range idn.Can {
			has = has || slices.Contains(c.Can, p.Do)
		}
		if !has {
			return false
		}
	}
	return c.Shared == nil || *c.Shared == (len(users) > 1)
}

func consideredFor(m *model.Model, from string, targets []string) bool {
	for _, t := range targets {
		if considered(m, from, t) {
			return true
		}
	}
	return false
}

func boolState(b *bool, yes, no string) string {
	switch {
	case b == nil:
		return "unknown"
	case *b:
		return yes
	}
	return no
}

func dedupe(m *model.Model, in []Suggestion) []Suggestion {
	var out []Suggestion
	for _, s := range in {
		if !duplicatesHandWritten(m, s.Threat.Kind, s.Threat.Title, s.Threat.Affects) {
			out = append(out, s)
		}
	}
	return out
}

func considered(m *model.Model, from, target string) bool {
	for _, t := range m.Threats {
		if t.From == from && (len(t.Affects) == 0 || slices.Contains(t.Affects, target)) {
			return true
		}
	}
	return false
}

func anyOf(want []string, got ...string) bool {
	if len(want) == 0 {
		return true
	}
	for _, g := range got {
		if slices.Contains(want, g) {
			return true
		}
	}
	return false
}

func sensitivities(m *model.Model, ids []string) []string {
	var out []string
	for _, id := range ids {
		if d := m.DataItem(id); d != nil {
			out = append(out, d.Sensitivity)
		}
	}
	return out
}

func matchComponent(m *model.Model, c *ComponentCond, comp *model.Component) bool {
	z := m.Zone(comp.Zone)
	if len(c.ZoneTrust) > 0 && (z == nil || !slices.Contains(c.ZoneTrust, z.Trust)) {
		return false
	}
	if len(c.ZoneNetwork) > 0 {
		network := "open"
		if z.Segmented() {
			network = "segmented"
		}
		if z == nil || !slices.Contains(c.ZoneNetwork, network) {
			return false
		}
	}
	if len(c.ZoneEgress) > 0 {
		egress := "open"
		if z.EgressRestricted() {
			egress = "restricted"
		}
		if !slices.Contains(c.ZoneEgress, egress) {
			return false
		}
	}
	if len(c.AtRest) > 0 && !slices.Contains(c.AtRest, boolState(comp.EncryptedAtRest, "encrypted", "unencrypted")) {
		return false
	}
	if len(c.Monitoring) > 0 && !slices.Contains(c.Monitoring, boolState(comp.Monitored, "on", "off")) {
		return false
	}
	if len(c.Patching) > 0 {
		p := comp.Patching
		if p == "" {
			p = "unknown"
		}
		if !slices.Contains(c.Patching, p) {
			return false
		}
	}
	if c.NotManaged && comp.Managed != nil && *comp.Managed {
		return false
	}
	if len(c.Handles) > 0 && !anyOf(c.Handles, sensitivities(m, handled(m, comp))...) {
		return false
	}
	if len(c.IdentityRights) > 0 && !slices.Contains(c.IdentityRights, identityRights(m, comp)) {
		return false
	}
	if len(c.Stores) > 0 && !anyOf(c.Stores, sensitivities(m, comp.Stores)...) {
		return false
	}
	if len(c.Tech) > 0 && !anyOf(c.Tech, comp.Tech...) {
		return false
	}
	if len(c.Features) > 0 && !anyOf(c.Features, comp.Features...) {
		return false
	}
	if len(c.Tenancy) > 0 && !slices.Contains(c.Tenancy, tenancy(m)) {
		return false
	}
	exposure := comp.Exposure
	if exposure == "" {
		exposure = "unknown"
	}
	return anyOf(c.Kind, comp.Kind) && (len(c.Exposure) == 0 || slices.Contains(c.Exposure, exposure))
}

func tenancy(m *model.Model) string {
	if m.System.Tenancy == "" {
		return "unknown"
	}
	return m.System.Tenancy
}

// wantsConfidential reports whether an entry is about business data rather
// than credentials, so {data} names e.g. "customer invoices" instead of
// "AWS credentials".
func wantsConfidential(c *ComponentCond) bool {
	conds := append(append([]string{}, c.Stores...), c.Handles...)
	return len(conds) == 0 || slices.Contains(conds, "confidential")
}

// behind follows a flow through gateways: a client talking to a load
// balancer is really talking to the service behind it. It returns the
// component at the end of the chain (or to itself).
func behind(m *model.Model, to *model.Component) *model.Component {
	for hops := 0; to != nil && to.Kind == "gateway" && hops < 3; hops++ {
		var next []string
		for _, fl := range m.Flows {
			if fl.From == to.ID {
				next = append(next, fl.To)
			}
		}
		if len(next) != 1 {
			break
		}
		to = m.Component(next[0])
	}
	return to
}

var encryptedTransports = []string{"https", "tls", "ssl", "mtls", "ssh", "grpcs", "wss", "sftp", "ldaps", "imaps", "smtps"}

// TransitState is a flow's encryption: what the model says, or what its
// transport makes obvious (HTTPS, TLS, ...), or "unknown".
func TransitState(f *model.Flow) string {
	if f.Encrypted != nil {
		return boolState(f.Encrypted, "encrypted", "unencrypted")
	}
	if f.Auth == "mtls" {
		return "encrypted"
	}
	over := strings.ToLower(f.Over)
	for _, t := range encryptedTransports {
		if strings.Contains(over, t) {
			return "encrypted"
		}
	}
	return "unknown"
}

func matchFlow(m *model.Model, c *FlowCond, f *model.Flow) bool {
	from, to := m.Component(f.From), behind(m, m.Component(f.To))
	if from == nil || to == nil {
		return false
	}
	if c.CrossesZones != nil && *c.CrossesZones != m.CrossesZones(*f) {
		return false
	}
	if len(c.FromZoneTrust) > 0 {
		z := m.Zone(from.Zone)
		if z == nil || !slices.Contains(c.FromZoneTrust, z.Trust) {
			return false
		}
	}
	if len(c.Carries) > 0 && !anyOf(c.Carries, sensitivities(m, f.Carries)...) {
		return false
	}
	if len(c.Auth) > 0 && !anyOf(c.Auth, f.Auth) {
		return false
	}
	toExposure := to.Exposure
	if toExposure == "" {
		toExposure = "unknown"
	}
	if len(c.ToExposure) > 0 && !slices.Contains(c.ToExposure, toExposure) {
		return false
	}
	if len(c.ToFeatures) > 0 && !anyOf(c.ToFeatures, to.Features...) {
		return false
	}
	if len(c.Tenancy) > 0 && !slices.Contains(c.Tenancy, tenancy(m)) {
		return false
	}
	if len(c.InTransit) > 0 && !slices.Contains(c.InTransit, TransitState(f)) {
		return false
	}
	return anyOf(c.FromKind, from.Kind) && anyOf(c.ToKind, to.Kind)
}

func name(m *model.Model, id string) string {
	if c := m.Component(id); c != nil {
		return c.Name
	}
	return id
}

// dataName names the most sensitive data in ids, for use mid-sentence.
// With preferBusiness, confidential business data wins over secrets
// (credentials and keys), which read oddly in most titles.
func dataName(m *model.Model, ids []string, preferBusiness bool) string {
	best, rank := "data", -1
	for _, id := range ids {
		d := m.DataItem(id)
		if d == nil {
			continue
		}
		r := slices.Index(model.Sensitivities, d.Sensitivity)
		if preferBusiness && d.Sensitivity == "secret" {
			r = 0
		}
		if r > rank {
			best, rank = midSentence(d.Name), r
		}
	}
	return best
}

func midSentence(s string) string {
	if len(s) > 1 && strings.ToUpper(s[:2]) == s[:2] {
		return s // starts with an acronym, e.g. "AWS keys"
	}
	return strings.ToLower(s[:1]) + s[1:]
}

type vars struct{ component, from, to, flow, data, zone, identity string }

func (v vars) apply(s string) string {
	return strings.NewReplacer("{component}", v.component, "{from}", v.from, "{to}", v.to, "{flow}", v.flow, "{data}", v.data, "{zone}", v.zone, "{identity}", v.identity).Replace(s)
}

func zoneName(m *model.Model, zoneID string) string {
	if z := m.Zone(zoneID); z != nil {
		return z.Name
	}
	return "the network"
}

func fill(m *model.Model, e Entry, from, target string, v vars, tech []string) Suggestion {
	s := Suggestion{From: from, Target: target, TargetName: v.component, WhyItMatters: strings.TrimSpace(e.WhyItMatters)}
	_, s.Level = risk.Level(risk.Inputs{Who: e.Defaults.Who, Effort: e.Defaults.Effort, Impact: e.Defaults.Impact})
	if v.flow != "" {
		s.TargetName = v.from + " → " + v.to
	}
	id := slug(e.ID + "-" + target)
	t := model.Threat{
		ID: id, Title: v.apply(e.Title), Kind: e.Kind, Affects: []string{target},
		Who: e.Defaults.Who, Effort: e.Defaults.Effort, Impact: e.Defaults.Impact,
		Status: "open", From: from, Refs: e.Refs,
	}
	for _, step := range e.Attack {
		t.Attack = append(t.Attack, v.apply(step))
	}
	if e.Gives != nil {
		g := *e.Gives
		g.Reads = resolve(m, g.Reads, target, v)
		g.Changes = resolve(m, g.Changes, target, v)
		g.Controls = resolveComponents(g.Controls, target, m)
		if len(g.Reads)+len(g.Changes)+len(g.Controls) > 0 || g.Access != "" {
			t.Gives = &g
		}
	}
	for _, em := range e.Mitigations {
		// Each target gets its own mitigation, so marking it done for one
		// service doesn't quietly mitigate the same threat on another.
		mid := em.ID
		if m.Mitigation(mid) != nil {
			mid = slug(em.ID + "-" + target)
		}
		t.Mitigations = append(t.Mitigations, mid)
		s.Mitigations = append(s.Mitigations, model.Mitigation{ID: mid, Title: v.apply(em.Title), Status: "planned", Effect: em.Effect})
		for _, tag := range tech {
			if advice, ok := em.ByTech[tag]; ok {
				if s.Advice == nil {
					s.Advice = map[string]string{}
				}
				s.Advice[mid+"/"+tag] = advice
			}
		}
	}
	s.Threat = t
	return s
}

// resolve turns "{data}" in gives into the target's actual data IDs.
func resolve(m *model.Model, refs []string, target string, v vars) []string {
	var out []string
	for _, r := range refs {
		if r != "{data}" {
			continue
		}
		var ids []string
		if c := m.Component(target); c != nil {
			ids = c.Stores
		} else if f := m.Flow(target); f != nil {
			ids = f.Carries
		}
		out = append(out, ids...)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func resolveComponents(refs []string, target string, m *model.Model) []string {
	var out []string
	for _, r := range refs {
		switch r {
		case "{component}", "{to}":
			if c := m.Component(target); c != nil {
				out = append(out, c.ID)
			} else if f := m.Flow(target); f != nil {
				out = append(out, f.To)
			}
		}
	}
	return out
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	dash := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.TrimSuffix(b.String(), "-")
	if len(out) > 60 {
		out = strings.TrimSuffix(out[:60], "-")
	}
	return out
}
