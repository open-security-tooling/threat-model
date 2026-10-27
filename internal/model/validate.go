package model

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Validate checks references between items and the rules that span them.
// Call it on a document Parse returned without errors.
func Validate(doc *Document) Diagnostics {
	v := &validator{doc: doc, m: doc.Model, ids: map[string]string{}}
	v.run()
	return v.diags
}

type validator struct {
	doc   *Document
	m     *Model
	ids   map[string]string // id -> section
	diags Diagnostics
}

func (v *validator) add(sev, code, p, msg, hint string) {
	v.diags = append(v.diags, Diagnostic{Severity: sev, Code: code, Path: p, Line: v.doc.Line(p), Message: msg, Hint: hint})
}

func idx(section string, i int) string { return section + "[" + strconv.Itoa(i) + "]" }

func (v *validator) idsIn(sections ...string) []string {
	var out []string
	for id, s := range v.ids {
		if slices.Contains(sections, s) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// ref checks that id names an item in one of the given sections.
func (v *validator) ref(p, who, field, id string, sections ...string) {
	if s, ok := v.ids[id]; ok && slices.Contains(sections, s) {
		return
	}
	want := strings.Join(sections, " or ")
	msg := fmt.Sprintf("%s: `%s` refers to `%s`, which isn't in %s.", who, field, id, want)
	if s, ok := v.ids[id]; ok {
		msg = fmt.Sprintf("%s: `%s` refers to `%s`, which is in %s, not %s.", who, field, id, s, want)
	}
	v.add(SevError, "unknown-ref", p, msg, suggestHint(id, v.idsIn(sections...)))
}

func (v *validator) run() {
	m := v.m
	if m.Version != Version {
		hint := "Run `threat migrate` to upgrade it."
		if m.Version > Version {
			hint = "Upgrade the threat tool to read it."
		}
		v.add(SevError, "version", "version", fmt.Sprintf("This file uses format version %d; this tool reads version %d.", m.Version, Version), hint)
		return
	}

	v.collectIDs()

	usedIdentity := map[string]bool{}
	for i, c := range m.Components {
		p, who := idx("components", i), "Component `"+c.ID+"`"
		if c.Identity != "" {
			v.ref(p+".identity", who, "identity", c.Identity, "identities")
			usedIdentity[c.Identity] = true
		}
		if c.Zone != "" {
			v.ref(p+".zone", who, "zone", c.Zone, "zones")
		}
		for j, d := range c.Stores {
			v.ref(fmt.Sprintf("%s.stores[%d]", p, j), who, "stores", d, "data")
		}
		for j, g := range c.Code {
			v.repoPath(fmt.Sprintf("%s.code[%d]", p, j), who, "code", g)
		}
	}
	today := time.Now().Format(time.DateOnly)
	for i, c := range m.Components {
		if c.Reviewed > today {
			v.add(SevError, "future-date", idx("components", i)+".reviewed", fmt.Sprintf("Component `%s` says it was reviewed on %s, which is in the future.", c.ID, c.Reviewed), "Set `reviewed` to the date the review actually happened.")
		}
	}
	if s := m.Signoff; s != nil && s.On > today {
		v.add(SevError, "future-date", "signoff.on", fmt.Sprintf("The sign-off is dated %s, which is in the future.", s.On), "")
	}
	for i, f := range m.Flows {
		p, who := idx("flows", i), "Flow `"+f.ID+"`"
		v.ref(p+".from", who, "from", f.From, "components")
		v.ref(p+".to", who, "to", f.To, "components")
		for j, d := range f.Carries {
			v.ref(fmt.Sprintf("%s.carries[%d]", p, j), who, "carries", d, "data")
		}
		if f.From == f.To && f.From != "" {
			v.add(SevWarning, "self-flow", p, who+" goes from a component to itself.", "")
		}
	}

	for i, idn := range m.Identities {
		p, who := idx("identities", i), "Identity `"+idn.ID+"`"
		for j, perm := range idn.Can {
			v.ref(fmt.Sprintf("%s.can[%d].on", p, j), who, "can.on", perm.On, "components", "data")
		}
		if !usedIdentity[idn.ID] {
			v.add(SevWarning, "unused", p, who+" isn't used by any component.", "Set `identity: "+idn.ID+"` on the components that run as it.")
		}
	}

	referenced := map[string]bool{}
	for i, t := range m.Threats {
		v.threat(i, t)
		for _, mid := range t.Mitigations {
			referenced[mid] = true
		}
	}
	for i, mit := range m.Mitigations {
		p, who := idx("mitigations", i), "Mitigation `"+mit.ID+"`"
		if !referenced[mit.ID] {
			v.add(SevWarning, "unused", p, who+" isn't linked to any threat.", "Add its ID to a threat's `mitigations` list.")
		}
		for j, ev := range mit.Evidence {
			if ev.Type == "link" {
				continue
			}
			file, _ := ev.Path()
			v.repoPath(fmt.Sprintf("%s.evidence[%d].%s", p, j, ev.Type), who, "evidence", file)
		}
	}

	for id := range m.Layout {
		if s := v.ids[id]; s != "zones" && s != "components" {
			v.add(SevWarning, "layout-ref", "layout."+id, fmt.Sprintf("`layout` has a position for `%s`, which isn't a zone or component.", id), "Tools will drop it on the next save.")
		}
	}
}

func (v *validator) collectIDs() {
	lists := map[string][]string{}
	for _, d := range v.m.Data {
		lists["data"] = append(lists["data"], d.ID)
	}
	for _, z := range v.m.Zones {
		lists["zones"] = append(lists["zones"], z.ID)
	}
	for _, a := range v.m.Actors {
		lists["actors"] = append(lists["actors"], a.ID)
	}
	for _, idn := range v.m.Identities {
		lists["identities"] = append(lists["identities"], idn.ID)
	}
	for _, c := range v.m.Components {
		lists["components"] = append(lists["components"], c.ID)
	}
	for _, f := range v.m.Flows {
		lists["flows"] = append(lists["flows"], f.ID)
	}
	for _, t := range v.m.Threats {
		lists["threats"] = append(lists["threats"], t.ID)
	}
	for _, mt := range v.m.Mitigations {
		lists["mitigations"] = append(lists["mitigations"], mt.ID)
	}
	for _, section := range Sections {
		for i, id := range lists[section] {
			p := idx(section, i) + ".id"
			if !idPattern.MatchString(id) {
				v.add(SevError, "id-format", p, fmt.Sprintf("ID `%s` should be lowercase letters, digits and dashes, like `invoice-api`.", id), "")
			}
			if prev, dup := v.ids[id]; dup {
				v.add(SevError, "duplicate-id", p, fmt.Sprintf("ID `%s` is used more than once (also in %s). IDs must be unique across the whole file.", id, prev), "")
				continue
			}
			v.ids[id] = section
		}
	}
}

func (v *validator) threat(i int, t Threat) {
	p, who := idx("threats", i), "Threat `"+t.ID+"`"
	for j, a := range t.Affects {
		v.ref(fmt.Sprintf("%s.affects[%d]", p, j), who, "affects", a, "components", "flows")
	}
	for j, mid := range t.Mitigations {
		v.ref(fmt.Sprintf("%s.mitigations[%d]", p, j), who, "mitigations", mid, "mitigations")
	}
	if g := t.Gives; g != nil {
		for j, d := range g.Reads {
			v.ref(fmt.Sprintf("%s.gives.reads[%d]", p, j), who, "gives.reads", d, "data")
		}
		for j, d := range g.Changes {
			v.ref(fmt.Sprintf("%s.gives.changes[%d]", p, j), who, "gives.changes", d, "data")
		}
		for j, c := range g.Controls {
			v.ref(fmt.Sprintf("%s.gives.controls[%d]", p, j), who, "gives.controls", c, "components")
		}
	}

	switch t.Status {
	case "accepted":
		if t.Accepted == nil {
			v.add(SevError, "accepted", p+".status", who+" is accepted, but doesn't say who accepted it, why, or until when.",
				"Add `accepted: {by: \"@you\", reason: ..., until: 2027-01-31}`.")
		}
	case "not-applicable":
		if t.Reason == "" {
			v.add(SevError, "reason", p+".status", who+" is marked not-applicable without a `reason`.", "Say in one line why it doesn't apply.")
		}
	case "open":
		for _, mid := range t.Mitigations {
			if mt := v.m.Mitigation(mid); mt != nil && mt.Status == "done" && mt.Effect != nil && mt.Effect.Eliminates {
				v.add(SevWarning, "can-be-mitigated", p+".status", fmt.Sprintf("%s is open, but mitigation `%s` is done and makes it impossible.", who, mid), "Set `status: mitigated`.")
				break
			}
		}
	case "mitigated":
		if !v.anyDone(t) {
			v.add(SevWarning, "mitigated-not-done", p+".status", who+" is marked mitigated, but none of its mitigations are done.", "")
		}
	}
	if t.Accepted != nil && t.Status != "accepted" {
		v.add(SevWarning, "accepted", p+".accepted", who+" has an `accepted` block but its status is "+t.Status+".", "")
	}
	if t.Status == "not-applicable" {
		return
	}
	if len(t.Affects) == 0 {
		v.add(SevWarning, "no-affects", p, who+" doesn't say which components or flows it `affects`.", "")
	}
	var missing []string
	for _, f := range []struct{ name, val string }{{"who", t.Who}, {"effort", t.Effort}, {"impact", t.Impact}} {
		if f.val == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 && t.Risk == nil {
		v.add(SevWarning, "not-assessed", p, fmt.Sprintf("%s can't be given a risk level yet: it's missing %s.", who, strings.Join(missing, ", ")), "")
	}
	if !strings.Contains(" "+strings.ToLower(t.Title)+" ", " could ") {
		v.add(SevWarning, "title-style", p+".title", who+"'s title doesn't read as \"who could do what by how\".",
			"For example: \"A logged-in customer could read other customers' invoices by changing the ID in the URL\".")
	}
}

func (v *validator) anyDone(t Threat) bool {
	for _, mid := range t.Mitigations {
		if mt := v.m.Mitigation(mid); mt != nil && mt.Status == "done" {
			return true
		}
	}
	return false
}

// repoPath rejects paths that could point outside the repository. Model files
// arrive in pull requests, so tools must never follow them out of the repo.
func (v *validator) repoPath(p, who, field, file string) {
	clean := path.Clean(strings.ReplaceAll(file, `\`, "/"))
	if file == "" || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || (len(file) > 1 && file[1] == ':') {
		v.add(SevError, "path-escape", p, fmt.Sprintf("%s: `%s` path `%s` must be relative to the repository root and stay inside it.", who, field, file), "")
	}
}
