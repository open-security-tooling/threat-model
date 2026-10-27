// Package catalog loads threat libraries and matches their entries against a
// model to suggest threats. See docs/threat-library.md.
package catalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/open-security-tooling/threat-model/catalogs"
	"github.com/open-security-tooling/threat-model/internal/model"
)

type Catalog struct {
	Name    string  `json:"name"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	ID           string              `json:"id"`
	Title        string              `json:"title"`
	Kind         string              `json:"kind"`
	Applies      AppliesList         `json:"applies"`
	Attack       []string            `json:"attack"`
	Defaults     Defaults            `json:"defaults"`
	Gives        *model.Gives        `json:"gives,omitempty"`
	Mitigations  []EntryMitigation   `json:"mitigations"`
	WhyItMatters string              `json:"why_it_matters"`
	Refs         map[string][]string `json:"refs,omitempty"`
}

// Applies says where an entry is relevant: exactly one of Component or Flow.
// All conditions given must hold; within a condition, any listed value matches.
type Applies struct {
	Component *ComponentCond `json:"component,omitempty"`
	Flow      *FlowCond      `json:"flow,omitempty"`
	Identity  *IdentityCond  `json:"identity,omitempty"`
}

// AppliesList is one condition set or a list of alternatives (any matches).
type AppliesList []Applies

func (a *AppliesList) UnmarshalJSON(b []byte) error {
	var list []Applies
	if json.Unmarshal(b, &list) == nil {
		*a = list
		return nil
	}
	var one Applies
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&one); err != nil {
		return err
	}
	*a = AppliesList{one}
	return nil
}

// IdentityCond matches identities (service accounts, roles, keys).
type IdentityCond struct {
	Kind   []string `json:"kind,omitempty"`
	Can    []string `json:"can,omitempty"`    // has any of these permissions
	Shared *bool    `json:"shared,omitempty"` // used by more than one component
}

// Control states used in conditions. A control the model doesn't mention is
// "unknown", so entries can suggest finding out without nagging when the
// model already says it's in place.
var (
	encryptionStates = []string{"encrypted", "unencrypted", "unknown"}
	monitoringStates = []string{"on", "off", "unknown"}
	patchingStates   = append(append([]string{}, model.Patching...), "unknown")
)

type ComponentCond struct {
	Kind        []string `json:"kind,omitempty"`
	Exposure    []string `json:"exposure,omitempty"`
	Tech        []string `json:"tech,omitempty"`
	Stores      []string `json:"stores,omitempty"` // data sensitivities
	ZoneTrust   []string `json:"zone_trust,omitempty"`
	ZoneNetwork []string `json:"zone_network,omitempty"` // open | segmented
	ZoneEgress  []string `json:"zone_egress,omitempty"`  // open | restricted
	AtRest      []string `json:"at_rest,omitempty"`      // encrypted | unencrypted | unknown
	Monitoring  []string `json:"monitoring,omitempty"`   // on | off | unknown
	Patching    []string `json:"patching,omitempty"`     // automated | scheduled | manual | unknown
	// Handles matches data the component stores or sends and receives.
	Handles []string `json:"handles,omitempty"` // data sensitivities
	// NotManaged skips managed services the provider runs and patches.
	NotManaged bool `json:"not_managed,omitempty"`
	// IdentityRights: "none" (no identity in the model) or "admin" (its identity has admin rights).
	IdentityRights []string `json:"identity_rights,omitempty"`
	// Features matches what the component does (any of), e.g. login, file-upload.
	Features []string `json:"features,omitempty"`
	// Tenancy matches the system's tenancy: single, multi or unknown.
	Tenancy []string `json:"tenancy,omitempty"`
}

type FlowCond struct {
	CrossesZones  *bool    `json:"crosses_zones,omitempty"`
	FromZoneTrust []string `json:"from_zone_trust,omitempty"`
	FromKind      []string `json:"from_kind,omitempty"`
	ToKind        []string `json:"to_kind,omitempty"`
	ToExposure    []string `json:"to_exposure,omitempty"`
	InTransit     []string `json:"in_transit,omitempty"` // encrypted | unencrypted | unknown
	ToFeatures    []string `json:"to_features,omitempty"`
	Tenancy       []string `json:"tenancy,omitempty"`
	Auth          []string `json:"auth,omitempty"`
	Carries       []string `json:"carries,omitempty"` // data sensitivities
}

type Defaults struct {
	Who    string `json:"who"`
	Effort string `json:"effort"`
	Impact string `json:"impact"`
}

type EntryMitigation struct {
	ID     string            `json:"id"`
	Title  string            `json:"title"`
	Effect *model.Effect     `json:"effect"`
	ByTech map[string]string `json:"by_tech,omitempty"`
}

// Builtin returns the catalogs shipped with the tool.
func Builtin() ([]Catalog, error) {
	var out []Catalog
	err := fs.WalkDir(catalogs.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".yaml" {
			return err
		}
		src, err := fs.ReadFile(catalogs.FS, p)
		if err != nil {
			return err
		}
		c, err := Parse(strings.TrimSuffix(path.Base(p), ".yaml"), src)
		if err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// Parse reads one catalog file and checks every entry.
func Parse(name string, src []byte) (Catalog, error) {
	if diags := model.StrictYAML(src); diags.HasErrors() {
		return Catalog{}, fmt.Errorf("catalog %s: %s", name, diags[0])
	}
	var generic any
	if err := yaml.Unmarshal(src, &generic); err != nil {
		return Catalog{}, fmt.Errorf("catalog %s: %w", name, err)
	}
	raw, err := json.Marshal(generic)
	if err != nil {
		return Catalog{}, err
	}
	var entries []Entry
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return Catalog{}, fmt.Errorf("catalog %s: %w", name, err)
	}
	c := Catalog{Name: name, Entries: entries}
	if errs := c.Check(); len(errs) > 0 {
		return Catalog{}, fmt.Errorf("catalog %s: %s", name, strings.Join(errs, "; "))
	}
	return c, nil
}

var placeholders = []string{"{component}", "{from}", "{to}", "{flow}", "{data}", "{zone}", "{identity}"}

// Check returns problems with the catalog's entries.
func (c Catalog) Check() []string {
	var errs []string
	seen := map[string]bool{}
	bad := func(id, format string, args ...any) { errs = append(errs, id+": "+fmt.Sprintf(format, args...)) }
	in := func(v string, enum []string) bool { return v == "" || slices.Contains(enum, v) }
	for _, e := range c.Entries {
		if e.ID == "" || seen[e.ID] {
			bad(e.ID, "missing or duplicate id")
		}
		seen[e.ID] = true
		if !strings.Contains(e.Title, " could ") {
			bad(e.ID, "title should read \"who could do what by how\"")
		}
		if !slices.Contains(model.ThreatKinds, e.Kind) {
			bad(e.ID, "unknown kind %q", e.Kind)
		}
		if len(e.Applies) == 0 {
			bad(e.ID, "needs applies")
		}
		for _, ap := range e.Applies {
			targets := 0
			for _, set := range []bool{ap.Component != nil, ap.Flow != nil, ap.Identity != nil} {
				if set {
					targets++
				}
			}
			if targets != 1 {
				bad(e.ID, "each applies needs exactly one of component, flow or identity")
			}
		}
		allIn := func(field string, vals, enum []string) {
			for _, v := range vals {
				if !slices.Contains(enum, v) {
					bad(e.ID, "%s takes %v, not %q", field, enum, v)
				}
			}
		}
		tenancies := append(append([]string{}, model.Tenancies...), "unknown")
		exposures := append(append([]string{}, model.Exposures...), "unknown")
		for _, ap := range e.Applies {
			if cc := ap.Component; cc != nil {
				allIn("zone_egress", cc.ZoneEgress, model.ZoneEgress)
				allIn("at_rest", cc.AtRest, encryptionStates)
				allIn("monitoring", cc.Monitoring, monitoringStates)
				allIn("patching", cc.Patching, patchingStates)
				allIn("handles", cc.Handles, model.Sensitivities)
				allIn("identity_rights", cc.IdentityRights, []string{"none", "admin"})
			}
			if fc := ap.Flow; fc != nil {
				allIn("in_transit", fc.InTransit, encryptionStates)
			}
			if ic := ap.Identity; ic != nil {
				allIn("kind", ic.Kind, model.IdentityKinds)
				allIn("can", ic.Can, model.Permissions)
			}
			if cc := ap.Component; cc != nil {
				for _, k := range cc.Kind {
					if !in(k, model.ComponentKinds) {
						bad(e.ID, "unknown component kind %q", k)
					}
				}
				allIn("tenancy", cc.Tenancy, tenancies)
				for _, x := range cc.Exposure {
					if !in(x, exposures) {
						bad(e.ID, "unknown exposure %q", x)
					}
				}
				for _, s := range cc.Stores {
					if !in(s, model.Sensitivities) {
						bad(e.ID, "stores takes sensitivities, not %q", s)
					}
				}
				for _, t := range cc.ZoneTrust {
					if !in(t, model.Trusts) {
						bad(e.ID, "unknown trust %q", t)
					}
				}
				for _, n := range cc.ZoneNetwork {
					if !in(n, model.ZoneNetworks) {
						bad(e.ID, "zone_network is open or segmented, not %q", n)
					}
				}
			}
			if fc := ap.Flow; fc != nil {
				for _, s := range fc.Carries {
					if !in(s, model.Sensitivities) {
						bad(e.ID, "carries takes sensitivities, not %q", s)
					}
				}
				for _, a := range fc.Auth {
					if !in(a, model.FlowAuths) {
						bad(e.ID, "unknown auth %q", a)
					}
				}
				for _, t := range fc.FromZoneTrust {
					if !in(t, model.Trusts) {
						bad(e.ID, "unknown trust %q", t)
					}
				}
				allIn("tenancy", fc.Tenancy, tenancies)
				for _, x := range fc.ToExposure {
					if !in(x, exposures) {
						bad(e.ID, "unknown exposure %q", x)
					}
				}
				for _, k := range append(append([]string{}, fc.FromKind...), fc.ToKind...) {
					if !in(k, model.ComponentKinds) {
						bad(e.ID, "unknown component kind %q", k)
					}
				}
			}
		}
		if len(e.Attack) < 2 || len(e.Attack) > 6 {
			bad(e.ID, "attack should have 2 to 6 steps")
		}
		d := e.Defaults
		if !in(d.Who, model.WhoLevels) || !in(d.Effort, model.Efforts) || !in(d.Impact, model.Impacts) || d.Who == "" || d.Effort == "" || d.Impact == "" {
			bad(e.ID, "defaults need valid who, effort and impact")
		}
		if len(e.Mitigations) == 0 {
			bad(e.ID, "needs at least one mitigation")
		}
		for _, m := range e.Mitigations {
			if m.ID == "" || m.Title == "" || m.Effect == nil {
				bad(e.ID, "mitigation %q needs id, title and effect", m.ID)
			}
		}
		if strings.TrimSpace(e.WhyItMatters) == "" {
			bad(e.ID, "needs why_it_matters")
		}
		texts := append([]string{e.Title}, e.Attack...)
		for _, m := range e.Mitigations {
			texts = append(texts, m.Title)
		}
		for _, t := range texts {
			for _, ph := range strings.FieldsFunc(t, func(r rune) bool { return r == ' ' }) {
				if i := strings.Index(ph, "{"); i >= 0 {
					j := strings.Index(ph[i:], "}")
					if j < 0 {
						continue
					}
					if tok := ph[i : i+j+1]; !slices.Contains(placeholders, tok) {
						bad(e.ID, "unknown placeholder %s", tok)
					}
				}
			}
		}
	}
	return errs
}
