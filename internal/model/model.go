// Package model defines the threat model types and parses and validates
// threatmodel.yaml files. See docs/model-format.md for the format.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Version is the format version this package reads and writes.
const Version = 1

type Model struct {
	Version     int               `json:"version"`
	System      System            `json:"system"`
	Data        []Data            `json:"data,omitempty"`
	Zones       []Zone            `json:"zones,omitempty"`
	Actors      []Actor           `json:"actors,omitempty"`
	Identities  []Identity        `json:"identities,omitempty"`
	Components  []Component       `json:"components,omitempty"`
	Flows       []Flow            `json:"flows,omitempty"`
	Threats     []Threat          `json:"threats,omitempty"`
	Mitigations []Mitigation      `json:"mitigations,omitempty"`
	Catalogs    []CatalogRef      `json:"catalogs,omitempty"`
	Signoff     *Signoff          `json:"signoff,omitempty"`
	Layout      map[string]Layout `json:"layout,omitempty"`
}

type System struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tenancy     string   `json:"tenancy,omitempty"`
	Owners      []string `json:"owners,omitempty"`
	Links       []string `json:"links,omitempty"`
}

type Data struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Sensitivity string `json:"sensitivity"`
	Description string `json:"description,omitempty"`
}

type Zone struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Trust string `json:"trust"`
	// Network is "open" (the default: a flat network) or "segmented" (only
	// the model's flows are allowed, e.g. by security groups).
	Network string `json:"network,omitempty"`
	// Egress is "open" (the default) or "restricted" outbound internet access.
	Egress string `json:"egress,omitempty"`
}

// EgressRestricted reports whether outbound traffic from the zone is limited.
func (z *Zone) EgressRestricted() bool { return z != nil && z.Egress == "restricted" }

// Identity is something a component runs as: a service account, cloud role,
// group or API key, with what it's allowed to do.
type Identity struct {
	ID    string       `json:"id"`
	Name  string       `json:"name"`
	Kind  string       `json:"kind"`
	Can   []Permission `json:"can,omitempty"`
	Notes string       `json:"notes,omitempty"`
}

type Permission struct {
	Do string `json:"do"` // read | write | admin | invoke
	On string `json:"on"` // component or data ID
}

// Segmented reports whether only declared flows can reach into the zone.
func (z *Zone) Segmented() bool { return z != nil && z.Network == "segmented" }

type Actor struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Access string `json:"access,omitempty"`
}

type Component struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Zone     string   `json:"zone,omitempty"`
	Exposure string   `json:"exposure,omitempty"`
	Tech     []string `json:"tech,omitempty"`
	Features []string `json:"features,omitempty"`
	Stores   []string `json:"stores,omitempty"`
	Identity string   `json:"identity,omitempty"`
	// Encrypted at rest, monitored: nil means the model doesn't say.
	EncryptedAtRest *bool    `json:"encrypted_at_rest,omitempty"`
	Monitored       *bool    `json:"monitored,omitempty"`
	Patching        string   `json:"patching,omitempty"`
	Managed         *bool    `json:"managed,omitempty"`
	Code            []string `json:"code,omitempty"`
	// Reviewed is a date; ReviewedBy is set when the file says who.
	Reviewed   string            `json:"reviewed,omitempty"`
	ReviewedBy string            `json:"reviewed_by,omitempty"`
	Considered map[string]string `json:"considered,omitempty"`
	Notes      string            `json:"notes,omitempty"`
}

type Flow struct {
	ID      string   `json:"id"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Over    string   `json:"over,omitempty"`
	Carries []string `json:"carries,omitempty"`
	Auth    string   `json:"auth,omitempty"`
	// Encrypted in transit; nil means the model doesn't say.
	Encrypted *bool  `json:"encrypted,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

type Threat struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Kind        string        `json:"kind,omitempty"`
	Affects     []string      `json:"affects,omitempty"`
	Attack      []string      `json:"attack,omitempty"`
	Who         string        `json:"who,omitempty"`
	Effort      string        `json:"effort,omitempty"`
	Impact      string        `json:"impact,omitempty"`
	ImpactNote  string        `json:"impact_note,omitempty"`
	Gives       *Gives        `json:"gives,omitempty"`
	Status      string        `json:"status"`
	Mitigations []string      `json:"mitigations,omitempty"`
	Accepted    *Acceptance   `json:"accepted,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Risk        *RiskOverride `json:"risk,omitempty"`
	From        string        `json:"from,omitempty"`
	Refs        Refs          `json:"refs,omitempty"`
}

// Gives describes what a successful attack hands the attacker.
type Gives struct {
	Reads    []string `json:"reads,omitempty"`
	Changes  []string `json:"changes,omitempty"`
	Controls []string `json:"controls,omitempty"`
	Access   string   `json:"access,omitempty"`
}

// Signoff records a security review of the whole model.
type Signoff struct {
	By   string `json:"by"`
	On   string `json:"on"`
	Note string `json:"note,omitempty"`
}

type Acceptance struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
	Until  string `json:"until"`
}

type RiskOverride struct {
	Override string `json:"override"`
	Reason   string `json:"reason"`
}

// Refs maps a reference scheme (stride, cwe, owasp, ...) to identifiers.
type Refs map[string][]string

type Mitigation struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Status   string     `json:"status"`
	Owner    string     `json:"owner,omitempty"`
	Due      string     `json:"due,omitempty"`
	Effect   *Effect    `json:"effect,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
	Notes    string     `json:"notes,omitempty"`
}

// Effect is what a mitigation changes about the threats it addresses. In YAML
// it is either a word ("eliminates", "detects") or a map overriding who,
// effort or impact.
type Effect struct {
	Eliminates bool   `json:"eliminates,omitempty"`
	Detects    bool   `json:"detects,omitempty"`
	Who        string `json:"who,omitempty"`
	Effort     string `json:"effort,omitempty"`
	Impact     string `json:"impact,omitempty"`
}

func (e *Effect) UnmarshalJSON(b []byte) error {
	var word string
	if json.Unmarshal(b, &word) == nil {
		switch word {
		case "eliminates":
			e.Eliminates = true
		case "detects":
			e.Detects = true
		default:
			return fmt.Errorf("effect must be eliminates, detects, or a map like {effort: hard}; got %q", word)
		}
		return nil
	}
	var m struct {
		Who    string `json:"who"`
		Effort string `json:"effort"`
		Impact string `json:"impact"`
	}
	if err := strictJSON(b, &m); err != nil {
		return fmt.Errorf("effect map may only set who, effort or impact: %w", err)
	}
	e.Who, e.Effort, e.Impact = m.Who, m.Effort, m.Impact
	return nil
}

func (e Effect) MarshalJSON() ([]byte, error) {
	switch {
	case e.Eliminates:
		return json.Marshal("eliminates")
	case e.Detects:
		return json.Marshal("detects")
	}
	m := map[string]string{}
	if e.Who != "" {
		m["who"] = e.Who
	}
	if e.Effort != "" {
		m["effort"] = e.Effort
	}
	if e.Impact != "" {
		m["impact"] = e.Impact
	}
	return json.Marshal(m)
}

// Evidence points at code, a test or a link that shows a mitigation exists.
// In YAML it is a single-key map: {code: path#symbol}, {test: ...} or {link: url}.
type Evidence struct {
	Type   string `json:"type"` // code | test | link
	Target string `json:"target"`
}

var evidenceTypes = []string{"code", "test", "link"}

func (ev *Evidence) UnmarshalJSON(b []byte) error {
	if json.Unmarshal(b, &struct {
		Type   *string `json:"type"`
		Target *string `json:"target"`
	}{&ev.Type, &ev.Target}) == nil && ev.Type != "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil || len(m) != 1 {
		return fmt.Errorf("evidence entries look like `code: path/to/file.go#Symbol`, `test: ...` or `link: https://...`")
	}
	for k, v := range m {
		ev.Type, ev.Target = k, v
	}
	return nil
}

// Path splits a code/test target into the file path and optional symbol.
func (ev Evidence) Path() (path, symbol string) {
	path, symbol, _ = strings.Cut(ev.Target, "#")
	return path, symbol
}

// CatalogRef is either "builtin:<name>" or {path: file.yaml}.
type CatalogRef struct {
	Builtin string `json:"builtin,omitempty"`
	Path    string `json:"path,omitempty"`
}

func (c *CatalogRef) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		name, ok := strings.CutPrefix(s, "builtin:")
		if !ok || name == "" {
			return fmt.Errorf("catalog %q: use builtin:<name> or {path: file.yaml}", s)
		}
		c.Builtin = name
		return nil
	}
	var m struct {
		Path string `json:"path"`
	}
	if err := strictJSON(b, &m); err != nil || m.Path == "" {
		return fmt.Errorf("catalog entries are builtin:<name> or {path: file.yaml}")
	}
	c.Path = m.Path
	return nil
}

type Layout struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	W float64 `json:"w,omitempty"`
	H float64 `json:"h,omitempty"`
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Lookup helpers.

func (m *Model) Component(id string) *Component {
	for i := range m.Components {
		if m.Components[i].ID == id {
			return &m.Components[i]
		}
	}
	return nil
}

func (m *Model) Flow(id string) *Flow {
	for i := range m.Flows {
		if m.Flows[i].ID == id {
			return &m.Flows[i]
		}
	}
	return nil
}

func (m *Model) Zone(id string) *Zone {
	for i := range m.Zones {
		if m.Zones[i].ID == id {
			return &m.Zones[i]
		}
	}
	return nil
}

func (m *Model) DataItem(id string) *Data {
	for i := range m.Data {
		if m.Data[i].ID == id {
			return &m.Data[i]
		}
	}
	return nil
}

func (m *Model) IdentityItem(id string) *Identity {
	for i := range m.Identities {
		if m.Identities[i].ID == id {
			return &m.Identities[i]
		}
	}
	return nil
}

func (m *Model) Threat(id string) *Threat {
	for i := range m.Threats {
		if m.Threats[i].ID == id {
			return &m.Threats[i]
		}
	}
	return nil
}

func (m *Model) Mitigation(id string) *Mitigation {
	for i := range m.Mitigations {
		if m.Mitigations[i].ID == id {
			return &m.Mitigations[i]
		}
	}
	return nil
}

// CrossesZones reports whether a flow connects components in different zones.
func (m *Model) CrossesZones(f Flow) bool {
	from, to := m.Component(f.From), m.Component(f.To)
	return from != nil && to != nil && from.Zone != "" && to.Zone != "" && from.Zone != to.Zone
}
