// Package ops is the contract between the core and every front end: the
// CLI, the MCP server and the WebAssembly build all call these functions,
// so an operation behaves the same everywhere.
//
// Operations are stateless: they take the model file's source text and
// return results, and edits return the new source. Edits that would add
// validation errors are rejected and the source is left unchanged.
package ops

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/catalog"
	"github.com/open-security-tooling/threat-model/internal/edit"
	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// Error is returned for requests that can't be carried out. Its message is
// meant to be shown to the user as is.
type Error struct {
	Message     string             `json:"message"`
	Diagnostics []model.Diagnostic `json:"diagnostics,omitempty"`
}

func (e *Error) Error() string { return e.Message }

func fail(format string, args ...any) error { return &Error{Message: fmt.Sprintf(format, args...)} }

// Loaded is a parsed and validated model.
type Loaded struct {
	Doc         *model.Document
	Model       *model.Model
	Diagnostics model.Diagnostics
}

// Load parses and validates source. Model is nil if the file can't be read
// as a model at all.
func Load(source []byte) Loaded {
	doc, diags := model.Parse(source)
	l := Loaded{Doc: doc, Diagnostics: diags}
	if doc != nil && doc.Model != nil {
		l.Model = doc.Model
		l.Diagnostics = append(l.Diagnostics, model.Validate(doc)...)
	}
	l.Diagnostics = l.Diagnostics.Sorted()
	return l
}

// --- validate / format ---

type ValidateResult struct {
	OK          bool               `json:"ok"`
	Errors      int                `json:"errors"`
	Warnings    int                `json:"warnings"`
	Diagnostics []model.Diagnostic `json:"diagnostics"`
	Canonical   bool               `json:"canonical"`
}

func Validate(source []byte) ValidateResult {
	l := Load(source)
	r := ValidateResult{Diagnostics: nonNil(l.Diagnostics)}
	for _, d := range l.Diagnostics {
		if d.Severity == model.SevError {
			r.Errors++
		} else {
			r.Warnings++
		}
	}
	r.OK = r.Errors == 0
	if out, err := edit.Format(source); err == nil {
		r.Canonical = string(out) == string(source)
	}
	return r
}

func nonNil(ds model.Diagnostics) []model.Diagnostic {
	if ds == nil {
		return []model.Diagnostic{}
	}
	return ds
}

type FormatResult struct {
	Source  string `json:"source"`
	Changed bool   `json:"changed"`
}

func Format(source []byte) (FormatResult, error) {
	if l := Load(source); l.Doc == nil {
		return FormatResult{}, &Error{Message: "The file can't be formatted until these problems are fixed.", Diagnostics: l.Diagnostics}
	}
	out, err := edit.Format(source)
	if err != nil {
		return FormatResult{}, fail("Couldn't format the file: %v", err)
	}
	return FormatResult{Source: string(out), Changed: string(out) != string(source)}, nil
}

// --- reading ---

// View is everything a front end needs to show a model.
type View struct {
	Model       *model.Model                   `json:"model"`
	Diagnostics []model.Diagnostic             `json:"diagnostics"`
	Risks       map[string]risk.Assessment     `json:"risks"`
	Crossings   []string                       `json:"crossings"`
	Summary     Summary                        `json:"summary"`
	Lines       map[string]int                 `json:"lines"`
	Coverage    map[string]map[string][]string `json:"coverage"`
	// Transit is each flow's encryption in transit: encrypted, unencrypted
	// or unknown, inferred from the protocol when the model doesn't say.
	Transit map[string]string `json:"transit"`
}

type Summary struct {
	Components  int            `json:"components"`
	Flows       int            `json:"flows"`
	Threats     int            `json:"threats"`
	Open        int            `json:"open"`
	ByRisk      map[string]int `json:"by_risk"`
	Mitigations map[string]int `json:"mitigations"`
	NotAssessed int            `json:"not_assessed"`
}

// Show parses source and computes risks, zone crossings and coverage.
func Show(source []byte) (View, error) {
	l := Load(source)
	if l.Model == nil {
		return View{Diagnostics: nonNil(l.Diagnostics)}, &Error{Message: "The file can't be read as a threat model.", Diagnostics: l.Diagnostics}
	}
	m := l.Model
	v := View{
		Model:       m,
		Diagnostics: nonNil(l.Diagnostics),
		Risks:       map[string]risk.Assessment{},
		Crossings:   []string{},
		Lines:       map[string]int{},
		Coverage:    map[string]map[string][]string{},
		Transit:     map[string]string{},
		Summary:     Summary{ByRisk: map[string]int{}, Mitigations: map[string]int{}},
	}
	for i, f := range m.Flows {
		v.Transit[f.ID] = catalog.TransitState(&m.Flows[i])
		if m.CrossesZones(f) {
			v.Crossings = append(v.Crossings, f.ID)
		}
		v.Lines[f.ID] = l.Doc.Line(fmt.Sprintf("flows[%d]", i))
	}
	for i, c := range m.Components {
		v.Lines[c.ID] = l.Doc.Line(fmt.Sprintf("components[%d]", i))
		v.Coverage[c.ID] = map[string][]string{}
	}
	for i := range m.Threats {
		t := &m.Threats[i]
		v.Lines[t.ID] = l.Doc.Line(fmt.Sprintf("threats[%d]", i))
		a := risk.Assess(m, t)
		v.Risks[t.ID] = a
		v.Summary.Threats++
		if t.Status == "open" {
			v.Summary.Open++
		}
		if t.Status != "not-applicable" {
			if a.Assessed {
				v.Summary.ByRisk[a.Level]++
			} else {
				v.Summary.NotAssessed++
			}
		}
		for _, target := range t.Affects {
			comps := []string{target}
			if f := m.Flow(target); f != nil {
				comps = []string{f.To}
			}
			for _, c := range comps {
				if cov, ok := v.Coverage[c]; ok && t.Kind != "" && !slices.Contains(cov[t.Kind], t.ID) {
					cov[t.Kind] = append(cov[t.Kind], t.ID)
				}
			}
		}
	}
	for i, mt := range m.Mitigations {
		v.Lines[mt.ID] = l.Doc.Line(fmt.Sprintf("mitigations[%d]", i))
		v.Summary.Mitigations[mt.Status]++
	}
	v.Summary.Components, v.Summary.Flows = len(m.Components), len(m.Flows)
	return v, nil
}

// ExplainResult is the plain-language card for one threat.
type ExplainResult struct {
	Threat      model.Threat       `json:"threat"`
	Risk        risk.Assessment    `json:"risk"`
	Mitigations []model.Mitigation `json:"mitigations"`
	Affects     []string           `json:"affects"`
}

func Explain(source []byte, id string) (ExplainResult, error) {
	l := Load(source)
	if l.Model == nil {
		return ExplainResult{}, &Error{Message: "The file can't be read as a threat model.", Diagnostics: l.Diagnostics}
	}
	m := l.Model
	t := m.Threat(id)
	if t == nil {
		if mt := m.Mitigation(id); mt != nil {
			return ExplainResult{}, fail("`%s` is a mitigation; explain takes a threat ID.", id)
		}
		var ids []string
		for _, th := range m.Threats {
			ids = append(ids, th.ID)
		}
		return ExplainResult{}, fail("There's no threat `%s`.%s", id, hintFor(id, ids))
	}
	r := ExplainResult{Threat: *t, Risk: risk.Assess(m, t), Mitigations: []model.Mitigation{}}
	for _, mid := range t.Mitigations {
		if mt := m.Mitigation(mid); mt != nil {
			r.Mitigations = append(r.Mitigations, *mt)
		}
	}
	for _, a := range t.Affects {
		if c := m.Component(a); c != nil {
			r.Affects = append(r.Affects, c.Name)
		} else if f := m.Flow(a); f != nil {
			r.Affects = append(r.Affects, flowName(m, f))
		}
	}
	return r, nil
}

func flowName(m *model.Model, f *model.Flow) string {
	name := func(id string) string {
		if c := m.Component(id); c != nil {
			return c.Name
		}
		return id
	}
	return name(f.From) + " → " + name(f.To)
}

func hintFor(got string, ids []string) string {
	best, bestD := "", 4
	for _, id := range ids {
		if d := distance(got, id); d < bestD {
			best, bestD = id, d
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf(" Did you mean `%s`?", best)
}

func distance(a, b string) int {
	if a == b {
		return 0
	}
	if strings.Contains(b, a) || strings.Contains(a, b) {
		return 1
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev = cur
	}
	return prev[len(b)]
}

// --- editing ---

// EditResult is returned by every edit.
type EditResult struct {
	Source      string             `json:"source"`
	Changed     bool               `json:"changed"`
	Created     bool               `json:"created,omitempty"`
	Diagnostics []model.Diagnostic `json:"diagnostics"`
}

// guard applies fn to source and rejects the result if it introduces errors
// that weren't there before. Pre-existing errors don't block unrelated edits,
// so a half-written file can still be worked on.
func guard(source []byte, fn func(d *edit.Doc) error) (EditResult, error) {
	before := Load(source)
	if before.Doc == nil {
		return EditResult{}, &Error{Message: "Fix the problems in the file before editing it.", Diagnostics: before.Diagnostics}
	}
	d, err := edit.Parse(source)
	if err != nil {
		return EditResult{}, fail("Couldn't read the file for editing: %v", err)
	}
	if err := fn(d); err != nil {
		var oe *Error
		if errorsAs(err, &oe) {
			return EditResult{}, oe
		}
		return EditResult{}, fail("%s", capitalize(err.Error()))
	}
	out := d.Bytes()
	after := Load(out)
	if introduced := newErrors(before.Diagnostics, after.Diagnostics); len(introduced) > 0 {
		return EditResult{}, &Error{Message: "That change would make the model invalid, so it wasn't made.", Diagnostics: introduced}
	}
	return EditResult{Source: string(out), Changed: string(out) != string(source), Diagnostics: nonNil(after.Diagnostics)}, nil
}

func errorsAs(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func diagKey(d model.Diagnostic) string { return d.Code + "\x00" + d.Path + "\x00" + d.Message }

func newErrors(before, after model.Diagnostics) []model.Diagnostic {
	seen := map[string]int{}
	for _, d := range before {
		if d.Severity == model.SevError {
			seen[d.Code+"\x00"+d.Message]++
		}
	}
	var out []model.Diagnostic
	for _, d := range after {
		if d.Severity != model.SevError {
			continue
		}
		k := d.Code + "\x00" + d.Message
		if seen[k] > 0 {
			seen[k]--
			continue
		}
		out = append(out, d)
	}
	return out
}

// Upsert creates or patches an item. Fields not given are left alone; a
// null field removes it.
func Upsert(source []byte, section, id string, fields map[string]any) (EditResult, error) {
	if !slices.Contains(model.Sections, section) {
		return EditResult{}, fail("Unknown section `%s`; use one of %s.", section, strings.Join(model.Sections, ", "))
	}
	if section == "threats" {
		if s, ok := fields["status"].(string); ok && s == "accepted" {
			return EditResult{}, fail("Use set_status to accept a risk; it records who accepted it, why and until when.")
		}
	}
	var created bool
	r, err := guard(source, func(d *edit.Doc) error {
		var err error
		created, err = d.Upsert(section, id, fields)
		return err
	})
	r.Created = created
	return r, err
}

// Delete removes an item. It refuses if other items still refer to it.
func Delete(source []byte, section, id string) (EditResult, error) {
	l := Load(source)
	if l.Model != nil {
		if refs := referencesTo(l.Model, id); len(refs) > 0 {
			return EditResult{}, fail("`%s` is still used by %s. Remove those references first.", id, strings.Join(refs, ", "))
		}
	}
	return guard(source, func(d *edit.Doc) error {
		if err := d.Delete(section, id); err != nil {
			return err
		}
		return d.SetLayout(id, nil)
	})
}

func referencesTo(m *model.Model, id string) []string {
	var refs []string
	add := func(kind, owner string) { refs = append(refs, fmt.Sprintf("%s `%s`", kind, owner)) }
	for _, c := range m.Components {
		if c.Zone == id || slices.Contains(c.Stores, id) {
			add("component", c.ID)
		}
	}
	for _, f := range m.Flows {
		if f.From == id || f.To == id || slices.Contains(f.Carries, id) {
			add("flow", f.ID)
		}
	}
	for _, t := range m.Threats {
		g := t.Gives
		if slices.Contains(t.Affects, id) || slices.Contains(t.Mitigations, id) ||
			g != nil && (slices.Contains(g.Reads, id) || slices.Contains(g.Changes, id) || slices.Contains(g.Controls, id)) {
			add("threat", t.ID)
		}
	}
	sort.Strings(refs)
	return slices.Compact(refs)
}

// SetSystem patches the system section.
func SetSystem(source []byte, fields map[string]any) (EditResult, error) {
	return guard(source, func(d *edit.Doc) error { return d.SetSystem(fields) })
}

// SetLayout sets (or with nil, removes) a diagram position.
func SetLayout(source []byte, id string, pos map[string]float64) (EditResult, error) {
	return guard(source, func(d *edit.Doc) error { return d.SetLayout(id, pos) })
}

// StatusRequest changes the status of a threat or mitigation.
type StatusRequest struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Reason   string            `json:"reason,omitempty"`
	Accepted *model.Acceptance `json:"accepted,omitempty"`
}

// SetStatus changes a threat's or mitigation's status. Accepting a risk is a
// human decision: callers acting for an agent pass allowAccept=false.
func SetStatus(source []byte, req StatusRequest, allowAccept bool) (EditResult, error) {
	l := Load(source)
	if l.Model == nil {
		return EditResult{}, &Error{Message: "Fix the problems in the file before editing it.", Diagnostics: l.Diagnostics}
	}
	if l.Model.Mitigation(req.ID) != nil {
		if !slices.Contains(model.MitigationStatuses, req.Status) {
			return EditResult{}, fail("Mitigation status must be one of %s.", strings.Join(model.MitigationStatuses, ", "))
		}
		return guard(source, func(d *edit.Doc) error {
			_, err := d.Upsert("mitigations", req.ID, map[string]any{"status": req.Status})
			return err
		})
	}
	if l.Model.Threat(req.ID) == nil {
		return EditResult{}, fail("There's no threat or mitigation `%s`.", req.ID)
	}
	fields := map[string]any{"status": req.Status}
	switch req.Status {
	case "accepted":
		if !allowAccept {
			return EditResult{}, fail("Accepting a risk is a human decision, and this session isn't allowed to make it. Leave the threat open and flag it for a person to review.")
		}
		a := req.Accepted
		if a == nil || a.By == "" || a.Reason == "" || a.Until == "" {
			return EditResult{}, fail("Accepting a risk needs `accepted.by`, `accepted.reason` and `accepted.until` (a date).")
		}
		fields["accepted"] = map[string]any{"by": a.By, "reason": a.Reason, "until": a.Until}
		fields["reason"] = nil
	case "not-applicable":
		if req.Reason == "" {
			return EditResult{}, fail("Say why the threat doesn't apply (`reason`).")
		}
		fields["reason"], fields["accepted"] = req.Reason, nil
	case "open", "mitigated":
		fields["accepted"], fields["reason"] = nil, nil
	default:
		return EditResult{}, fail("Threat status must be one of %s.", strings.Join(model.ThreatStatuses, ", "))
	}
	return guard(source, func(d *edit.Doc) error {
		_, err := d.Upsert("threats", req.ID, fields)
		return err
	})
}

// New returns a starter model for a system with the given name.
func New(name string) (EditResult, error) {
	if strings.TrimSpace(name) == "" {
		return EditResult{}, fail("Give the model a name.")
	}
	src := fmt.Sprintf(starterTemplate, strings.NewReplacer("\n", " ", "\r", " ").Replace(name))
	r, err := SetSystem([]byte(src), map[string]any{"name": name})
	if err != nil {
		return EditResult{}, err
	}
	r.Created = true
	return r, nil
}

const starterTemplate = `# yaml-language-server: $schema=` + model.SchemaURL + `
#
# Threat model for %s. Spec: https://github.com/open-security-tooling/threat-model
version: 1

system:
  name: placeholder

data:
  - id: user-data
    name: User data
    sensitivity: confidential

zones:
  - id: internet
    name: Public internet
    trust: untrusted
  - id: backend
    name: Our backend
    trust: trusted

components:
  - id: browser
    name: User's browser
    kind: client
    zone: internet

  - id: api
    name: API
    kind: service
    zone: backend
    exposure: internet

flows:
  - id: browser-to-api
    from: browser
    to: api
    over: HTTPS
    carries: [user-data]
`

// LayoutsResult is returned by SetLayouts.
type layoutBatch = map[string]map[string]float64

// SetLayouts sets (or, for nil entries, removes) many diagram positions in
// one edit, e.g. when the first drag saves the automatic layout.
func SetLayouts(source []byte, positions layoutBatch) (EditResult, error) {
	ids := make([]string, 0, len(positions))
	for id := range positions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return guard(source, func(d *edit.Doc) error {
		for _, id := range ids {
			if err := d.SetLayout(id, positions[id]); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetSignoff records (or, with nil, removes) a security sign-off of the
// whole model. It's a person's statement, so MCP doesn't expose it.
func SetSignoff(source []byte, s *model.Signoff) (EditResult, error) {
	if s != nil && (s.By == "" || s.On == "") {
		return EditResult{}, fail("A sign-off needs `by` and `on` (a date).")
	}
	return guard(source, func(d *edit.Doc) error {
		if s == nil {
			return d.SetSignoff(nil)
		}
		f := map[string]any{"by": s.By, "on": s.On}
		if s.Note != "" {
			f["note"] = s.Note
		}
		return d.SetSignoff(f)
	})
}

// --- JSON dispatch, used by the WASM bridge and MCP ---

// Request is the envelope for Call.
type Request struct {
	Source      string             `json:"source"`
	Section     string             `json:"section,omitempty"`
	ID          string             `json:"id,omitempty"`
	Fields      map[string]any     `json:"fields,omitempty"`
	Position    map[string]float64 `json:"position,omitempty"`
	Status      *StatusRequest     `json:"status,omitempty"`
	AllowAccept bool               `json:"allow_accept,omitempty"`
	// For suggestions: the catalog entry (catalog:<catalog>/<entry>), the
	// component or flow it's for, and custom catalog sources by path.
	From     string            `json:"from,omitempty"`
	Target   string            `json:"target,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Catalogs map[string]string `json:"catalogs,omitempty"`
	// For simulation: where the attacker starts and which data to reach.
	Start   string   `json:"start,omitempty"`
	Targets []string `json:"targets,omitempty"`
	// For set_layouts: positions by ID (null removes one). For new: the name.
	Positions map[string]map[string]float64 `json:"positions,omitempty"`
	Name      string                        `json:"name,omitempty"`
	// For set_signoff; null removes the sign-off.
	Signoff *model.Signoff `json:"signoff,omitempty"`
}

// Names lists the operations Call understands.
var Names = []string{"validate", "format", "show", "explain", "upsert", "delete", "set_system", "set_layout", "set_status",
	"suggest", "accept_suggestion", "dismiss_suggestion", "paths", "blast_radius", "set_layouts", "new", "report", "set_signoff"}

// Call runs an operation from a JSON request and returns a JSON response:
// {"result": ...} on success or {"error": {"message": ..., "diagnostics": [...]}}.
func Call(op string, request []byte) []byte {
	res, err := call(op, request)
	if err != nil {
		e, ok := err.(*Error)
		if !ok {
			e = &Error{Message: err.Error()}
		}
		b, _ := json.Marshal(map[string]any{"error": e})
		return b
	}
	b, err := json.Marshal(map[string]any{"result": res})
	if err != nil {
		b, _ = json.Marshal(map[string]any{"error": &Error{Message: "internal error: " + err.Error()}})
	}
	return b
}

func call(op string, request []byte) (any, error) {
	var req Request
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fail("Bad request: %v", err)
	}
	src := []byte(req.Source)
	switch op {
	case "validate":
		return Validate(src), nil
	case "format":
		return Format(src)
	case "show":
		return Show(src)
	case "explain":
		return Explain(src, req.ID)
	case "upsert":
		return Upsert(src, req.Section, req.ID, req.Fields)
	case "delete":
		return Delete(src, req.Section, req.ID)
	case "set_system":
		return SetSystem(src, req.Fields)
	case "set_layout":
		return SetLayout(src, req.ID, req.Position)
	case "set_status":
		if req.Status == nil {
			return nil, fail("set_status needs a `status` object.")
		}
		return SetStatus(src, *req.Status, req.AllowAccept)
	case "suggest":
		return Suggest(src, req.Target, req.Catalogs)
	case "accept_suggestion":
		return AcceptSuggestion(src, req.From, req.Target, req.Fields, req.Catalogs)
	case "dismiss_suggestion":
		return DismissSuggestion(src, req.From, req.Target, req.Reason, req.Catalogs)
	case "paths":
		return Paths(src, req.Start, req.Targets)
	case "blast_radius":
		return BlastRadius(src, req.ID)
	case "set_layouts":
		return SetLayouts(src, req.Positions)
	case "new":
		return New(req.Name)
	case "report":
		return Report(src)
	case "set_signoff":
		return SetSignoff(src, req.Signoff)
	}
	return nil, fail("Unknown operation `%s`; use one of %s.", op, strings.Join(Names, ", "))
}
