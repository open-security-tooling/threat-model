package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
)

// Meta describes where a register came from. The caller supplies all of it,
// so the output depends only on the inputs.
type Meta struct {
	// Model is the system's name; empty means use the model's system.name.
	Model       string
	GeneratedAt time.Time
	// Commit is the git commit SHA the model was read at.
	Commit string
	// File is the model file's path, relative to the repository root.
	File string
}

// Row is one threat in the risk register.
type Row struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Kind  string `json:"kind,omitempty"`
	// Components are the components the threat affects. For a threat on a
	// flow, that's the component the flow goes to, which is the one that
	// has to defend against it (the same rule as the coverage view).
	Components []RowComponent `json:"components"`
	// Zones are the names of the zones those components sit in, deduplicated.
	Zones         []string `json:"zones"`
	InherentLevel string   `json:"inherent_level,omitempty"`
	ResidualLevel string   `json:"residual_level,omitempty"`
	Status        string   `json:"status"`
	Why           string   `json:"why"`
	// Reason is why a not-applicable threat doesn't apply.
	Reason      string          `json:"reason,omitempty"`
	Mitigations []RowMitigation `json:"mitigations"`
	Accepted    *RowAcceptance  `json:"accepted,omitempty"`
	// Refs are mappings such as cwe and owasp; RefsText flattens them to
	// "cwe: CWE-639; owasp: API1:2023".
	Refs     map[string][]string `json:"refs,omitempty"`
	RefsText string              `json:"refs_text,omitempty"`
	// EvidencePresent is true when at least one linked mitigation lists
	// evidence. It says the model claims evidence; `threat check` is what
	// confirms the files still exist.
	EvidencePresent bool `json:"evidence_present"`
	// Reviewed is the least recent review across the affected components
	// (empty if any of them was never reviewed), and ReviewedBy who did it.
	Reviewed   string `json:"reviewed,omitempty"`
	ReviewedBy string `json:"reviewed_by,omitempty"`

	ModelName   string `json:"model"`
	File        string `json:"file,omitempty"`
	Commit      string `json:"commit,omitempty"`
	GeneratedAt string `json:"generated_at,omitempty"`
}

type RowComponent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Zone       string `json:"zone,omitempty"`
	Reviewed   string `json:"reviewed,omitempty"`
	ReviewedBy string `json:"reviewed_by,omitempty"`
}

type RowMitigation struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Owner       string `json:"owner,omitempty"`
	Due         string `json:"due,omitempty"`
	HasEvidence bool   `json:"has_evidence"`
}

type RowAcceptance struct {
	By     string `json:"by"`
	Until  string `json:"until"`
	Reason string `json:"reason"`
}

// Register builds one row per threat, in the order the model lists them.
func Register(v ops.View, meta Meta) ([]Row, error) {
	m := v.Model
	if m == nil {
		return nil, errors.New("the file can't be read as a threat model, so there's no register to export; run `threat validate` to see why")
	}
	name := meta.Model
	if name == "" {
		name = m.System.Name
	}
	generated := ""
	if !meta.GeneratedAt.IsZero() {
		generated = meta.GeneratedAt.UTC().Format(time.RFC3339)
	}
	rows := make([]Row, 0, len(m.Threats))
	for i := range m.Threats {
		t := &m.Threats[i]
		a := v.Risks[t.ID]
		row := Row{
			ID: t.ID, Title: t.Title, Kind: t.Kind, Status: t.Status, Why: a.Why, Reason: t.Reason,
			InherentLevel: a.InherentLevel, ResidualLevel: a.Level,
			Components: []RowComponent{}, Zones: []string{}, Mitigations: []RowMitigation{},
			ModelName: name, File: meta.File, Commit: meta.Commit, GeneratedAt: generated,
		}
		if t.Status == "not-applicable" {
			row.InherentLevel, row.ResidualLevel = "", ""
		}
		for _, c := range affectedComponents(m, t) {
			zone := c.Zone
			if z := m.Zone(c.Zone); z != nil {
				zone = z.Name
			}
			row.Components = append(row.Components, RowComponent{ID: c.ID, Name: c.Name, Zone: zone, Reviewed: c.Reviewed, ReviewedBy: c.ReviewedBy})
			if zone != "" && !slices.Contains(row.Zones, zone) {
				row.Zones = append(row.Zones, zone)
			}
		}
		row.Reviewed, row.ReviewedBy = oldestReview(row.Components)
		for _, id := range t.Mitigations {
			mt := m.Mitigation(id)
			if mt == nil {
				row.Mitigations = append(row.Mitigations, RowMitigation{ID: id})
				continue
			}
			rm := RowMitigation{ID: mt.ID, Title: mt.Title, Status: mt.Status, Owner: mt.Owner, Due: mt.Due, HasEvidence: len(mt.Evidence) > 0}
			row.EvidencePresent = row.EvidencePresent || rm.HasEvidence
			row.Mitigations = append(row.Mitigations, rm)
		}
		if t.Accepted != nil {
			row.Accepted = &RowAcceptance{By: t.Accepted.By, Until: t.Accepted.Until, Reason: t.Accepted.Reason}
		}
		if len(t.Refs) > 0 {
			row.Refs = map[string][]string(t.Refs)
			row.RefsText = flattenRefs(t.Refs)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func affectedComponents(m *model.Model, t *model.Threat) []*model.Component {
	var out []*model.Component
	add := func(id string) {
		c := m.Component(id)
		if c != nil && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	for _, id := range t.Affects {
		if f := m.Flow(id); f != nil {
			add(f.To)
		} else {
			add(id)
		}
	}
	return out
}

// oldestReview is the review that's most out of date: never reviewed beats
// any date, and an earlier date beats a later one.
func oldestReview(cs []RowComponent) (string, string) {
	if len(cs) == 0 {
		return "", ""
	}
	best := cs[0]
	for _, c := range cs[1:] {
		if best.Reviewed == "" {
			break
		}
		if c.Reviewed == "" || c.Reviewed < best.Reviewed {
			best = c
		}
	}
	if best.Reviewed == "" {
		return "", ""
	}
	return best.Reviewed, best.ReviewedBy
}

func flattenRefs(refs model.Refs) string {
	keys := make([]string, 0, len(refs))
	for k := range refs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+strings.Join(refs[k], ", "))
	}
	return strings.Join(parts, "; ")
}

// RegisterColumns are the CSV header, in order. Lists inside a cell are
// separated by "; ", and the mitigation columns line up item by item
// ("none" fills an empty owner or due date so they stay aligned).
var RegisterColumns = []string{
	"id", "title", "kind", "status", "inherent_level", "residual_level", "why", "reason",
	"components", "zones",
	"mitigation_ids", "mitigation_titles", "mitigation_statuses", "mitigation_owners", "mitigation_due",
	"accepted_by", "accepted_until", "accepted_reason",
	"refs", "evidence_present", "reviewed", "reviewed_by",
	"model", "file", "commit", "generated_at",
}

// RegisterCSV renders rows as CSV that's safe to open in a spreadsheet.
func RegisterCSV(rows []Row) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.UseCRLF = true // what Excel expects (RFC 4180)
	_ = w.Write(RegisterColumns)
	for _, r := range rows {
		var names, ids, titles, statuses, owners, due []string
		for _, c := range r.Components {
			names = append(names, c.Name)
		}
		for _, mt := range r.Mitigations {
			ids = append(ids, mt.ID)
			titles = append(titles, mt.Title)
			statuses = append(statuses, orNone(mt.Status))
			owners = append(owners, orNone(mt.Owner))
			due = append(due, orNone(mt.Due))
		}
		var acc RowAcceptance
		if r.Accepted != nil {
			acc = *r.Accepted
		}
		evidence := "no"
		if r.EvidencePresent {
			evidence = "yes"
		}
		record := []string{
			r.ID, r.Title, r.Kind, r.Status, r.InherentLevel, r.ResidualLevel, r.Why, r.Reason,
			list(names), list(r.Zones),
			list(ids), list(titles), list(statuses), list(owners), list(due),
			acc.By, acc.Until, acc.Reason,
			r.RefsText, evidence, r.Reviewed, r.ReviewedBy,
			r.ModelName, r.File, r.Commit, r.GeneratedAt,
		}
		for i := range record {
			record[i] = csvCell(record[i])
		}
		_ = w.Write(record)
	}
	w.Flush()
	return buf.Bytes()
}

func list(items []string) string { return strings.Join(items, "; ") }

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// csvCell stops a spreadsheet from treating model text as a formula. A
// cell starting with = + - @ tab or CR can run a formula (and through DDE,
// a command) when the file is opened, so it gets a leading apostrophe,
// which spreadsheets read as "this is text".
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// RegisterJSON renders rows as JSON: {"version": 1, "threats": [...]}.
func RegisterJSON(rows []Row) []byte {
	if rows == nil {
		rows = []Row{}
	}
	b, err := json.MarshalIndent(struct {
		Version int   `json:"version"`
		Threats []Row `json:"threats"`
	}{1, rows}, "", "  ")
	if err != nil {
		// Rows hold only strings, bools, slices and maps of strings.
		panic(err)
	}
	return append(b, '\n')
}
