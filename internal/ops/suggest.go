package ops

import (
	"sort"

	"github.com/open-security-tooling/threat-model/internal/catalog"
	"github.com/open-security-tooling/threat-model/internal/edit"
	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/risk"
)

// catalogsFor returns the catalogs a model asks for. Custom catalogs are
// passed in by the caller (keyed by the path in the model), because ops
// never read files themselves.
func catalogsFor(m *model.Model, custom map[string]string) ([]catalog.Catalog, error) {
	builtin, err := catalog.Builtin()
	if err != nil {
		return nil, err
	}
	if len(m.Catalogs) == 0 {
		return builtin, nil
	}
	var out []catalog.Catalog
	for _, ref := range m.Catalogs {
		if ref.Builtin != "" {
			found := false
			for _, c := range builtin {
				if c.Name == ref.Builtin {
					out, found = append(out, c), true
				}
			}
			if !found {
				return nil, fail("The model asks for catalog `builtin:%s`, which doesn't exist.", ref.Builtin)
			}
			continue
		}
		src, ok := custom[ref.Path]
		if !ok {
			return nil, fail("Catalog %s wasn't provided.", ref.Path)
		}
		c, err := catalog.Parse(ref.Path, []byte(src))
		if err != nil {
			return nil, fail("%v", err)
		}
		out = append(out, c)
	}
	return out, nil
}

type SuggestResult struct {
	Suggestions []catalog.Suggestion `json:"suggestions"`
}

// Suggest lists library threats that match the model and haven't been
// accepted or dismissed yet. target narrows it to one component or flow.
func Suggest(source []byte, target string, custom map[string]string) (SuggestResult, error) {
	l := Load(source)
	if l.Model == nil {
		return SuggestResult{}, &Error{Message: "The file can't be read as a threat model.", Diagnostics: l.Diagnostics}
	}
	if target != "" && l.Model.Component(target) == nil && l.Model.Flow(target) == nil && l.Model.IdentityItem(target) == nil {
		return SuggestResult{}, fail("There's no component, flow or identity `%s`.", target)
	}
	cats, err := catalogsFor(l.Model, custom)
	if err != nil {
		return SuggestResult{}, err
	}
	s := catalog.Suggest(l.Model, cats, target)
	// Highest risk first, then grouped by what they're for.
	sort.SliceStable(s, func(i, j int) bool {
		if ri, rj := risk.Rank(s[i].Level), risk.Rank(s[j].Level); ri != rj {
			return ri > rj
		}
		return s[i].Target < s[j].Target
	})
	if s == nil {
		s = []catalog.Suggestion{}
	}
	return SuggestResult{Suggestions: s}, nil
}

func findSuggestion(source []byte, from, target string, custom map[string]string) (catalog.Suggestion, error) {
	r, err := Suggest(source, target, custom)
	if err != nil {
		return catalog.Suggestion{}, err
	}
	for _, s := range r.Suggestions {
		if s.From == from && s.Target == target {
			return s, nil
		}
	}
	return catalog.Suggestion{}, fail("There's no open suggestion %s for `%s`; it may already be accepted or dismissed.", from, target)
}

// AcceptSuggestion adds a suggested threat and any of its mitigations the
// model doesn't have yet. Fields in overrides replace the suggested values.
func AcceptSuggestion(source []byte, from, target string, overrides map[string]any, custom map[string]string) (EditResult, error) {
	s, err := findSuggestion(source, from, target, custom)
	if err != nil {
		return EditResult{}, err
	}
	t := s.Threat
	fields := map[string]any{
		"title": t.Title, "kind": t.Kind, "affects": toAny(t.Affects), "attack": toAny(t.Attack),
		"who": t.Who, "effort": t.Effort, "impact": t.Impact, "status": "open",
		"mitigations": toAny(t.Mitigations), "from": t.From,
	}
	if g := t.Gives; g != nil {
		gives := map[string]any{}
		if len(g.Reads) > 0 {
			gives["reads"] = toAny(g.Reads)
		}
		if len(g.Changes) > 0 {
			gives["changes"] = toAny(g.Changes)
		}
		if len(g.Controls) > 0 {
			gives["controls"] = toAny(g.Controls)
		}
		if g.Access != "" {
			gives["access"] = g.Access
		}
		fields["gives"] = gives
	}
	if len(t.Refs) > 0 {
		refs := map[string]any{}
		for k, v := range t.Refs {
			refs[k] = toAny(v)
		}
		fields["refs"] = refs
	}
	for k, v := range overrides {
		if k == "status" && v == "accepted" {
			return EditResult{}, fail("Use set_status to accept a risk.")
		}
		fields[k] = v
	}
	l := Load(source)
	r, err := guard(source, func(d *edit.Doc) error {
		for _, mt := range s.Mitigations {
			if l.Model.Mitigation(mt.ID) != nil {
				continue
			}
			mf := map[string]any{"title": mt.Title, "status": "planned"}
			if mt.Effect != nil {
				mf["effect"] = effectValue(*mt.Effect)
			}
			if _, err := d.Upsert("mitigations", mt.ID, mf); err != nil {
				return err
			}
		}
		_, err := d.Upsert("threats", t.ID, fields)
		return err
	})
	r.Created = err == nil
	return r, err
}

// DismissSuggestion records that a suggestion was considered and doesn't
// apply, so it isn't suggested again and reviewers can see why.
func DismissSuggestion(source []byte, from, target, reason string, custom map[string]string) (EditResult, error) {
	if reason == "" {
		return EditResult{}, fail("Say in one line why the suggestion doesn't apply (`reason`).")
	}
	s, err := findSuggestion(source, from, target, custom)
	if err != nil {
		return EditResult{}, err
	}
	return guard(source, func(d *edit.Doc) error {
		// Keep the suggested answers, so reports and reviewers can see how
		// serious the dismissed threat would have been.
		_, err := d.Upsert("threats", s.Threat.ID, map[string]any{
			"title": s.Threat.Title, "kind": s.Threat.Kind, "affects": toAny(s.Threat.Affects),
			"who": s.Threat.Who, "effort": s.Threat.Effort, "impact": s.Threat.Impact,
			"status": "not-applicable", "reason": reason, "from": s.From,
		})
		return err
	})
}

func effectValue(e model.Effect) any {
	switch {
	case e.Eliminates:
		return "eliminates"
	case e.Detects:
		return "detects"
	}
	m := map[string]any{}
	if e.Who != "" {
		m["who"] = e.Who
	}
	if e.Effort != "" {
		m["effort"] = e.Effort
	}
	if e.Impact != "" {
		m["impact"] = e.Impact
	}
	return m
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
