package model

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml/token"
)

var reviewedObj = &object{Name: "reviewed", Fields: []field{
	{Name: "on", Kind: kDate, Required: true},
	{Name: "by", Kind: kString, Required: true},
}}

// shapeChecker checks a decoded YAML value against the schema table, so
// problems are reported with the field's path and line, in plain language.
type shapeChecker struct {
	pos   map[string]token.Position
	diags Diagnostics
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func (c *shapeChecker) add(sev, code, path, msg, hint string) {
	p := c.pos[path]
	c.diags = append(c.diags, Diagnostic{Severity: sev, Code: code, Path: path, Line: p.Line, Column: p.Column, Message: msg, Hint: hint})
}

// label names an item for messages, e.g. "Threat `read-others-invoices`".
func label(o *object, item map[string]any, path string) string {
	name := strings.ToUpper(o.Name[:1]) + o.Name[1:]
	if id, ok := item["id"].(string); ok && id != "" {
		return fmt.Sprintf("%s `%s`", name, id)
	}
	return fmt.Sprintf("%s at %s", name, path)
}

func typeName(v any) string {
	switch v.(type) {
	case string:
		return "text"
	case bool:
		return "true/false"
	case int, int64, uint64, float64:
		return "a number"
	case []any:
		return "a list"
	case map[string]any:
		return "a map"
	case nil:
		return "empty"
	}
	return fmt.Sprintf("%T", v)
}

func (c *shapeChecker) object(path, who string, v any, o *object) {
	m, ok := v.(map[string]any)
	if !ok {
		c.add(SevError, "type", path, fmt.Sprintf("%s should be a map of fields, but it's %s.", who, typeName(v)), "")
		return
	}
	for key, val := range m {
		f := o.field(key)
		if f == nil {
			c.add(SevError, "unknown-field", join(path, key),
				fmt.Sprintf("%s has an unknown field `%s`.", who, key), suggestHint(key, o.names()))
			continue
		}
		if val == nil {
			continue
		}
		c.field(join(path, key), who, val, f)
	}
	for _, f := range o.Fields {
		if !f.Required {
			continue
		}
		if val, ok := m[f.Name]; !ok || val == nil || val == "" {
			c.add(SevError, "missing-field", path, fmt.Sprintf("%s is missing `%s`.", who, f.Name), "")
		}
	}
}

func (c *shapeChecker) field(path, who string, v any, f *field) {
	switch f.Kind {
	case kString:
		c.str(path, who, f.Name, v, f.Enum)
	case kReviewed:
		if m, ok := v.(map[string]any); ok {
			c.object(path, who+": `reviewed`", m, reviewedObj)
			return
		}
		c.field(path, who, v, &field{Name: f.Name, Kind: kDate})
	case kConsidered:
		m, ok := v.(map[string]any)
		if !ok {
			c.add(SevError, "type", path, fmt.Sprintf("%s: `considered` should map threat kinds to why they don't apply, e.g. `{disrupt: \"Stateless and autoscaled\"}`.", who), "")
			return
		}
		for k, val := range m {
			if !slices.Contains(ThreatKinds, k) {
				c.add(SevError, "enum", join(path, k), fmt.Sprintf("%s: `considered` has `%s`, which isn't a threat kind (%s).", who, k, oneOf(ThreatKinds)), suggestHint(k, ThreatKinds))
				continue
			}
			c.str(join(path, k), who, "considered."+k, val, nil)
		}
	case kBool:
		if _, ok := v.(bool); !ok {
			c.add(SevError, "type", path, fmt.Sprintf("%s: `%s` should be true or false.", who, f.Name), "")
		}
	case kInt:
		if _, ok := v.(uint64); !ok {
			if _, ok := v.(int64); !ok {
				c.add(SevError, "type", path, fmt.Sprintf("%s: `%s` should be a whole number.", who, f.Name), "")
			}
		}
	case kNumber:
		switch v.(type) {
		case uint64, int64, float64:
		default:
			c.add(SevError, "type", path, fmt.Sprintf("%s: `%s` should be a number.", who, f.Name), "")
		}
	case kDate:
		s, ok := v.(string)
		if _, err := time.Parse(time.DateOnly, s); !ok || err != nil {
			c.add(SevError, "date", path, fmt.Sprintf("%s: `%s` should be a date like 2026-10-27.", who, f.Name), "")
		}
	case kStringList:
		list, ok := v.([]any)
		if !ok {
			hint := ""
			if s, isStr := v.(string); isStr {
				hint = fmt.Sprintf("Write it as a list: `%s: [%s]`.", f.Name, s)
			}
			c.add(SevError, "type", path, fmt.Sprintf("%s: `%s` should be a list.", who, f.Name), hint)
			return
		}
		for i, item := range list {
			c.str(path+"["+strconv.Itoa(i)+"]", who, f.Name, item, f.Enum)
		}
	case kObject:
		sub := who + ": `" + f.Name + "`"
		c.object(path, sub, v, f.Obj)
	case kObjectList:
		list, ok := v.([]any)
		if !ok {
			c.add(SevError, "type", path, fmt.Sprintf("`%s` should be a list, with each item starting with `- id: ...`.", f.Name), "")
			return
		}
		for i, item := range list {
			p := path + "[" + strconv.Itoa(i) + "]"
			m, _ := item.(map[string]any)
			c.object(p, label(f.Obj, m, p), item, f.Obj)
		}
	case kEffect:
		c.effect(path, who, v)
	case kEvidenceList:
		c.evidence(path, who, v)
	case kCatalogList:
		c.catalogs(path, v)
	case kLayoutMap:
		c.layout(path, v)
	case kRefs:
		m, ok := v.(map[string]any)
		if !ok {
			c.add(SevError, "type", path, fmt.Sprintf("%s: `refs` should be a map like `cwe: [CWE-639]`.", who), "")
			return
		}
		for k, val := range m {
			if list, ok := val.([]any); ok {
				for i, item := range list {
					c.str(join(path, k)+"["+strconv.Itoa(i)+"]", who, "refs."+k, item, nil)
				}
			} else {
				c.add(SevError, "type", join(path, k), fmt.Sprintf("%s: `refs.%s` should be a list, e.g. `%s: [...]`.", who, k, k), "")
			}
		}
	}
}

func (c *shapeChecker) str(path, who, name string, v any, enum []string) {
	s, ok := v.(string)
	if !ok {
		hint := ""
		if _, isNum := v.(float64); isNum || typeName(v) == "a number" || typeName(v) == "true/false" {
			hint = "Put it in quotes so YAML keeps it as text."
		}
		c.add(SevError, "type", path, fmt.Sprintf("%s: `%s` should be text, but it's %s.", who, name, typeName(v)), hint)
		return
	}
	if enum != nil && !slices.Contains(enum, s) {
		c.add(SevError, "enum", path, fmt.Sprintf("%s: `%s` is `%s`, which isn't one of %s.", who, name, s, oneOf(enum)), suggestHint(s, enum))
	}
}

func (c *shapeChecker) effect(path, who string, v any) {
	switch e := v.(type) {
	case string:
		if e != "eliminates" && e != "detects" {
			c.add(SevError, "enum", path, fmt.Sprintf("%s: `effect` is `%s`.", who, e),
				"Use `eliminates`, `detects`, or a map like `{effort: hard}`.")
		}
	case map[string]any:
		if len(e) == 0 {
			c.add(SevError, "type", path, fmt.Sprintf("%s: `effect` is an empty map.", who), "Set at least one of who, effort or impact.")
		}
		enums := map[string][]string{"who": WhoLevels, "effort": Efforts, "impact": Impacts}
		for k, val := range e {
			enum, ok := enums[k]
			if !ok {
				c.add(SevError, "unknown-field", join(path, k), fmt.Sprintf("%s: `effect` can only change who, effort or impact, not `%s`.", who, k), suggestHint(k, []string{"who", "effort", "impact"}))
				continue
			}
			c.str(join(path, k), who, "effect."+k, val, enum)
		}
	default:
		c.add(SevError, "type", path, fmt.Sprintf("%s: `effect` should be `eliminates`, `detects`, or a map like `{effort: hard}`.", who), "")
	}
}

func (c *shapeChecker) evidence(path, who string, v any) {
	list, ok := v.([]any)
	if !ok {
		c.add(SevError, "type", path, fmt.Sprintf("%s: `evidence` should be a list like `- test: path/to/file_test.go#TestName`.", who), "")
		return
	}
	for i, item := range list {
		p := path + "[" + strconv.Itoa(i) + "]"
		m, ok := item.(map[string]any)
		if !ok || len(m) != 1 {
			c.add(SevError, "type", p, fmt.Sprintf("%s: each evidence entry is one of `code: ...`, `test: ...` or `link: ...`.", who), "")
			continue
		}
		for k, val := range m {
			if !slices.Contains(evidenceTypes, k) {
				c.add(SevError, "enum", join(p, k), fmt.Sprintf("%s: evidence type `%s` isn't one of %s.", who, k, oneOf(evidenceTypes)), suggestHint(k, evidenceTypes))
				continue
			}
			c.str(join(p, k), who, "evidence."+k, val, nil)
		}
	}
}

func (c *shapeChecker) catalogs(path string, v any) {
	list, ok := v.([]any)
	if !ok {
		c.add(SevError, "type", path, "`catalogs` should be a list like `- builtin:web`.", "")
		return
	}
	for i, item := range list {
		p := path + "[" + strconv.Itoa(i) + "]"
		switch it := item.(type) {
		case string:
			if !strings.HasPrefix(it, "builtin:") || len(it) == len("builtin:") {
				c.add(SevError, "type", p, fmt.Sprintf("Catalog `%s` should be `builtin:<name>` or `path: file.yaml`.", it), "")
			}
		case map[string]any:
			if s, ok := it["path"].(string); !ok || s == "" || len(it) != 1 {
				c.add(SevError, "type", p, "Custom catalogs are written as `- path: security/our-threats.yaml`.", "")
			}
		default:
			c.add(SevError, "type", p, "Catalog entries are `builtin:<name>` or `path: file.yaml`.", "")
		}
	}
}

func (c *shapeChecker) layout(path string, v any) {
	m, ok := v.(map[string]any)
	if !ok {
		c.add(SevError, "type", path, "`layout` should map IDs to positions, like `api: {x: 100, y: 40}`.", "")
		return
	}
	for id, pos := range m {
		p := join(path, id)
		pm, ok := pos.(map[string]any)
		if !ok {
			c.add(SevError, "type", p, fmt.Sprintf("Layout for `%s` should look like `{x: 100, y: 40}`.", id), "")
			continue
		}
		for k, val := range pm {
			if !slices.Contains([]string{"x", "y", "w", "h"}, k) {
				c.add(SevError, "unknown-field", join(p, k), fmt.Sprintf("Layout for `%s` has an unknown field `%s`; use x, y, w and h.", id, k), "")
				continue
			}
			switch val.(type) {
			case uint64, int64, float64:
			default:
				c.add(SevError, "type", join(p, k), fmt.Sprintf("Layout for `%s`: `%s` should be a number.", id, k), "")
			}
		}
	}
}
