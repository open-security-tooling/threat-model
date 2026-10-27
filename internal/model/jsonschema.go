package model

import "encoding/json"

// SchemaURL is where the published JSON Schema for this version lives.
const SchemaURL = "https://open-security-tooling.github.io/threat-model/schema/v1.json"

// JSONSchema returns the JSON Schema for the file format, generated from the
// same table the parser checks against. Editors use it for autocomplete via
// the `# yaml-language-server: $schema=...` header.
func JSONSchema() []byte {
	root := objectSchema(rootObj)
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["$id"] = SchemaURL
	root["title"] = "threat-model file (threatmodel.yaml)"
	b, _ := json.MarshalIndent(root, "", "  ")
	return append(b, '\n')
}

func objectSchema(o *object) map[string]any {
	props := map[string]any{}
	var required []string
	for _, f := range o.Fields {
		props[f.Name] = fieldSchema(f)
		if f.Required {
			required = append(required, f.Name)
		}
	}
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

var idSchema = map[string]any{"type": "string", "pattern": idPattern.String()}

func fieldSchema(f field) map[string]any {
	var s map[string]any
	str := func() map[string]any {
		if f.Enum != nil {
			return map[string]any{"enum": f.Enum}
		}
		return map[string]any{"type": "string"}
	}
	switch f.Kind {
	case kString:
		s = str()
		if f.Name == "id" {
			s = idSchema
		}
	case kInt:
		s = map[string]any{"type": "integer"}
		if f.Name == "version" {
			s["const"] = Version
		}
	case kNumber:
		s = map[string]any{"type": "number"}
	case kBool:
		s = map[string]any{"type": "boolean"}
	case kReviewed:
		s = map[string]any{"oneOf": []any{
			map[string]any{"type": "string", "format": "date"},
			objectSchema(reviewedObj),
		}}
	case kConsidered:
		props := map[string]any{}
		for _, k := range ThreatKinds {
			props[k] = map[string]any{"type": "string"}
		}
		s = map[string]any{"type": "object", "additionalProperties": false, "properties": props}
	case kDate:
		s = map[string]any{"type": "string", "format": "date"}
	case kStringList:
		s = map[string]any{"type": "array", "items": str()}
	case kObject:
		s = objectSchema(f.Obj)
	case kObjectList:
		s = map[string]any{"type": "array", "items": objectSchema(f.Obj)}
	case kEffect:
		s = map[string]any{"oneOf": []any{
			map[string]any{"enum": []string{"eliminates", "detects"}},
			map[string]any{"type": "object", "additionalProperties": false, "minProperties": 1, "properties": map[string]any{
				"who": map[string]any{"enum": WhoLevels}, "effort": map[string]any{"enum": Efforts}, "impact": map[string]any{"enum": Impacts},
			}},
		}}
	case kEvidenceList:
		one := func(k string) map[string]any {
			return map[string]any{"type": "object", "additionalProperties": false, "required": []string{k},
				"properties": map[string]any{k: map[string]any{"type": "string"}}}
		}
		s = map[string]any{"type": "array", "items": map[string]any{"oneOf": []any{one("code"), one("test"), one("link")}}}
	case kCatalogList:
		s = map[string]any{"type": "array", "items": map[string]any{"oneOf": []any{
			map[string]any{"type": "string", "pattern": "^builtin:[a-z0-9-]+$"},
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"path"}, "properties": map[string]any{"path": map[string]any{"type": "string"}}},
		}}}
	case kLayoutMap:
		num := map[string]any{"type": "number"}
		s = map[string]any{"type": "object", "additionalProperties": map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"x", "y"},
			"properties": map[string]any{"x": num, "y": num, "w": num, "h": num},
		}}
	case kRefs:
		s = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}
	}
	if f.Doc != "" {
		s = withDescription(s, f.Doc)
	}
	return s
}

func withDescription(s map[string]any, doc string) map[string]any {
	out := make(map[string]any, len(s)+1)
	for k, v := range s {
		out[k] = v
	}
	out["description"] = doc
	return out
}
