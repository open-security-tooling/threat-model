// Package edit changes model files in place, keeping comments, the order
// items were written in, and blank lines, so tool and agent edits show up as
// small diffs. It also defines the canonical format (`threat fmt`).
package edit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"

	"github.com/open-security-tooling/threat-model/internal/model"
)

// Doc is an editable model file.
type Doc struct {
	file *ast.File
}

// Parse reads a file for editing. Callers should have checked it with
// model.Parse first; Parse here only needs it to be YAML.
func Parse(src []byte) (*Doc, error) {
	if len(src) > model.DefaultLimits.MaxBytes {
		return nil, fmt.Errorf("file is larger than %d bytes", model.DefaultLimits.MaxBytes)
	}
	f, err := parser.ParseBytes(src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if len(f.Docs) != 1 || f.Docs[0].Body == nil {
		return nil, fmt.Errorf("a model file holds exactly one YAML document")
	}
	return &Doc{file: f}, nil
}

// Bytes prints the document in canonical form.
func (d *Doc) Bytes() []byte {
	s := d.file.String()
	s = strings.TrimRight(s, "\n") + "\n"
	return []byte(s)
}

// Format returns src in canonical form.
func Format(src []byte) ([]byte, error) {
	d, err := Parse(src)
	if err != nil {
		return nil, err
	}
	return d.Bytes(), nil
}

func (d *Doc) root() (*ast.MappingNode, error) {
	switch b := d.file.Docs[0].Body.(type) {
	case *ast.MappingNode:
		return b, nil
	case *ast.MappingValueNode:
		// A single top-level key parses as a bare pair; normalise to a mapping.
		m := ast.Mapping(b.GetToken(), false, b)
		d.file.Docs[0].Body = m
		return m, nil
	}
	return nil, fmt.Errorf("the top level of a model file must be a map")
}

func keyIndex(m *ast.MappingNode, key string) int {
	for i, mv := range m.Values {
		if mv.Key.String() == key {
			return i
		}
	}
	return -1
}

var idRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// itemIndex finds the item with the given id in a section's list.
func itemIndex(seq *ast.SequenceNode, id string) int {
	for i, v := range seq.Values {
		if m := asMapping(v); m != nil {
			if k := keyIndex(m, "id"); k >= 0 && scalarString(m.Values[k].Value) == id {
				return i
			}
		}
	}
	return -1
}

func asMapping(n ast.Node) *ast.MappingNode {
	switch n := n.(type) {
	case *ast.MappingNode:
		return n
	case *ast.MappingValueNode:
		return nil
	}
	return nil
}

func scalarString(n ast.Node) string {
	if s, ok := n.(*ast.StringNode); ok {
		return s.Value
	}
	if n == nil {
		return ""
	}
	return n.String()
}

func (d *Doc) section(name string) (*ast.SequenceNode, error) {
	root, err := d.root()
	if err != nil {
		return nil, err
	}
	i := keyIndex(root, name)
	if i < 0 {
		return nil, nil
	}
	seq, ok := root.Values[i].Value.(*ast.SequenceNode)
	if !ok {
		if _, isNull := root.Values[i].Value.(*ast.NullNode); isNull {
			return nil, nil
		}
		return nil, fmt.Errorf("`%s` must be a list", name)
	}
	return seq, nil
}

// Has reports whether an item exists.
func (d *Doc) Has(section, id string) bool {
	seq, err := d.section(section)
	return err == nil && seq != nil && itemIndex(seq, id) >= 0
}

// Upsert creates or updates the item with the given id. Fields are patched:
// fields not mentioned are left alone, and a nil value removes a field.
// It reports whether the item was created.
func (d *Doc) Upsert(section, id string, fields map[string]any) (created bool, err error) {
	if !slices.Contains(model.Sections, section) {
		return false, fmt.Errorf("unknown section %q", section)
	}
	if !idRe.MatchString(id) {
		return false, fmt.Errorf("ID %q should be lowercase letters, digits and dashes", id)
	}
	if v, ok := fields["id"]; ok && v != id {
		return false, fmt.Errorf("can't change an item's id with upsert; delete and re-create it")
	}
	order := model.FieldOrder(section)
	seq, err := d.section(section)
	if err != nil {
		return false, err
	}
	if seq == nil || itemIndex(seq, id) < 0 {
		return true, d.appendItem(section, id, fields, order)
	}
	i := itemIndex(seq, id)
	return false, d.patchMapping(fmt.Sprintf("$.%s[%d]", section, i), asMapping(seq.Values[i]), fields, order)
}

// Delete removes an item and its comments.
func (d *Doc) Delete(section, id string) error {
	seq, err := d.section(section)
	if err != nil {
		return err
	}
	if seq == nil || itemIndex(seq, id) < 0 {
		return fmt.Errorf("no %s item with id %q", section, id)
	}
	i := itemIndex(seq, id)
	// Keep the blank line that separated the deleted item from its
	// predecessor on whatever item now takes its place.
	seq.Values = slices.Delete(seq.Values, i, i+1)
	if len(seq.ValueHeadComments) > i {
		seq.ValueHeadComments = slices.Delete(seq.ValueHeadComments, i, i+1)
	}
	return d.refresh()
}

// SetSystem patches the `system` section.
func (d *Doc) SetSystem(fields map[string]any) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	order := model.FieldOrder("system")
	if i := keyIndex(root, "system"); i >= 0 {
		if m := asMapping(root.Values[i].Value); m != nil {
			return d.patchMapping("$.system", m, fields, order)
		}
	}
	return d.setRootKey("system", orderedMap(fields, order))
}

// SetSignoff sets, or with nil removes, the model's security sign-off.
func (d *Doc) SetSignoff(fields map[string]any) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	if fields == nil {
		if i := keyIndex(root, "signoff"); i >= 0 {
			root.Values = slices.Delete(root.Values, i, i+1)
			return d.refresh()
		}
		return nil
	}
	return d.setRootKey("signoff", orderedMap(fields, subOrder("signoff")))
}

// SetLayout sets or removes (pos == nil) a component's or zone's position.
func (d *Doc) SetLayout(id string, pos map[string]float64) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	i := keyIndex(root, "layout")
	if i < 0 || asMapping(root.Values[i].Value) == nil {
		if pos == nil {
			return nil
		}
		return d.setRootKey("layout", ordered{{id, layoutValue(pos)}})
	}
	lm := asMapping(root.Values[i].Value)
	if pos == nil {
		if k := keyIndex(lm, id); k >= 0 {
			lm.Values = slices.Delete(lm.Values, k, k+1)
		}
		return nil
	}
	return d.patchMapping("$.layout", lm, map[string]any{id: layoutValue(pos)}, nil)
}

func layoutValue(pos map[string]float64) flowMap {
	var fm flowMap
	for _, k := range []string{"x", "y", "w", "h"} {
		if v, ok := pos[k]; ok {
			fm = append(fm, kv{k, v})
		}
	}
	return fm
}

func (d *Doc) setRootKey(key string, value any) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	if i := keyIndex(root, key); i >= 0 {
		root.Values = slices.Delete(root.Values, i, i+1)
	}
	if err := mergeText(d.file, "$", emitPair(key, value, 0)); err != nil {
		return err
	}
	reorder(root, model.FieldOrder(""), len(root.Values)-1)
	if err := d.refresh(); err != nil {
		return err
	}
	root, _ = d.root()
	if i := keyIndex(root, key); i > 0 {
		if err := d.blankBefore(root.Values[i]); err != nil {
			return err
		}
	}
	// The section that now follows the new one keeps its own blank line.
	root, _ = d.root()
	if i := keyIndex(root, key); i >= 0 && i+1 < len(root.Values) {
		return d.blankBefore(root.Values[i+1])
	}
	return nil
}

func (d *Doc) appendItem(section, id string, fields map[string]any, order []string) error {
	fields = cloneWith(fields, "id", id)
	for k, v := range fields {
		if v == nil {
			delete(fields, k)
		}
	}
	item := orderedMap(fields, order)
	seq, err := d.section(section)
	if err != nil {
		return err
	}
	if seq == nil {
		return d.setRootKey(section, []any{item})
	}
	if seq.IsFlowStyle || len(seq.Values) == 0 {
		// `data: []` (e.g. after deleting the last item) or an inline list:
		// rewrite the section as a block list with the new item appended.
		var existing []any
		if err := yaml.NodeToValue(seq, &existing); err != nil {
			return fmt.Errorf("couldn't read the `%s` list: %w", section, err)
		}
		items := make([]any, 0, len(existing)+1)
		for _, e := range existing {
			if m, ok := e.(map[string]any); ok {
				items = append(items, orderedMap(m, order))
			} else {
				items = append(items, e)
			}
		}
		return d.setRootKey(section, append(items, item))
	}
	blank := len(seq.Values) > 0 && (len(seq.Values) == 1 && isMultiline(seq.Values[0]) || len(seq.Values) > 1 && startsWithBlank(seq.Values[1]))
	if err := mergeText(d.file, "$."+section, emitValue(section, []any{item}, 0)); err != nil {
		return err
	}
	if err := d.refresh(); err != nil {
		return err
	}
	if blank {
		seq, _ = d.section(section)
		return d.blankBefore(seq.Values[len(seq.Values)-1])
	}
	return nil
}

// patchMapping applies fields to the mapping at path.
func (d *Doc) patchMapping(path string, m *ast.MappingNode, fields map[string]any, order []string) error {
	if m == nil {
		return fmt.Errorf("%s is not a map", path)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sortByOrder(keys, order)
	for _, k := range keys {
		v := fields[k]
		i := keyIndex(m, k)
		if v == nil {
			if i >= 0 {
				m.Values = slices.Delete(m.Values, i, i+1)
			}
			continue
		}
		if i >= 0 && isInline(v) && isInlineNode(m.Values[i].Value) {
			// Replace just the value, keeping any comment on the line.
			p, err := yaml.PathString(path + "." + k)
			if err != nil {
				return err
			}
			comment := m.Values[i].Value.GetComment()
			if err := p.ReplaceWithReader(d.file, strings.NewReader(emitInline(k, v))); err != nil {
				return err
			}
			if comment != nil {
				if err := m.Values[i].Value.SetComment(comment); err != nil {
					return err
				}
			}
			continue
		}
		at := i
		if i >= 0 {
			m.Values = slices.Delete(m.Values, i, i+1)
		}
		if err := mergeInto(d.file, path, m, emitPair(k, v, 0)); err != nil {
			return err
		}
		last := len(m.Values) - 1
		if at >= 0 {
			moveTo(m, last, at)
		} else {
			reorder(m, order, last)
		}
	}
	return nil
}

// mergeInto merges "key: value" text into the mapping at path. An empty
// mapping can't be merged into by the library, so it's handled separately.
func mergeInto(f *ast.File, path string, m *ast.MappingNode, text string) error {
	if len(m.Values) == 0 {
		return fmt.Errorf("can't add fields to an empty map at %s", path)
	}
	return mergeText(f, path, text)
}

func mergeText(f *ast.File, path, text string) error {
	p, err := yaml.PathString(path)
	if err != nil {
		return err
	}
	return p.MergeFromReader(f, strings.NewReader(text))
}

// reorder moves the value at index from to its canonical position among its
// siblings. Keys not in order stay where they are.
func reorder(m *ast.MappingNode, order []string, from int) {
	if order == nil {
		return
	}
	key := m.Values[from].Key.String()
	rank := slices.Index(order, key)
	if rank < 0 {
		return
	}
	to := from
	for j := 0; j < from; j++ {
		if r := slices.Index(order, m.Values[j].Key.String()); r > rank {
			to = j
			break
		}
	}
	moveTo(m, from, to)
}

func moveTo(m *ast.MappingNode, from, to int) {
	if from == to {
		return
	}
	v := m.Values[from]
	m.Values = slices.Delete(m.Values, from, from+1)
	m.Values = slices.Insert(m.Values, to, v)
}

func sortByOrder(keys, order []string) {
	sort.SliceStable(keys, func(i, j int) bool {
		ri, rj := slices.Index(order, keys[i]), slices.Index(order, keys[j])
		if ri < 0 {
			ri = len(order)
		}
		if rj < 0 {
			rj = len(order)
		}
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
}

// Blank lines: the printer emits a blank line wherever a token's line number
// jumps by more than one. Nodes merged in from snippets carry the snippet's
// line numbers, so after each structural edit the document is re-printed and
// re-parsed (refresh), and blank lines are added as plain text.

func (d *Doc) refresh() error {
	f, err := parser.ParseBytes(d.Bytes(), parser.ParseComments)
	if err != nil {
		return fmt.Errorf("internal error: edit produced invalid YAML: %w", err)
	}
	d.file = f
	return nil
}

// blankBefore makes sure the line before node n is blank. Blank lines
// between items or top-level keys never change what the YAML means.
func (d *Doc) blankBefore(n ast.Node) error {
	tk := n.GetToken()
	if mv := firstPair(n); mv != nil {
		tk = mv.Key.GetToken()
	}
	if tk == nil || tk.Position == nil {
		return nil
	}
	lines := strings.Split(string(d.Bytes()), "\n")
	at := tk.Position.Line - 1 // 0-based line of the node
	// Step back over the node's own head comments.
	for at > 0 && strings.HasPrefix(strings.TrimSpace(lines[at-1]), "#") {
		at--
	}
	if at <= 0 || strings.TrimSpace(lines[at-1]) == "" {
		return nil
	}
	lines = slices.Insert(lines, at, "")
	f, err := parser.ParseBytes([]byte(strings.Join(lines, "\n")), parser.ParseComments)
	if err != nil {
		return fmt.Errorf("internal error: edit produced invalid YAML: %w", err)
	}
	d.file = f
	return nil
}

func firstPair(n ast.Node) *ast.MappingValueNode {
	switch n := n.(type) {
	case *ast.MappingNode:
		if len(n.Values) > 0 {
			return n.Values[0]
		}
	case *ast.MappingValueNode:
		return n
	}
	return nil
}

func startsWithBlank(n ast.Node) bool {
	return strings.HasPrefix(n.String(), "\n")
}

func isMultiline(n ast.Node) bool {
	return strings.Contains(strings.TrimSpace(n.String()), "\n")
}

func isInlineNode(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.SequenceNode:
		return n.IsFlowStyle
	case *ast.MappingNode:
		return n.IsFlowStyle
	case *ast.LiteralNode:
		return false
	}
	return n != nil && !isMultiline(n)
}

func cloneWith(m map[string]any, k string, v any) map[string]any {
	out := make(map[string]any, len(m))
	for key, val := range m {
		out[key] = val
	}
	out[k] = v
	return out
}

// Value emission. New values are written in the house style: short scalar
// lists and small maps inline, attack steps and lists of maps as blocks.

type kv struct {
	K string
	V any
}
type ordered []kv
type flowMap []kv

func orderedMap(fields map[string]any, order []string) ordered {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sortByOrder(keys, order)
	out := make(ordered, 0, len(keys))
	for _, k := range keys {
		out = append(out, kv{k, normalize(k, fields[k])})
	}
	return out
}

// Keys whose values are written as flow maps, e.g. effect: {effort: hard}.
var flowMapKeys = []string{"effect", "can", "reviewed"}

// Keys whose lists are always written as blocks.
var blockListKeys = []string{"attack", "evidence", "owners", "links", "catalogs"}

func normalize(key string, v any) any {
	switch v := v.(type) {
	case map[string]any:
		order := subOrder(key)
		if slices.Contains(flowMapKeys, key) {
			var fm flowMap
			for _, e := range orderedMap(v, order) {
				fm = append(fm, e)
			}
			return fm
		}
		return orderedMap(v, order)
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = normalize(key, e)
		}
		return out
	case []string:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = e
		}
		return out
	}
	return v
}

func subOrder(key string) []string {
	switch key {
	case "gives":
		return []string{"reads", "changes", "controls", "access"}
	case "accepted":
		return []string{"by", "reason", "until"}
	case "risk":
		return []string{"override", "reason"}
	case "effect":
		return []string{"who", "effort", "impact"}
	case "can":
		return []string{"do", "on"}
	case "reviewed":
		return []string{"on", "by"}
	case "signoff":
		return []string{"by", "on", "note"}
	}
	return nil
}

func isInline(v any) bool {
	switch v := v.(type) {
	case map[string]any, ordered:
		return false
	case []any:
		for _, e := range v {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	}
	return true
}

func emitInline(key string, v any) string {
	return strings.TrimSpace(emitValue(key, normalize(key, v), 0))
}

func emitPair(key string, v any, indent int) string {
	pad := strings.Repeat(" ", indent)
	val := emitValue(key, normalize(key, v), indent+2)
	if strings.HasPrefix(val, "\n") {
		return pad + key + ":" + val
	}
	return pad + key + ": " + val
}

// emitValue returns YAML for v. Block values start with "\n" and are
// indented by indent; inline values have no newline.
func emitValue(key string, v any, indent int) string {
	pad := strings.Repeat(" ", indent)
	switch v := v.(type) {
	case nil:
		return "null"
	case string:
		return scalar(v)
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case flowMap:
		parts := make([]string, len(v))
		for i, e := range v {
			parts[i] = e.K + ": " + emitValue(e.K, e.V, 0)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case ordered:
		var b strings.Builder
		for _, e := range v {
			b.WriteString("\n" + emitPair(e.K, e.V, indent))
		}
		return b.String()
	case []any:
		if len(v) == 0 {
			return "[]"
		}
		if inline := flowList(key, v); inline != "" {
			return inline
		}
		var b strings.Builder
		for _, e := range v {
			item := emitValue(key, e, indent+2)
			if strings.HasPrefix(item, "\n") {
				// A map in a list: first field goes on the dash line.
				item = strings.TrimPrefix(item, "\n")
				item = strings.TrimPrefix(item, strings.Repeat(" ", indent+2))
			}
			b.WriteString("\n" + pad + "- " + item)
		}
		return b.String()
	}
	// Anything else (e.g. decoded JSON numbers) goes through JSON.
	b, _ := json.Marshal(v)
	return string(b)
}

func flowList(key string, v []any) string {
	if slices.Contains(blockListKeys, key) {
		return ""
	}
	parts := make([]string, len(v))
	total := 0
	for i, e := range v {
		s, ok := e.(string)
		if !ok {
			return ""
		}
		parts[i] = scalar(s)
		total += len(parts[i]) + 2
	}
	if total > 72 {
		return ""
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// A colon is fine in a plain scalar unless a space or the end follows it.
var plainSafe = regexp.MustCompile(`^[A-Za-z0-9_./()'"\-](?:[^:#\n\r\t]|:[^\s])*$`)

// Words other YAML parsers (YAML 1.1) would read as booleans or null.
var ambiguous = []string{"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~"}

// scalar writes a string plainly when that's unambiguous, otherwise quoted.
func scalar(s string) string {
	if needsQuotes(s) || !readsBackAs(s) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		return strings.TrimSuffix(buf.String(), "\n")
	}
	return s
}

// readsBackAs is the safety net under needsQuotes: a plain scalar is only
// used if parsing it back gives exactly the same string.
func readsBackAs(s string) bool {
	var v map[string]any
	if err := yaml.Unmarshal([]byte("v: "+s+"\n"), &v); err != nil {
		return false
	}
	got, ok := v["v"].(string)
	if !ok || got != s {
		return false
	}
	var l map[string][]any
	if err := yaml.Unmarshal([]byte("v: ["+s+"]\n"), &l); err != nil || len(l["v"]) != 1 || l["v"][0] != s {
		return false
	}
	return true
}

func needsQuotes(s string) bool {
	if strings.HasPrefix(s, "---") || strings.HasPrefix(s, "...") {
		return true
	}
	if s == "" || strings.TrimSpace(s) != s || slices.Contains(ambiguous, strings.ToLower(s)) {
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	if strings.ContainsAny(s[:1], "-'\"") && (len(s) == 1 || s[1] == ' ' || s[0] != '-') {
		return true
	}
	if strings.Contains(s, ": ") || strings.Contains(s, " #") || strings.HasSuffix(s, ":") {
		return true
	}
	if strings.ContainsAny(s, "{}[],&*!|>%`") && strings.ContainsAny(s[:1], "{}[],&*!|>%`") {
		return true
	}
	if strings.ContainsAny(s, "[]{},") {
		// Fine in block context but breaks inside [a, b] lists.
		return true
	}
	return !plainSafe.MatchString(s)
}
