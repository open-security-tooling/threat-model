package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
)

// Limits bound how much work parsing an untrusted file can cause.
type Limits struct {
	MaxBytes  int
	MaxDepth  int
	MaxNodes  int
	MaxString int
}

var DefaultLimits = Limits{
	MaxBytes:  5 << 20,
	MaxDepth:  32,
	MaxNodes:  250_000,
	MaxString: 64 << 10,
}

// Document is a parsed model file: the syntax tree (for comment-preserving
// edits), the decoded model, and where each field lives in the source.
type Document struct {
	File  *ast.File
	Model *Model
	pos   map[string]token.Position
}

// Line returns the 1-based source line of a path like "threats[2].who", or 0.
func (d *Document) Line(path string) int {
	if d == nil {
		return 0
	}
	return d.pos[path].Line
}

// Parse reads a model file. It returns the document (nil if the file can't be
// read as a model at all) and any problems found. Parse checks syntax, the
// strict-YAML rules and the shape of every field; Validate checks references
// and the rules that span items.
func Parse(src []byte) (*Document, Diagnostics) {
	return ParseWithLimits(src, DefaultLimits)
}

func ParseWithLimits(src []byte, lim Limits) (doc *Document, diags Diagnostics) {
	if len(src) > lim.MaxBytes {
		return nil, Diagnostics{errorf("too-large", "", 0, "The file is %d bytes; the limit is %d.", len(src), lim.MaxBytes)}
	}
	defer func() {
		// The parser handles untrusted input; never let a parser bug crash the caller.
		if r := recover(); r != nil {
			doc, diags = nil, Diagnostics{errorf("parse", "", 0, "The YAML parser failed on this file (%v). Please report this as a bug.", r)}
		}
	}()

	f, err := parser.ParseBytes(src, parser.ParseComments)
	if err != nil {
		return nil, Diagnostics{syntaxDiag(err)}
	}
	var body ast.Node
	switch {
	case len(f.Docs) == 0 || f.Docs[0].Body == nil:
		return nil, Diagnostics{errorf("empty", "", 0, "The file is empty. Start with `version: 1` and a `system:` section, or run `threat init`.")}
	case len(f.Docs) > 1:
		return nil, Diagnostics{errorf("multi-doc", "", lineOf(f.Docs[1].Body), "A model file holds one YAML document; remove the `---` separator.")}
	default:
		body = f.Docs[0].Body
	}

	w := &walker{lim: lim, pos: map[string]token.Position{}}
	w.walk(body, "", 0)
	if len(w.diags) > 0 {
		return nil, w.diags
	}

	var generic any
	if err := yaml.NodeToValue(body, &generic); err != nil {
		return nil, Diagnostics{syntaxDiag(err)}
	}
	sc := &shapeChecker{pos: w.pos}
	sc.object("", "The file", generic, rootObj)
	if sc.diags.HasErrors() {
		return &Document{File: f, pos: w.pos}, sc.diags
	}

	normalizeReviewed(generic)
	raw, err := json.Marshal(generic)
	if err != nil {
		return nil, Diagnostics{errorf("decode", "", 0, "Couldn't read the model: %v", err)}
	}
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		// The shape checker should have caught this; report it rather than panic.
		return &Document{File: f, pos: w.pos}, append(sc.diags, errorf("decode", "", 0, "Couldn't read the model: %v", err))
	}
	return &Document{File: f, Model: &m, pos: w.pos}, sc.diags
}

// StrictYAML checks that src is a single YAML document within the size limits
// and uses no anchors, aliases, tags, merge keys or directives. Threat
// library files are held to the same rules as model files.
func StrictYAML(src []byte) (diags Diagnostics) {
	if len(src) > DefaultLimits.MaxBytes {
		return Diagnostics{errorf("too-large", "", 0, "The file is %d bytes; the limit is %d.", len(src), DefaultLimits.MaxBytes)}
	}
	defer func() {
		if r := recover(); r != nil {
			diags = Diagnostics{errorf("parse", "", 0, "The YAML parser failed on this file (%v).", r)}
		}
	}()
	f, err := parser.ParseBytes(src, parser.ParseComments)
	if err != nil {
		return Diagnostics{syntaxDiag(err)}
	}
	if len(f.Docs) != 1 {
		return Diagnostics{errorf("multi-doc", "", 0, "The file must hold exactly one YAML document.")}
	}
	w := &walker{lim: DefaultLimits, pos: map[string]token.Position{}}
	w.walk(f.Docs[0].Body, "", 0)
	return w.diags
}

// normalizeReviewed turns `reviewed: {on, by}` into the flat reviewed and
// reviewed_by fields the Go types use.
func normalizeReviewed(generic any) {
	root, _ := generic.(map[string]any)
	comps, _ := root["components"].([]any)
	for _, c := range comps {
		cm, _ := c.(map[string]any)
		if r, ok := cm["reviewed"].(map[string]any); ok {
			cm["reviewed"], cm["reviewed_by"] = r["on"], r["by"]
		}
	}
}

func syntaxDiag(err error) Diagnostic {
	var ye interface {
		GetToken() *token.Token
		GetMessage() string
	}
	if errors.As(err, &ye) && ye.GetToken() != nil {
		p := ye.GetToken().Position
		return Diagnostic{Severity: SevError, Code: "syntax", Line: p.Line, Column: p.Column,
			Message: "This isn't valid YAML: " + ye.GetMessage() + "."}
	}
	return errorf("syntax", "", 0, "This isn't valid YAML: %v", err)
}

func lineOf(n ast.Node) int {
	if n == nil || n.GetToken() == nil || n.GetToken().Position == nil {
		return 0
	}
	return n.GetToken().Position.Line
}

// walker enforces the strict-YAML rules and records field positions.
type walker struct {
	lim   Limits
	nodes int
	pos   map[string]token.Position
	diags Diagnostics
}

func (w *walker) fail(n ast.Node, code, msg string) {
	if len(w.diags) < 20 {
		w.diags = append(w.diags, Diagnostic{Severity: SevError, Code: code, Line: lineOf(n), Message: msg})
	}
}

func (w *walker) walk(n ast.Node, path string, depth int) {
	if n == nil || len(w.diags) >= 20 {
		return
	}
	w.nodes++
	if w.nodes > w.lim.MaxNodes {
		if w.nodes == w.lim.MaxNodes+1 {
			w.fail(n, "too-large", fmt.Sprintf("The file has more than %d YAML nodes.", w.lim.MaxNodes))
		}
		return
	}
	if depth > w.lim.MaxDepth {
		w.fail(n, "too-deep", fmt.Sprintf("The file is nested more than %d levels deep.", w.lim.MaxDepth))
		return
	}
	if path != "" {
		if _, seen := w.pos[path]; !seen && n.GetToken() != nil && n.GetToken().Position != nil {
			w.pos[path] = *n.GetToken().Position
		}
	}
	switch n := n.(type) {
	case *ast.AnchorNode, *ast.AliasNode:
		w.fail(n, "anchor", "Anchors and aliases (& and *) aren't allowed in model files. Write the value out in full.")
	case *ast.TagNode:
		w.fail(n, "tag", "YAML tags (like !!str) aren't allowed in model files. Quote the value instead.")
	case *ast.MergeKeyNode:
		w.fail(n, "merge-key", "Merge keys (<<) aren't allowed in model files.")
	case *ast.DirectiveNode:
		w.fail(n, "directive", "YAML directives (%YAML, %TAG) aren't allowed in model files.")
	case *ast.MappingNode:
		for _, mv := range n.Values {
			w.walk(mv, path, depth)
		}
	case *ast.MappingValueNode:
		key := n.Key.String()
		if _, ok := n.Key.(*ast.MergeKeyNode); ok {
			w.fail(n, "merge-key", "Merge keys (<<) aren't allowed in model files.")
			return
		}
		child := key
		if path != "" {
			child = path + "." + key
		}
		if t := n.Key.GetToken(); t != nil && t.Position != nil {
			w.pos[child] = *t.Position
		}
		w.walk(n.Value, child, depth+1)
	case *ast.SequenceNode:
		for i, v := range n.Values {
			w.walk(v, path+"["+strconv.Itoa(i)+"]", depth+1)
		}
	case *ast.StringNode:
		if len(n.Value) > w.lim.MaxString {
			w.fail(n, "too-large", fmt.Sprintf("A text value is longer than %d characters.", w.lim.MaxString))
		}
	case *ast.LiteralNode:
		if n.Value != nil && len(n.Value.Value) > w.lim.MaxString {
			w.fail(n, "too-large", fmt.Sprintf("A text value is longer than %d characters.", w.lim.MaxString))
		}
	}
}
