package model

import (
	"fmt"
	"sort"
	"strings"
)

const (
	SevError   = "error"
	SevWarning = "warning"
)

// Diagnostic is one problem found in a model, written for a developer to act on.
type Diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}

func (d Diagnostic) String() string {
	var b strings.Builder
	if d.Line > 0 {
		fmt.Fprintf(&b, "line %d: ", d.Line)
	}
	b.WriteString(d.Message)
	if d.Hint != "" {
		b.WriteString(" " + d.Hint)
	}
	return b.String()
}

type Diagnostics []Diagnostic

func (ds Diagnostics) HasErrors() bool {
	for _, d := range ds {
		if d.Severity == SevError {
			return true
		}
	}
	return false
}

// Sorted orders diagnostics by line, keeping errors before warnings on a line.
func (ds Diagnostics) Sorted() Diagnostics {
	out := append(Diagnostics(nil), ds...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Severity == SevError && out[j].Severity != SevError
	})
	return out
}

func errorf(code, path string, line int, format string, args ...any) Diagnostic {
	return Diagnostic{Severity: SevError, Code: code, Path: path, Line: line, Message: fmt.Sprintf(format, args...)}
}

// didYouMean returns the closest candidate within a small edit distance.
func didYouMean(got string, candidates []string) string {
	best, bestDist := "", 3
	if len(got) <= 3 {
		bestDist = 2
	}
	for _, c := range candidates {
		if d := editDistance(strings.ToLower(got), strings.ToLower(c)); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func suggestHint(got string, candidates []string) string {
	if s := didYouMean(got, candidates); s != "" {
		return fmt.Sprintf("Did you mean `%s`?", s)
	}
	return ""
}

func oneOf(values []string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = "`" + v + "`"
	}
	if len(q) <= 1 {
		return strings.Join(q, "")
	}
	return strings.Join(q[:len(q)-1], ", ") + " or " + q[len(q)-1]
}
