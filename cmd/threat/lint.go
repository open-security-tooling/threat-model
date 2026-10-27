package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
)

// Writing-rule checks for `threat lint`, on top of what validation already
// reports. They are warnings: heuristics that help, not format rules. They
// live in the CLI for now; they belong in internal/model next to the
// title-style check, so the web app and MCP server can report them too.

// refPattern matches security reference IDs, which belong in `refs`:
// CWE-639, CAPEC-66, ATT&CK techniques like T1078, OWASP codes like
// A01:2021 or API1:2023.
var refPattern = regexp.MustCompile(`(?i)\b(CWE|CAPEC)-\d+\b|\bT1\d{3}(\.\d{3})?\b|\b(API)?A?\d{1,2}:20\d\d\b`)

// acronymPattern matches words with two or more capitals in a row, e.g.
// SSRF, IMDSv2, UUIDs.
var acronymPattern = regexp.MustCompile(`\b[A-Z][A-Z0-9&]*[A-Z][A-Za-z0-9]*\b`)

// plainAcronyms are common enough that developers read them as words.
var plainAcronyms = []string{
	"API", "APIs", "AWS", "CDN", "CI", "CSV", "DNS", "GCP", "HTML", "HTTP", "HTTPS", "ID", "IDs",
	"IP", "IPs", "JSON", "OK", "PDF", "PDFs", "PR", "PRs", "SQL", "SSH", "UI", "URL", "URLs", "USB",
	"UUID", "UUIDs", "VPN", "XML", "YAML",
}

// vaguePhrases make a mitigation title say nothing about what to change.
var vaguePhrases = []string{
	"implement proper", "ensure proper", "ensure security", "ensure secure", "follow best practice",
	"best practices", "proper access control", "proper validation", "properly secure",
	"improve security", "enhance security", "harden the", "appropriate security", "adequate security",
}

func lintWriting(src []byte) []model.Diagnostic {
	l := ops.Load(src)
	if l.Model == nil {
		return nil
	}
	m := l.Model
	var out []model.Diagnostic
	warn := func(path, code, msg, hint string) {
		out = append(out, model.Diagnostic{Severity: model.SevWarning, Code: code, Path: path, Line: l.Doc.Line(path), Message: msg, Hint: hint})
	}
	// Threat titles are read by everyone, so they get the acronym check too.
	// Mitigation titles are meant to name the stack ("Require IMDSv2 ..."),
	// so they only get the references check.
	titleChecks := func(path, who, title string, acronyms bool) {
		if refs := refPattern.FindAllString(title, -1); len(refs) > 0 {
			warn(path, "title-refs", fmt.Sprintf("%s's title contains %s.", who, quoteList(refs)),
				"Move security references into `refs` and say in plain words what could happen.")
		}
		if !acronyms {
			return
		}
		var unexplained []string
		for _, a := range acronymPattern.FindAllString(title, -1) {
			if refPattern.MatchString(a) || slices.Contains(plainAcronyms, a) || slices.Contains(unexplained, a) || explained(title, a) {
				continue
			}
			unexplained = append(unexplained, a)
		}
		if len(unexplained) > 0 {
			warn(path, "title-acronym", fmt.Sprintf("%s's title uses %s without explaining it.", who, quoteList(unexplained)),
				"Say it in plain words, with the acronym in brackets if it helps, e.g. \"make our server fetch internal URLs (SSRF)\".")
		}
	}
	for i, t := range m.Threats {
		p := fmt.Sprintf("threats[%d]", i)
		who := fmt.Sprintf("Threat `%s`", t.ID)
		titleChecks(p+".title", who, t.Title, true)
		if t.Kind == "" {
			warn(p, "no-kind", who+" doesn't say what `kind` of threat it is.",
				"Set `kind` to one of "+strings.Join(model.ThreatKinds, ", ")+", so coverage and suggestions can use it.")
		}
	}
	for i, mt := range m.Mitigations {
		p := fmt.Sprintf("mitigations[%d]", i)
		who := fmt.Sprintf("Mitigation `%s`", mt.ID)
		titleChecks(p+".title", who, mt.Title, false)
		lower := strings.ToLower(mt.Title)
		for _, phrase := range vaguePhrases {
			if strings.Contains(lower, phrase) {
				warn(p+".title", "vague-mitigation", fmt.Sprintf("%s's title (%q) doesn't say what to change.", who, phrase),
					"Name the action in code or config, e.g. \"Check the invoice belongs to the caller's account before returning it\".")
				break
			}
		}
	}
	return out
}

// explained reports whether an acronym appears inside a parenthetical next
// to words that explain it, as in "fetch internal URLs for them (SSRF)" or
// "(cross-site request forgery, CSRF)".
func explained(title, acronym string) bool {
	for rest := title; ; {
		open := strings.Index(rest, "(")
		if open < 0 {
			return false
		}
		end := strings.Index(rest[open:], ")")
		if end < 0 {
			return false
		}
		inside := rest[open+1 : open+end]
		for _, w := range strings.FieldsFunc(inside, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if w == acronym {
				return true
			}
		}
		rest = rest[open+end+1:]
	}
}

func quoteList(words []string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = "`" + w + "`"
	}
	return strings.Join(q, ", ")
}
