package export

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/check"
)

// GitHubAnnotations renders findings as GitHub workflow commands, one per
// line, e.g. `::error file=threatmodel.yaml,line=12,title=…::message`.
// Printed to a step's output, they show up on the pull request's diff.
//
// Model text ends up in these lines, and the runner treats any output line
// starting with "::" as a command. Escaping CR and LF keeps each annotation
// on its own line, so model text can't start a new command; escaping ':'
// and ',' in properties keeps it from adding or ending a property.
func GitHubAnnotations(r check.Result, modelPath string) string {
	file := filepath.ToSlash(modelPath)
	var b strings.Builder
	for _, f := range r.Findings {
		cmd := "warning"
		if f.Severity == check.SevError {
			cmd = "error"
		}
		props := []string{"file=" + escapeProperty(file)}
		if f.Line > 0 {
			props = append(props, "line="+strconv.Itoa(f.Line))
		}
		title := "threat check: " + f.Code
		if f.ID != "" {
			title += " (" + f.ID + ")"
		}
		props = append(props, "title="+escapeProperty(title))
		msg := f.Message
		if f.Hint != "" {
			msg += " " + f.Hint
		}
		b.WriteString("::" + cmd + " " + strings.Join(props, ",") + "::" + escapeData(msg) + "\n")
	}
	return b.String()
}

// escapeData escapes a workflow command's message, as @actions/core does.
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// escapeProperty escapes a workflow command's property value.
func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
