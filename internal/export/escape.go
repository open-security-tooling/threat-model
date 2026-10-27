// Package export turns a model and a check result into the formats other
// tools read: a risk register (CSV or JSON), SARIF for code scanning,
// GitHub workflow annotations, and the Markdown summary for a pull request.
//
// Everything here is a pure function of its inputs, so output is
// deterministic and easy to test. Model text is untrusted (models arrive in
// pull requests), so every format escapes it for where it ends up: Excel
// formulas, workflow commands, Markdown and HTML.
package export

import (
	"regexp"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/risk"
)

// mdEscape neutralises Markdown and HTML in model text, as in
// internal/ops/report.go, and also breaks @mentions so model text can't
// ping people or teams from a bot comment.
func mdEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '<', '>', '#', '|', '!', '~', '&':
			b.WriteRune('\\')
			b.WriteRune(r)
		case '@':
			// A zero-width space stops GitHub from linking a mention.
			b.WriteString("@​")
		case '\n', '\r':
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]*$`)

// code renders an ID as inline code when it's a plain ID. Anything else
// (a broken model can have any text as an ID) is escaped as text, so a
// backtick can't end the code span early.
func code(id string) string {
	if safeID.MatchString(id) {
		return "`" + id + "`"
	}
	return mdEscape(id)
}

var badge = map[string]string{"critical": "🟥 Critical", "high": "🟧 High", "medium": "🟨 Medium", "low": "🟩 Low", "": "⬜ Not assessed"}

func levelBadge(level string) string {
	if b, ok := badge[level]; ok {
		return b
	}
	return mdEscape(level)
}

func levelText(level string) string {
	if level == "" {
		return "not assessed"
	}
	return level
}

// byRisk orders levels highest first; unknown and unassessed sort last.
func byRisk(a, b string) int { return risk.Rank(b) - risk.Rank(a) }
