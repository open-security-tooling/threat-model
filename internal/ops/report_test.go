package ops

import (
	"os"
	"strings"
	"testing"

	"github.com/open-security-tooling/threat-model/internal/edit"
)

func TestReportEscapesModelText(t *testing.T) {
	src, err := os.ReadFile("../../docs/examples/invoice-service.threatmodel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := edit.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	evil := `Someone could <img src=x onerror=alert(1)> click [here](https://evil.example) ![x](https://evil.example/t.png)`
	if _, err := d.Upsert("threats", "read-others-invoices", map[string]any{"title": evil}); err != nil {
		t.Fatal(err)
	}
	v, err := Show(d.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	md := ReportMarkdown(v)
	// Each of these must only ever appear with a backslash before it.
	for _, bad := range []string{"<img", "[here]", "![x]", "](https://evil.example/t.png)"} {
		if strings.Count(md, bad) != strings.Count(md, `\`+bad) {
			t.Errorf("report contains unescaped %q", bad)
		}
	}
	if !strings.Contains(md, `click \[here\](https://evil.example)`) || !strings.Contains(md, `\!\[x\]`) {
		t.Error("link and image syntax not escaped")
	}
	if !strings.Contains(md, `\<img src=x onerror=alert(1)\>`) {
		t.Error("escaped title not present")
	}
	if !strings.Contains(md, "# Threat model: Invoice service") || !strings.Contains(md, "## Considered and ruled out") {
		t.Error("report structure missing")
	}
}
