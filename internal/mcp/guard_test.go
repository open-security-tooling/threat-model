package mcp

import (
	"os"
	"strings"
	"testing"
)

func TestDismissingSeriousSuggestionNeedsPerson(t *testing.T) {
	file := exampleFile(t)
	c := start(t, Options{File: file})
	before, _ := os.ReadFile(file)
	// catalog:web/database-injection on api-to-db is critical by default.
	msg := c.fails("dismiss_suggestion", map[string]any{"from": "catalog:web/database-injection", "target": "api-to-db", "reason": "internal only"})
	if !strings.Contains(msg, "person") {
		t.Errorf("refusal doesn't explain: %s", msg)
	}
	if after, _ := os.ReadFile(file); string(after) != string(before) {
		t.Error("file changed")
	}
	c2 := start(t, Options{File: file, AllowRiskLowering: true})
	c2.ok("dismiss_suggestion", map[string]any{"from": "catalog:web/database-injection", "target": "api-to-db", "reason": "Calls are signed with a shared key."})
}
