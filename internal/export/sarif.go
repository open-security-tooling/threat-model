package export

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/check"
	"github.com/open-security-tooling/threat-model/internal/ops"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	toolName     = "threat"
	toolURI      = "https://github.com/open-security-tooling/threat-model"
	// Rule IDs for open threats are this prefix plus the threat's kind.
	threatRulePrefix = "open-threat/"
)

// findingRules explains each check finding in plain language. Codes not
// listed (validation problems, mostly) get a generic description.
var findingRules = map[string]string{
	"format":                "The model file isn't in canonical format. Run `threat fmt` and commit the result.",
	"policy":                "The policy file (.threat.yaml) couldn't be read.",
	"git":                   "A git command needed for the check failed.",
	"acceptance-expired":    "An accepted risk has passed its `until` date. Fix it, or have someone re-accept it with a new date.",
	"evidence-missing":      "A mitigation is marked done, but the code or test it points to is gone.",
	"no-evidence":           "A mitigation is marked done but doesn't say where it lives in the code.",
	"no-test-evidence":      "A mitigation protects against a high or critical threat but has no test proving it works.",
	"unmitigated":           "A high or critical threat is open with no mitigation planned.",
	"needs-review":          "Code behind a component changed since its threats were last reviewed. Check they're still accurate, then update `reviewed`.",
	"uncovered-flow":        "A new flow crosses between zones and has no threats yet.",
	"uncovered-component":   "A component reachable from the internet has no threats yet.",
	"overdue":               "A mitigation is past its due date.",
	"risk-override":         "A threat's risk level is set by hand instead of computed.",
	"threat-removed":        "A threat was removed from the model. A person should agree with that.",
	"threat-dismissed":      "A threat was marked not applicable. A person should agree with that.",
	"risk-accepted":         "A threat was accepted as a risk. A person should agree with that.",
	"risk-lowered":          "A threat's risk went down because its who, effort or impact answers changed, not because a mitigation was finished.",
	"done-without-evidence": "A mitigation was marked done without any evidence.",
	"signoff-stale":         "The model changed after its security sign-off.",
	"policy-open-risk":      "A threat is open at a risk level the policy doesn't allow.",
	"policy-due":            "The policy requires a due date on mitigations for threats at this risk level.",
	"policy-test-evidence":  "The policy requires test evidence for mitigations of threats at this risk level.",
	"policy-acceptance":     "A risk is accepted for longer than the policy allows.",
	"policy-signoff":        "The policy requires a security sign-off, and the model has none.",
	"policy-review-age":     "A component hasn't been reviewed as recently as the policy requires.",
	"policy-catalog":        "The policy requires a threat catalog the model doesn't use.",
}

// threatKinds explains each threat kind, as in docs/concepts.md.
var threatKinds = map[string]string{
	"impersonate":   "Someone could pretend to be someone or something else.",
	"tamper":        "Someone could change data or code they shouldn't.",
	"cover-tracks":  "Someone could do something and leave no trace, or deny it later.",
	"leak":          "Someone could see data they shouldn't.",
	"disrupt":       "Someone could break the system or slow it down.",
	"escalate":      "Someone could get more access than they should have.",
	"abuse":         "Someone could use a feature exactly as built, but for harm.",
	"manipulate-ai": "Someone could trick an AI component into doing something it shouldn't.",
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIF renders a check result as SARIF 2.1.0 for GitHub code scanning:
// one result per finding (ruleId is the finding code) and, when v is
// given, one per open threat (ruleId is open-threat/<kind>, level by its
// residual risk: critical and high are errors, medium a warning, low a
// note). modelPath is the model file relative to the repository root.
func SARIF(r check.Result, v *ops.View, modelPath string) []byte {
	uri := filepath.ToSlash(modelPath)
	var lines map[string]int
	if v != nil {
		lines = v.Lines
	}
	loc := func(line int, id string) []sarifLocation {
		if line <= 0 {
			line = lines[id]
		}
		if line <= 0 {
			line = 1 // code scanning needs a line; the top of the file is honest
		}
		return []sarifLocation{{sarifPhysical{sarifArtifact{uri}, sarifRegion{line}}}}
	}

	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		level := "warning"
		if f.Severity == check.SevError {
			level = "error"
		}
		if _, ok := rules[f.Code]; !ok {
			rules[f.Code] = findingRule(f.Code, level)
		}
		msg := f.Message
		if f.Hint != "" {
			msg += " " + f.Hint
		}
		res := sarifResult{RuleID: f.Code, Level: level, Message: sarifText{sarifEscape(msg)}, Locations: loc(f.Line, f.ID)}
		if f.ID != "" {
			res.Properties = map[string]any{"id": f.ID}
		}
		results = append(results, res)
	}

	if v != nil && v.Model != nil {
		for _, t := range openThreats(v) {
			a := v.Risks[t.ID]
			kind := t.Kind
			if kind == "" {
				kind = "other"
			}
			id := threatRulePrefix + kind
			if _, ok := rules[id]; !ok {
				rules[id] = threatRule(id, kind)
			}
			msg := "Open threat (" + levelText(a.Level) + " risk): " + t.Title
			if a.Why != "" {
				msg += " Why: " + a.Why
			}
			results = append(results, sarifResult{
				RuleID: id, Level: threatLevel(a.Level), Message: sarifText{sarifEscape(msg)}, Locations: loc(0, t.ID),
				Properties: map[string]any{"id": t.ID, "risk": levelText(a.Level)},
			})
		}
	}

	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := map[string]int{}
	ruleList := make([]sarifRule, 0, len(ids))
	for i, id := range ids {
		index[id] = i
		ruleList = append(ruleList, rules[id])
	}
	if results == nil {
		results = []sarifResult{}
	}
	for i := range results {
		results[i].RuleIndex = index[results[i].RuleID]
	}

	log := sarifLog{Version: sarifVersion, Schema: sarifSchema, Runs: []sarifRun{{
		Tool:    sarifTool{sarifDriver{Name: toolName, InformationURI: toolURI, Rules: ruleList}},
		Results: results,
	}}}
	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		panic(err) // only strings, ints and maps of strings
	}
	return append(b, '\n')
}

func findingRule(code, level string) sarifRule {
	desc, ok := findingRules[code]
	if !ok {
		desc = "The model file has a problem (" + code + ")."
	}
	return sarifRule{
		ID: code, Name: ruleName(code),
		ShortDescription: sarifText{firstSentence(desc)}, FullDescription: sarifText{desc}, Help: sarifText{desc},
		DefaultConfiguration: sarifConfig{level},
		Properties:           map[string]any{"tags": []string{"threat-model"}},
	}
}

func threatRule(id, kind string) sarifRule {
	desc, ok := threatKinds[kind]
	if !ok {
		desc = "Someone could harm the system in a way the threat model describes."
	}
	help := desc + " Each result is one open threat from the threat model; its message says why it has that risk level. " +
		"Fix it by finishing a mitigation, or have a person accept the risk in the model. Run `threat explain <id>` for the details."
	return sarifRule{
		ID: id, Name: ruleName(id),
		ShortDescription: sarifText{"Open threat: " + kind}, FullDescription: sarifText{desc}, Help: sarifText{help},
		DefaultConfiguration: sarifConfig{"warning"},
		Properties:           map[string]any{"tags": []string{"security", "threat-model"}},
	}
}

func threatLevel(level string) string {
	switch level {
	case "critical", "high":
		return "error"
	case "low":
		return "note"
	}
	// Medium, and not yet assessed: someone should look.
	return "warning"
}

// openThreats are the open threats, highest residual risk first, then in
// model order.
func openThreats(v *ops.View) []openThreat {
	var out []openThreat
	for _, t := range v.Model.Threats {
		if t.Status == "open" {
			out = append(out, openThreat{ID: t.ID, Title: t.Title, Kind: t.Kind})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return byRisk(v.Risks[out[i].ID].Level, v.Risks[out[j].ID].Level) < 0
	})
	return out
}

type openThreat struct{ ID, Title, Kind string }

// ruleName turns "needs-review" or "open-threat/leak" into "NeedsReview" or
// "OpenThreatLeak", the form SARIF viewers expect for rule names.
func ruleName(id string) string {
	var b strings.Builder
	for _, part := range strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '/' || r == '_' }) {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

// sarifEscape keeps model text from becoming a link: SARIF message text
// turns [text](target) into a link, and a backslash before a bracket is how
// SARIF says "this bracket is just a bracket".
func sarifEscape(s string) string {
	return strings.NewReplacer(`[`, `\[`, `]`, `\]`).Replace(s)
}
