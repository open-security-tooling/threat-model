package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/open-security-tooling/threat-model/internal/catalog"
	"github.com/open-security-tooling/threat-model/internal/model"
	"github.com/open-security-tooling/threat-model/internal/ops"
	"github.com/open-security-tooling/threat-model/internal/risk"
	"github.com/open-security-tooling/threat-model/internal/sim"
)

// customCatalogs reads the model's custom catalog files from the repository.
func customCatalogs(modelPath string, src []byte) (map[string]string, error) {
	doc, _ := model.Parse(src)
	if doc == nil || doc.Model == nil {
		return nil, nil
	}
	abs, _ := filepath.Abs(modelPath)
	return catalog.ReadCustom(gitRoot(filepath.Dir(abs)), doc.Model.Catalogs)
}

func cmdSuggest(args []string) int {
	f := newFlags("suggest", "suggest [--component id | --flow id] [--min-risk high] [--limit 10] [--accept catalog:x/y --target id | --dismiss catalog:x/y --target id --reason ...] [--json]")
	component := f.String("component", "", "only suggest for this component")
	flow := f.String("flow", "", "only suggest for this flow")
	minRisk := f.String("min-risk", "", "only suggestions at least this risky: low, medium, high or critical")
	limit := f.Int("limit", 0, "show at most this many suggestions, highest risk first (0: all)")
	accept := f.String("accept", "", "accept the suggestion with this `from` (catalog:<catalog>/<entry>)")
	dismiss := f.String("dismiss", "", "dismiss the suggestion with this `from`")
	target := f.String("target", "", "component or flow the accepted/dismissed suggestion is for")
	reason := f.String("reason", "", "why a dismissed suggestion doesn't apply")
	if !f.parse(args) {
		return exitUsage
	}
	if *minRisk != "" && risk.Rank(*minRisk) < 0 {
		fail(fmt.Errorf("--min-risk must be one of %s", strings.Join(risk.Levels, ", ")))
		return exitUsage
	}
	if *limit < 0 {
		fail(fmt.Errorf("--limit can't be negative"))
		return exitUsage
	}
	path, src, ok := f.read()
	if !ok {
		return exitUsage
	}
	custom, err := customCatalogs(path, src)
	if err != nil {
		fail(err)
		return exitUsage
	}
	if *accept != "" || *dismiss != "" {
		if *target == "" {
			fail(fmt.Errorf("--target is required with --accept or --dismiss"))
			return exitUsage
		}
		var r ops.EditResult
		from := *accept
		if *accept != "" {
			r, err = ops.AcceptSuggestion(src, *accept, *target, nil, custom)
		} else {
			from = *dismiss
			r, err = ops.DismissSuggestion(src, *dismiss, *target, *reason, custom)
		}
		if err != nil {
			fail(err)
			if hint := suggestionHint(src, custom, from, *target, *accept != ""); hint != "" {
				fmt.Fprint(os.Stderr, hint)
			}
			return exitUsage
		}
		if err := writeAtomic(path, []byte(r.Source)); err != nil {
			fail(err)
			return exitUsage
		}
		if f.json {
			printJSON(map[string]any{"ok": true})
		} else if *accept != "" {
			fmt.Printf("Added the threat to %s. Review its who, effort and impact for your system.\n", filepath.Base(path))
		} else {
			fmt.Printf("Recorded it as not applicable in %s.\n", filepath.Base(path))
		}
		return exitOK
	}
	t := *component
	if *flow != "" {
		t = *flow
	}
	r, err := ops.Suggest(src, t, custom)
	if err != nil {
		fail(err)
		return exitUsage
	}
	all := len(r.Suggestions)
	// ops sorts by risk, highest first, so filtering and cutting keep the
	// most serious ones.
	if *minRisk != "" {
		r.Suggestions = slices.DeleteFunc(r.Suggestions, func(s catalog.Suggestion) bool { return risk.Rank(s.Level) < risk.Rank(*minRisk) })
	}
	if *limit > 0 && len(r.Suggestions) > *limit {
		r.Suggestions = r.Suggestions[:*limit]
	}
	if f.json {
		printJSON(r)
		return exitOK
	}
	if len(r.Suggestions) == 0 {
		if all > 0 {
			fmt.Printf("No suggestions at %s risk or above (%s below that). Run without --min-risk to see them.\n", *minRisk, plural(all, "suggestion"))
		} else {
			fmt.Println("No new suggestions. Everything the library knows about has been considered.")
		}
		return exitOK
	}
	// Group by target, the group with the most serious suggestion first.
	var order []string
	groups := map[string][]catalog.Suggestion{}
	w := 0
	for _, s := range r.Suggestions {
		if _, ok := groups[s.Target]; !ok {
			order = append(order, s.Target)
		}
		groups[s.Target] = append(groups[s.Target], s)
		w = max(w, visibleWidth(level(s.Level)))
	}
	indent := strings.Repeat(" ", w+4)
	for _, target := range order {
		g := groups[target]
		fmt.Printf("\n%s %s\n", bold(g[0].TargetName), dim("("+target+")"))
		for _, s := range g {
			fmt.Printf("  %s  %s\n", pad(level(s.Level), w), s.Threat.Title)
			fmt.Printf("%s%s\n", indent, dim(s.WhyItMatters))
			fmt.Printf("%s%s\n", indent, dim(fmt.Sprintf("threat suggest --accept %s --target %s", s.From, s.Target)))
		}
	}
	fmt.Printf("\n%s", plural(len(r.Suggestions), "suggestion"))
	if hidden := all - len(r.Suggestions); hidden > 0 {
		fmt.Printf(" (%d more not shown)", hidden)
	}
	fmt.Println(". Accept the ones that apply, or dismiss them with --dismiss ... --reason \"...\".")
	return exitOK
}

// suggestionHint explains why --accept or --dismiss found nothing: the
// threat is already in the model, or the from/target pair is slightly off.
func suggestionHint(src []byte, custom map[string]string, from, target string, accepting bool) string {
	if l := ops.Load(src); l.Model != nil {
		for _, t := range l.Model.Threats {
			if t.From == from && slices.Contains(t.Affects, target) {
				what := "accepted as threat `" + t.ID + "`"
				if t.Status == "not-applicable" {
					what = "dismissed (threat `" + t.ID + "`, not-applicable)"
				}
				return fmt.Sprintf("It's already in the model: %s. See it with `threat explain %s`.\n", what, t.ID)
			}
		}
	}
	r, err := ops.Suggest(src, "", custom)
	if err != nil || len(r.Suggestions) == 0 {
		return ""
	}
	type cand struct {
		s     catalog.Suggestion
		score int
	}
	var cands []cand
	for _, s := range r.Suggestions {
		score := editDistance(from, s.From) + editDistance(target, s.Target)
		// Only pairs that share a part, or are a typo or two away.
		if s.From == from || s.Target == target || score <= 4 {
			cands = append(cands, cand{s, score})
		}
	}
	if len(cands) == 0 {
		return "Run `threat suggest` to see the open suggestions and their exact --accept commands.\n"
	}
	slices.SortStableFunc(cands, func(a, b cand) int { return a.score - b.score })
	flag := "--dismiss"
	if accepting {
		flag = "--accept"
	}
	var b strings.Builder
	b.WriteString("Closest open suggestions:\n")
	for i, c := range cands {
		if i == 3 {
			break
		}
		fmt.Fprintf(&b, "  threat suggest %s %s --target %s    %s\n", flag, c.s.From, c.s.Target, dim("("+c.s.TargetName+": "+c.s.Threat.Title+")"))
	}
	return b.String()
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	// Only used to suggest IDs, which are short; anything longer isn't a typo.
	if len(ra) > 256 || len(rb) > 256 {
		return len(ra) + len(rb)
	}
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func cmdPaths(args []string) int {
	f := newFlags("paths", "paths [--from anyone|any-user|insider|privileged|physical|controls:<component>] [--to data-id,...] [--blast component] [--json]")
	from := f.String("from", "anyone", "where the attacker starts")
	to := f.String("to", "", "comma-separated data IDs to reach (default: all confidential and secret data)")
	blast := f.String("blast", "", "show everything reachable if this component is compromised")
	if !f.parse(args) {
		return exitUsage
	}
	_, src, ok := f.read()
	if !ok {
		return exitUsage
	}
	m := ops.Load(src).Model
	if *blast != "" {
		b, err := ops.BlastRadius(src, *blast)
		if err != nil {
			fail(err)
			return exitUsage
		}
		if f.json {
			printJSON(b)
			return exitOK
		}
		printBlast(m, b)
		return exitOK
	}
	var targets []string
	if *to != "" {
		targets = strings.Split(*to, ",")
	}
	r, err := ops.Paths(src, *from, targets)
	if err != nil {
		fail(err)
		return exitUsage
	}
	if f.json {
		printJSON(r)
		return exitOK
	}
	for _, p := range r.Paths {
		arrow := style("1;31", "→")
		if p.Contained {
			arrow = style("1;33", "◌")
		}
		fmt.Printf("\n%s %s %s\n", arrow, bold(p.TargetName), dim("(hardest step: "+p.Weakest+")"))
		for i, s := range p.Steps {
			tag := ""
			if s.ThreatID != "" {
				tag = dim(" (" + s.ThreatID + ")")
			}
			fmt.Printf("  %d. %s%s\n", i+1, s.Title, tag)
			if len(s.Gains) > 0 {
				fmt.Printf("     %s\n", dim("→ "+strings.Join(s.Gains, ", ")))
			}
		}
		if p.Exit != "" {
			fmt.Printf("  %d. %s\n", len(p.Steps)+1, p.Exit)
		}
	}
	if len(r.Unreachable) > 0 {
		fmt.Printf("\n%s Not reachable from %s: %s\n", style("1;32", "✓"), r.From, strings.Join(names(m, nil, r.Unreachable), ", "))
	}
	if len(r.Fixes) > 0 {
		fmt.Println("\n" + bold("Fixes that would cut paths"))
		for _, fx := range r.Fixes {
			var does []string
			if len(fx.Breaks) > 0 {
				does = append(does, "protects "+strings.Join(names(m, nil, fx.Breaks), ", "))
			}
			if len(fx.Harder) > 0 {
				does = append(does, "makes the easiest path to "+strings.Join(names(m, nil, fx.Harder), ", ")+" harder")
			}
			fmt.Printf("  %s %s\n", fx.Title, dim(fmt.Sprintf("(%s, %s; %s)", fx.MitigationID, fx.Status, strings.Join(does, "; "))))
		}
	}
	return exitOK
}

// names turns data or component IDs into their names, preferring the names
// a result already carries.
func names(m *model.Model, known map[string]string, ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		switch {
		case known[id] != "":
			out[i] = known[id]
		case m != nil && m.DataItem(id) != nil:
			out[i] = m.DataItem(id).Name
		case m != nil && m.Component(id) != nil:
			out[i] = m.Component(id).Name
		default:
			out[i] = id
		}
	}
	return out
}

func printBlast(m *model.Model, b sim.Blast) {
	name := names(m, b.Names, []string{b.Component})[0]
	type item struct{ verb, id string }
	var added, already []item
	for _, l := range []struct {
		verb string
		ids  []string
	}{{"read", b.Reads}, {"change", b.Changes}, {"control", b.Controls}} {
		for _, id := range l.ids {
			if slices.Contains(b.AlreadyReachable, id) {
				already = append(already, item{l.verb, id})
			} else {
				added = append(added, item{l.verb, id})
			}
		}
	}
	line := func(it item) string { return it.verb + " " + names(m, b.Names, []string{it.id})[0] }
	if len(added) == 0 {
		fmt.Printf("Compromising %s %s adds nothing beyond what anyone on the internet can already reach.\n", bold(name), dim("("+b.Component+")"))
	} else {
		fmt.Printf("If %s %s is compromised, the attacker could:\n", bold(name), dim("("+b.Component+")"))
	}
	for _, it := range added {
		fmt.Printf("  %s\n", line(it))
	}
	for _, it := range already {
		fmt.Printf("  %s\n", dim(line(it)+" (already reachable from the internet)"))
	}
}
