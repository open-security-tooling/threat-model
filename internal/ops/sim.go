package ops

import "github.com/open-security-tooling/threat-model/internal/sim"

// Paths finds attack paths from a starting point ("anyone", "any-user",
// "insider", "privileged", "physical" or "controls:<component>") to data.
func Paths(source []byte, from string, to []string) (sim.Result, error) {
	l := Load(source)
	if l.Model == nil {
		return sim.Result{}, &Error{Message: "The file can't be read as a threat model.", Diagnostics: l.Diagnostics}
	}
	if from == "" {
		from = "anyone"
	}
	start, err := sim.ParseStart(l.Model, from)
	if err != nil {
		return sim.Result{}, fail("%s", capitalize(err.Error()))
	}
	for _, d := range to {
		if l.Model.DataItem(d) == nil {
			return sim.Result{}, fail("There's no data `%s` to find paths to.", d)
		}
	}
	return sim.Paths(l.Model, start, to), nil
}

// BlastRadius shows what an attacker who controls a component could reach.
func BlastRadius(source []byte, component string) (sim.Blast, error) {
	l := Load(source)
	if l.Model == nil {
		return sim.Blast{}, &Error{Message: "The file can't be read as a threat model.", Diagnostics: l.Diagnostics}
	}
	if l.Model.Component(component) == nil {
		return sim.Blast{}, fail("There's no component `%s`.", component)
	}
	return sim.BlastRadius(l.Model, component), nil
}
