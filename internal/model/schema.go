package model

// The schema table below is the single description of the file format. It
// drives shape checking (unknown keys, types, enums), canonical key order
// when writing, and the published JSON Schema.

type kind int

const (
	kString kind = iota
	kInt
	kNumber
	kDate
	kStringList
	kObject
	kObjectList
	kEffect
	kEvidenceList
	kCatalogList
	kLayoutMap
	kRefs
	kBool
	kReviewed
	kConsidered
)

type field struct {
	Name     string
	Kind     kind
	Enum     []string
	Obj      *object
	Required bool
	Doc      string
}

type object struct {
	Name   string
	Fields []field
}

func (o *object) field(name string) *field {
	for i := range o.Fields {
		if o.Fields[i].Name == name {
			return &o.Fields[i]
		}
	}
	return nil
}

func (o *object) names() []string {
	out := make([]string, len(o.Fields))
	for i, f := range o.Fields {
		out[i] = f.Name
	}
	return out
}

// Enumerations, in the order they're documented.
var (
	Sensitivities      = []string{"public", "internal", "confidential", "secret"}
	Trusts             = []string{"untrusted", "partial", "trusted"}
	ZoneNetworks       = []string{"open", "segmented"}
	Tenancies          = []string{"single", "multi"}
	ZoneEgress         = []string{"open", "restricted"}
	Patching           = []string{"automated", "scheduled", "manual"}
	IdentityKinds      = []string{"service-account", "role", "user-group", "api-key", "other"}
	Permissions        = []string{"read", "write", "admin", "invoke"}
	WhoLevels          = []string{"anyone", "any-user", "insider", "privileged", "physical"}
	ComponentKinds     = []string{"client", "service", "gateway", "database", "storage", "queue", "cache", "identity", "third-party", "pipeline", "ai", "other"}
	Exposures          = []string{"internet", "internal", "local"}
	FlowAuths          = []string{"none", "session-cookie", "bearer-token", "api-key", "mtls", "iam", "other"}
	ThreatKinds        = []string{"impersonate", "tamper", "cover-tracks", "leak", "disrupt", "escalate", "abuse", "manipulate-ai"}
	Efforts            = []string{"trivial", "moderate", "hard"}
	Impacts            = []string{"low", "medium", "high", "critical"}
	ThreatStatuses     = []string{"open", "mitigated", "accepted", "not-applicable"}
	MitigationStatuses = []string{"planned", "in-progress", "done"}
	RiskLevels         = []string{"low", "medium", "high", "critical"}
)

var (
	systemObj = &object{Name: "system", Fields: []field{
		{Name: "name", Kind: kString, Required: true, Doc: "What this model describes"},
		{Name: "description", Kind: kString},
		{Name: "tenancy", Kind: kString, Enum: Tenancies, Doc: "single: one customer per deployment. multi: customers share the system (multi-tenant SaaS)"},
		{Name: "owners", Kind: kStringList, Doc: "Who maintains this model, e.g. @org/team"},
		{Name: "links", Kind: kStringList},
	}}
	dataObj = &object{Name: "data", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "name", Kind: kString, Required: true},
		{Name: "sensitivity", Kind: kString, Enum: Sensitivities, Required: true},
		{Name: "description", Kind: kString},
	}}
	zoneObj = &object{Name: "zone", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "name", Kind: kString, Required: true},
		{Name: "trust", Kind: kString, Enum: Trusts, Required: true},
		{Name: "network", Kind: kString, Enum: ZoneNetworks, Doc: "open: anything in the zone can reach anything else (default). segmented: only the flows in the model are allowed"},
		{Name: "egress", Kind: kString, Enum: ZoneEgress, Doc: "open: components can connect anywhere on the internet (default). restricted: outbound traffic only to allowed destinations"},
	}}
	permissionObj = &object{Name: "permission", Fields: []field{
		{Name: "do", Kind: kString, Enum: Permissions, Required: true},
		{Name: "on", Kind: kString, Required: true, Doc: "A component or data ID"},
	}}
	identityObj = &object{Name: "identity", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "name", Kind: kString, Required: true},
		{Name: "kind", Kind: kString, Enum: IdentityKinds, Required: true},
		{Name: "can", Kind: kObjectList, Obj: permissionObj, Doc: "What this identity is allowed to do"},
		{Name: "notes", Kind: kString},
	}}
	actorObj = &object{Name: "actor", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "name", Kind: kString, Required: true},
		{Name: "access", Kind: kString, Enum: WhoLevels},
	}}
	componentObj = &object{Name: "component", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "name", Kind: kString, Required: true},
		{Name: "kind", Kind: kString, Enum: ComponentKinds, Required: true},
		{Name: "zone", Kind: kString},
		{Name: "exposure", Kind: kString, Enum: Exposures},
		{Name: "tech", Kind: kStringList},
		{Name: "features", Kind: kStringList, Doc: "What it does, in plain words: login, signup, password-reset, file-upload, outbound-webhooks, inbound-webhooks, admin-panel, search, export, payments…"},
		{Name: "stores", Kind: kStringList, Doc: "IDs of data this component keeps"},
		{Name: "identity", Kind: kString, Doc: "The identity (service account, role) it runs as"},
		{Name: "encrypted_at_rest", Kind: kBool, Doc: "Whether data it stores is encrypted on disk"},
		{Name: "monitored", Kind: kBool, Doc: "Whether security-relevant events are logged and alerted on"},
		{Name: "patching", Kind: kString, Enum: Patching, Doc: "How updates to its dependencies and software are applied"},
		{Name: "managed", Kind: kBool, Doc: "A managed service the provider runs and patches (e.g. RDS, an AWS load balancer)"},
		{Name: "code", Kind: kStringList, Doc: "Paths or globs of the code that implements it"},
		{Name: "reviewed", Kind: kReviewed, Doc: "When someone last checked its threats: a date, or {on: date, by: \"@someone\"}"},
		{Name: "considered", Kind: kConsidered, Doc: "Threat kinds checked and found not to apply, with why, e.g. {disrupt: \"Stateless, autoscaled behind the load balancer\"}"},
		{Name: "notes", Kind: kString},
	}}
	flowObj = &object{Name: "flow", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "from", Kind: kString, Required: true},
		{Name: "to", Kind: kString, Required: true},
		{Name: "over", Kind: kString},
		{Name: "carries", Kind: kStringList},
		{Name: "auth", Kind: kString, Enum: FlowAuths},
		{Name: "encrypted", Kind: kBool, Doc: "Whether traffic is encrypted in transit (e.g. TLS)"},
		{Name: "notes", Kind: kString},
	}}
	givesObj = &object{Name: "gives", Fields: []field{
		{Name: "reads", Kind: kStringList},
		{Name: "changes", Kind: kStringList},
		{Name: "controls", Kind: kStringList},
		{Name: "access", Kind: kString, Enum: WhoLevels},
	}}
	acceptedObj = &object{Name: "accepted", Fields: []field{
		{Name: "by", Kind: kString, Required: true},
		{Name: "reason", Kind: kString, Required: true},
		{Name: "until", Kind: kDate, Required: true},
	}}
	signoffObj = &object{Name: "signoff", Fields: []field{
		{Name: "by", Kind: kString, Required: true},
		{Name: "on", Kind: kDate, Required: true},
		{Name: "note", Kind: kString},
	}}
	riskObj = &object{Name: "risk", Fields: []field{
		{Name: "override", Kind: kString, Enum: RiskLevels, Required: true},
		{Name: "reason", Kind: kString, Required: true},
	}}
	threatObj = &object{Name: "threat", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "title", Kind: kString, Required: true, Doc: "Who could do what by how"},
		{Name: "kind", Kind: kString, Enum: ThreatKinds},
		{Name: "affects", Kind: kStringList, Doc: "Component and/or flow IDs"},
		{Name: "attack", Kind: kStringList, Doc: "The attack as concrete steps"},
		{Name: "who", Kind: kString, Enum: WhoLevels},
		{Name: "effort", Kind: kString, Enum: Efforts},
		{Name: "impact", Kind: kString, Enum: Impacts},
		{Name: "impact_note", Kind: kString},
		{Name: "gives", Kind: kObject, Obj: givesObj},
		{Name: "status", Kind: kString, Enum: ThreatStatuses, Required: true},
		{Name: "mitigations", Kind: kStringList},
		{Name: "accepted", Kind: kObject, Obj: acceptedObj},
		{Name: "reason", Kind: kString, Doc: "Why this threat doesn't apply (status: not-applicable)"},
		{Name: "risk", Kind: kObject, Obj: riskObj},
		{Name: "from", Kind: kString, Doc: "catalog:<catalog>/<entry> when accepted from the library"},
		{Name: "refs", Kind: kRefs},
	}}
	mitigationObj = &object{Name: "mitigation", Fields: []field{
		{Name: "id", Kind: kString, Required: true},
		{Name: "title", Kind: kString, Required: true},
		{Name: "status", Kind: kString, Enum: MitigationStatuses, Required: true},
		{Name: "owner", Kind: kString},
		{Name: "due", Kind: kDate, Doc: "When it should be done by (YYYY-MM-DD)"},
		{Name: "effect", Kind: kEffect},
		{Name: "evidence", Kind: kEvidenceList},
		{Name: "notes", Kind: kString},
	}}
	rootObj = &object{Name: "model", Fields: []field{
		{Name: "version", Kind: kInt, Required: true},
		{Name: "system", Kind: kObject, Obj: systemObj, Required: true},
		{Name: "data", Kind: kObjectList, Obj: dataObj},
		{Name: "zones", Kind: kObjectList, Obj: zoneObj},
		{Name: "actors", Kind: kObjectList, Obj: actorObj},
		{Name: "identities", Kind: kObjectList, Obj: identityObj},
		{Name: "components", Kind: kObjectList, Obj: componentObj},
		{Name: "flows", Kind: kObjectList, Obj: flowObj},
		{Name: "threats", Kind: kObjectList, Obj: threatObj},
		{Name: "mitigations", Kind: kObjectList, Obj: mitigationObj},
		{Name: "catalogs", Kind: kCatalogList},
		{Name: "signoff", Kind: kObject, Obj: signoffObj, Doc: "A security review of the whole model: who signed it off and when"},
		{Name: "layout", Kind: kLayoutMap},
	}}
)

// Sections lists the top-level list sections whose items have IDs, in file order.
var Sections = []string{"data", "zones", "actors", "identities", "components", "flows", "threats", "mitigations"}

// FieldOrder returns the canonical key order for items in a section, or for
// the top level when section is "".
func FieldOrder(section string) []string {
	if section == "" {
		return rootObj.names()
	}
	if f := rootObj.field(section); f != nil && f.Obj != nil {
		return f.Obj.names()
	}
	return nil
}

// sectionObject returns the schema object for items in a top-level section.
func sectionObject(section string) *object {
	if f := rootObj.field(section); f != nil {
		return f.Obj
	}
	return nil
}
