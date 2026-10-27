package mcp

import (
	"maps"
	"slices"

	"github.com/open-security-tooling/threat-model/internal/model"
)

// JSON Schemas for tool inputs. Enumerations come from the model package so
// they can't drift from the format.

type schema = map[string]any

const idPattern = `^[a-z0-9]+(-[a-z0-9]+)*$`

func object(props schema, required ...string) schema {
	s := schema{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) schema { return schema{"type": "string", "description": desc} }

func idField(desc string) schema {
	return schema{"type": "string", "pattern": idPattern, "description": desc}
}

func enum(desc string, values []string) schema {
	return schema{"type": "string", "enum": values, "description": desc}
}

func strList(desc string) schema {
	return schema{"type": "array", "items": schema{"type": "string"}, "description": desc}
}

func idList(desc string) schema {
	return schema{"type": "array", "items": schema{"type": "string", "pattern": idPattern}, "description": desc}
}

func date(desc string) schema {
	return schema{"type": "string", "pattern": `^\d{4}-\d{2}-\d{2}$`, "description": desc}
}

// threatStatusesForUpsert leaves out "accepted": that goes through set_status.
var threatStatusesForUpsert = []string{"open", "mitigated", "not-applicable"}

// sectionFields describes the fields of items in each section, without id.
// TestSchemasCoverFormat checks these against the model's field table.
var sectionFields = map[string]schema{
	"data": {
		"name":        str("Human-readable name, e.g. \"Customer invoices\"."),
		"sensitivity": enum("public: fine if anyone sees it. internal: not for outsiders. confidential: would harm users or the business if leaked. secret: gives access to other things if leaked (passwords, keys, tokens).", model.Sensitivities),
		"description": str("What the data contains."),
	},
	"zones": {
		"name":    str("Human-readable name, e.g. \"Production AWS account\"."),
		"trust":   enum("How much the zone is trusted.", model.Trusts),
		"network": enum("open (default): anything in the zone can reach anything else, like a flat network. segmented: only the flows in the model are allowed, e.g. by security groups or network policies.", model.ZoneNetworks),
		"egress":  enum("open (default): components can connect anywhere on the internet. restricted: outbound traffic only to allowed destinations (egress firewall or proxy).", model.ZoneEgress),
	},
	"actors": {
		"name":   str("Human-readable name, e.g. \"Customer\" or \"Support agent\"."),
		"access": enum("The least access this actor has, the same scale as a threat's who. find_paths accepts an actor ID as a starting point.", model.WhoLevels),
	},
	"identities": {
		"name": str("Human-readable name, e.g. \"API task role\"."),
		"kind": enum("What sort of identity it is.", model.IdentityKinds),
		"can": schema{"type": "array", "description": "What the identity is allowed to do. Be specific; this drives blast-radius simulation.", "items": object(schema{
			"do": enum("read and write apply to data (or a component's stored data); admin means full control of a component; invoke means it can call the component.", model.Permissions),
			"on": idField("A component or data ID."),
		}, "do", "on")},
		"notes": str("Anything else worth knowing."),
	},
	"components": {
		"name":              str("Human-readable name, e.g. \"Invoice API\"."),
		"kind":              enum("What sort of thing it is. Use other and describe it in notes if nothing fits.", model.ComponentKinds),
		"zone":              idField("ID of the zone it runs in."),
		"exposure":          enum("Who can reach it over the network.", model.Exposures),
		"tech":              strList("Free-form technology tags, e.g. [\"go\", \"postgres\", \"aws-ecs\"]."),
		"features":          strList("What it does, in plain words, e.g. [\"login\", \"password-reset\", \"file-upload\", \"outbound-webhooks\", \"admin-panel\", \"export\"]. Used to suggest relevant threats."),
		"stores":            idList("IDs of data items this component keeps."),
		"identity":          idField("ID of the identity (service account, role) it runs as."),
		"encrypted_at_rest": schema{"type": "boolean", "description": "Whether data it stores is encrypted on disk. Leave out if unknown."},
		"monitored":         schema{"type": "boolean", "description": "Whether security-relevant events are logged and alerted on. Leave out if unknown."},
		"patching":          enum("How updates to its dependencies and software get applied.", model.Patching),
		"code":              strList("Repository-relative paths or globs of the code that implements it, e.g. [\"internal/invoice/**\"]. Used to notice when the code changes."),
		"reviewed": schema{"description": "When someone last checked this component's threats: a date (YYYY-MM-DD), or {\"on\": date, \"by\": \"@someone\"}. Only set this after actually checking them, and never to a future date.", "oneOf": []any{
			date("The review date."),
			object(schema{"on": date("The review date."), "by": str("Who reviewed it, e.g. \"@alice\".")}, "on", "by"),
		}},
		"considered": schema{"type": "object", "description": "Threat kinds that were checked and don't apply, mapped to a one-line reason, e.g. {\"disrupt\": \"Stateless and autoscaled\"}.", "additionalProperties": schema{"type": "string"}},
		"managed":    schema{"type": "boolean", "description": "True for a managed service the provider runs and patches (e.g. RDS, an AWS load balancer)."},
		"notes":      str("Anything else worth knowing."),
	},
	"flows": {
		"from":      idField("ID of the component that starts the request."),
		"to":        idField("ID of the component that receives it. Responses are implied; model two flows if both sides start conversations."),
		"over":      str("Protocol or transport, free-form, e.g. \"HTTPS\"."),
		"carries":   idList("IDs of data items sent over this flow."),
		"auth":      enum("How the receiver authenticates the caller.", model.FlowAuths),
		"encrypted": schema{"type": "boolean", "description": "Whether the traffic is encrypted in transit (e.g. TLS). Leave out if unknown."},
		"notes":     str("Anything else worth knowing."),
	},
	"threats": {
		"title":       str("One sentence in the form \"who could do what by how\", e.g. \"A logged-in customer could read other customers' invoices by changing the invoice ID in the URL\". No unexplained acronyms."),
		"kind":        enum("What the attacker achieves.", model.ThreatKinds),
		"affects":     idList("IDs of the components and/or flows the threat applies to."),
		"attack":      strList("The attack as concrete steps, six or fewer, that a junior developer could follow in a test environment."),
		"who":         enum("The least access an attacker needs.", model.WhoLevels),
		"effort":      enum("How hard the attack is for that attacker.", model.Efforts),
		"impact":      enum("How bad a successful attack is for people and the business.", model.Impacts),
		"impact_note": str("The impact in plain words about people and the business, e.g. \"Exposes names and addresses of every customer\"."),
		"gives": object(schema{
			"reads":    idList("IDs of data the attacker can read."),
			"changes":  idList("IDs of data the attacker can change."),
			"controls": idList("IDs of components the attacker can run code as or act as."),
			"access":   enum("Access level the attacker ends up with.", model.WhoLevels),
		}),
		"status":      enum("Defaults to open when creating. To accept a risk, use set_status instead.", threatStatusesForUpsert),
		"mitigations": idList("IDs of mitigations that address this threat."),
		"reason":      str("Why the threat doesn't apply. Required when status is not-applicable."),
		"risk": object(schema{
			"override": enum("The risk level to show instead of the computed one.", model.RiskLevels),
			"reason":   str("Why the computed risk is wrong for this threat."),
		}, "override", "reason"),
		"from": str("catalog:<catalog>/<entry> when the threat came from the threat library."),
		"refs": schema{
			"type":                 "object",
			"description":          "Security references by scheme, e.g. {\"cwe\": [\"CWE-639\"], \"owasp\": [\"API1:2023\"]}. Keep them out of the title and steps.",
			"additionalProperties": schema{"type": "array", "items": schema{"type": "string"}},
		},
	},
	"mitigations": {
		"title":  str("An action in code or config, scoped to the stack where possible, e.g. \"Check the invoice belongs to the caller's account before returning it\"."),
		"status": enum("Defaults to planned when creating. Set done only when the fix exists, and add evidence.", model.MitigationStatuses),
		"due":    date("When it should be done by (YYYY-MM-DD)."),
		"owner":  str("Who is responsible, e.g. \"@alice\" or \"@org/team\"."),
		"effect": schema{
			"description": "What the mitigation changes about the threats it's linked to: \"eliminates\" (no longer possible), \"detects\" (you'd find out), or an object overriding who, effort or impact, e.g. {\"effort\": \"hard\"}.",
			"oneOf": []any{
				schema{"type": "string", "enum": []string{"eliminates", "detects"}},
				object(schema{
					"who":    enum("Only attackers with this access could now do it.", model.WhoLevels),
					"effort": enum("The attack's effort once this is done.", model.Efforts),
					"impact": enum("The attack's impact once this is done.", model.Impacts),
				}),
			},
		},
		"evidence": schema{
			"type":        "array",
			"description": "Where the fix can be seen. Each entry has exactly one key: {\"code\": \"path/file.go#Symbol\"}, {\"test\": \"path/file_test.go#TestName\"} or {\"link\": \"https://...\"}. Prefer a test.",
			"items": schema{
				"type":          "object",
				"minProperties": 1,
				"maxProperties": 1,
				"properties": schema{
					"code": str("Repository-relative path, optionally #Symbol."),
					"test": str("Repository-relative path of a test, optionally #TestName."),
					"link": str("A URL, e.g. a pull request."),
				},
				"additionalProperties": false,
			},
		},
		"notes": str("Anything else worth knowing."),
	},
}

// upsertSchema is the input schema for upsert_<section>: id, the section's
// fields, and remove.
func upsertSchema(section string) schema {
	fields := sectionFields[section]
	props := maps.Clone(fields)
	props["id"] = idField("The item's ID: lowercase letters, digits and dashes. An existing ID updates that item; a new one creates it.")
	names := slices.Sorted(maps.Keys(fields))
	props["remove"] = schema{
		"type":        "array",
		"items":       schema{"type": "string", "enum": names},
		"description": "Names of fields to delete from the item.",
	}
	return object(props, "id")
}
