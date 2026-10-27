# Simulation: attack paths and blast radius

Most threat modeling stops at a list. A list doesn't show how threats **combine**. A low-risk leak of an internal URL plus a medium-risk missing auth check can add up to a full compromise.

Since the model is a graph (components, flows, zones and threats), we can simulate an attacker moving through it. This isn't a penetration test. It reasons about the model you wrote, so it's only as good as the model. But it's deterministic, fast and explainable, and it answers questions a list can't.

## Questions it answers

1. **"How could someone on the internet get to our payment data?"**
   The tool finds every chain of open threats from a starting point to a target and shows each chain as a short story:
   > 1. Anyone could find the staging admin panel by guessing `admin-staging.acme.com` *(leak-staging-url)*.
   > 2. Anyone could log in there with the default password *(default-admin-password)* → **controls admin-panel**.
   > 3. The admin panel connects to the production database with full access → **reads payments**.

2. **"If this component got hacked, what could the attacker reach?"** (blast radius)
   Pick a component, for example *"the `left-pad` dependency in our build is compromised"*. The tool shows what compromising it **adds** to what anyone on the internet could already reach: the data it stores or receives, what its identity can do, and the components it can reach. Segmenting zones and narrowing identities visibly shrinks it.

3. **"Which fix breaks the most attack paths?"**
   The tool ranks open mitigations by how many paths to sensitive data they'd cut. Often one boring fix, like "remove production DB access from the admin panel", beats ten clever ones.

4. **"What if?"**
   Toggle a mitigation, or mark a threat as fixed, and watch paths disappear in the diagram. Nothing is written to the file unless you save.

## How it works

The simulation tracks the attacker's **position**: the access level, the components they control, and the data they can read or change. It then repeatedly applies any open threat they now qualify for.

- **Start:** an access level from the `who` scale (`anyone`, `any-user`, …) or "controls component X".
- **A threat applies** when the attacker has at least the `who` access it requires *and* can reach one of its `affects` targets. A target is reachable if it's exposed to the attacker's zone or controlled components, or sits next to them via a flow. When a threat applies, its `gives` is added to the position.
- **Built-in rules,** which follow from the model's structure:
  - controlling a component lets you read everything it `stores` and everything that flows into or out of it
  - controlling a component lets you do whatever its `identity` is allowed to (`read`, `write`, `admin`, `invoke`)
  - controlling a component lets you reach everything it has flows to, as that component, which counts as being "on the network" for insider-level threats against those targets
  - in an `open` zone (a flat network), controlling one component reaches everything else in the zone, and controlling something in a trusted open zone puts you on the inside
  - in a `segmented` zone, only declared flows and identity permissions get you in

**Getting data out.** Reading data isn't the end of an attack, because the data still has to leave. Each path ends with how it gets out: straight to the attacker, through a component that's reachable from the internet, through a component in a zone with open egress, or over a flow to a third party. If none of those exist, the path is marked **contained**: the attacker could read the data, but nothing lets it out. Contained paths are listed after the others, and restricting egress shows up as a fix that matters.
- **It stops** when nothing new can be gained. The model is small, so this is a quick graph search.

Only threats with `status: open`, or threats whose mitigations aren't `done`, are used. Mitigations with `effect: eliminates` remove a threat from the search, and other effects change `who` or `effort` before the threat is applied.

Each path is ranked by its *weakest link*, meaning the step with the highest effort, so "three trivial steps" ranks above "one hard step".

## What it can't do (and won't pretend to)

- **It doesn't find threats you didn't write down.** Missing threats mean missing paths. The [threat library](threat-library.md) and coverage view are there to reduce that gap.
- **It doesn't touch real systems.** No scanning, no exploitation. Model-level reasoning only.
- **`gives` is a judgment call.** If the model says a threat gives control of a component, the simulation believes it.

## Going further: agent red-teaming (experimental)

An agent can play attacker against the model through MCP using the `red-team` prompt. It reads the model, proposes new threats or chains that are missing, and submits them as **suggestions**, never directly into the model, each with its attack steps. This is non-deterministic, so it's opt-in and clearly labelled. Humans accept or dismiss each suggestion like any other.

## Going further: threats as tests

The strongest evidence that a mitigation works is a test that tries the attack. The `attack` steps of a threat are often close to a test case, for example *"log in as user A, request user B's invoice, expect 404"*.

- The `test:` evidence type links a mitigation to the test that proves it.
- `threat check` warns when a `done` mitigation for a high or critical threat has no test evidence.
- Agents can be asked to write that test from the attack steps, using the MCP `write-attack-test` prompt.

This turns the model from documentation into something that fails CI when a fix regresses.
