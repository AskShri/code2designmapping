# Alignment with the Black Duck threat modeling model

**Reference:** Black Duck, "What Is Threat Modeling and How Does It Work?" (https://www.blackduck.com/glossary/what-is-threat-modeling.html), with its companion posts "The Step-by-Step Guide to Threat Modeling" and "The 5 Pillars of a Successful Threat Model."

**Caveat:** the glossary page could not be fetched verbatim from the sandbox this document was written in; its content was taken from search-engine summaries of the page and from the two companion Black Duck posts. The quoted phrases below are the ones those summaries attribute to Black Duck. Re-check against the live page before quoting it externally.

## What Black Duck's model asks of a DFD

Black Duck describes threat modeling as a structured process whose artifacts are "an abstraction of the system," "profiles of potential attackers, including their goals and methods," and "a catalog of threats that could arise." It describes four steps: **Diagram** (what are we building?), **Identify threats** (what could go wrong?), **Mitigate** (what are we doing to defend against threats?), **Validate** (have we acted on each of the previous steps?). Its best practices are:

1. **Define the scope and depth of analysis** with stakeholders.
2. **Gain a visual understanding**: diagram the major system components and the interactions among them.
3. **Model the attack possibilities**: "identify software assets, security controls, and threat agents and diagram their locations to create a security model of the system." The step-by-step guide names the elements added to the component diagram as **assets, controls, threat agents and trust zones**.
4. **Identify threats** by asking "Are there paths where a threat agent can reach an asset without going through a control?", "Could a threat agent defeat this security control?" and "What must a threat agent do to defeat this control?"
5. **Create a traceability matrix of missing or weak security controls**: for every threat agent and asset pair, follow the agent along the control path; reaching the asset without passing a control is a potential attack, and each control crossed is judged on whether it would halt the agent or could be bypassed.

## Element-by-element mapping

| Black Duck element | code2design IR | Status |
|---|---|---|
| System components and their interactions | `processes` (L0/L1/L2), `entities`, `stores`, `flows` with protocol and payload | Already present |
| Trust zones / trust boundaries | `boundaries`, nested, always rendered; flows record `crosses_boundary` | Already present |
| Security controls, diagrammed at their location | `controls` attached to entry points and flows; `authentication` and `encryption` on every flow; `encryption_at_rest` on stores | Already present |
| Missing or weak controls | `weaknesses` (provable negatives) and `unknown` attribute values surfaced as questions | Already present |
| **Software assets** | **New `assets` collection**: `kind` (data, credential, key, privileged_function, system), `data_classes`, `held_by`, `processed_by`, with evidence. Derived from schema fields with sensitive data classes, stores that hold them, and secrets read from config; extendable by overrides. | Added |
| **Threat agents with goals, methods and location** | **New `threat_agents` collection**: `access` (anonymous, authenticated, insider, third_party, physical), `location` (boundary), `entry` (elements the agent reaches directly), `passes_controls` (controls the agent legitimately satisfies), `goals`. Default agents are derived, one per way into the system: an anonymous caller at every public entry point, an authenticated caller where authn exists, an insider per trust boundary, and a potentially hostile responder per external dependency. All are `origin: inferred` and meant to be edited in `overrides.yaml`. | Added |
| **Traceability matrix of control paths** | **New `traceability-matrix.md` export**: for every (agent, asset) pair, the shortest path over the flow graph from the agent's entry to an element holding the asset, the controls crossed, the controls still effective for that agent, and a verdict ordered worst first. | Added |
| Scope and depth of analysis | `provenance.scope` (include/exclude globs, depth level, out-of-scope element IDs); out-of-scope elements are rendered greyed | Added |
| Catalog of threats | STRIDE-per-element table (`stride-table.md`), plus OTM, Threat Dragon, pytm and Threagile exports for tools that enumerate threats | Already present |
| Attacker profiles | Threat agent profile table in the traceability export | Added |

## The four steps, mapped to the tool

| Step | Black Duck question | What code2design produces | Where the human comes in |
|---|---|---|---|
| Diagram | What are we building? | L0/L1/L2 DFDs, per-entry-point control flows, per-store neighborhoods, all evidence-backed and deterministic | Confirms scope; corrects names and groupings via overrides |
| Identify threats | What could go wrong? | STRIDE table with exit points and weaknesses first; traceability matrix with "no effective control" rows first; questions list for unknown attributes | Answers the unknowns; edits the derived threat agents; rates risk in a downstream tool |
| Mitigate | What are we doing to defend against threats? | Controls and their coverage per flow and entry point; weaknesses; the matrix shows which controls each agent must defeat | Adds or strengthens controls in code; records accepted risks downstream (Threat Dragon, FlowStrider, IriusRisk) |
| Validate | Have we acted on each of the previous steps? | `verify` re-checks every evidence span and content hash; PR mode diffs the model and flags new exit points, removed controls, new uncontrolled paths; lint gates fail CI | Reviews the PR design delta |

## How the traceability matrix is computed

1. Build an undirected graph whose nodes are processes, entities and stores and whose edges are flows (an attacker can push requests along a request flow and pull data back along a response or read flow).
2. For each threat agent, start a breadth-first search at its `entry` elements. Neighbours are visited in ID order, so the result is deterministic.
3. For each asset, the target set is `held_by`; if nothing in it is reachable, fall back to `processed_by`.
4. Record the flows traversed and the controls on them. Controls whose kind is in the agent's `passes_controls` are crossed but not effective (an authenticated user passes `authn`).
5. Verdict: no path is "unreachable"; a path with no effective control is a potential attack path; a path whose non-local links have `unknown` authentication or encryption is "controlled at entry" with the questionable link named; otherwise "controlled". An agent that starts inside the asset holder's element gets its own verdict, since no flow-level control can apply.

The matrix answers Black Duck's three questions directly: the "no effective control" rows are the paths where an agent reaches an asset without a control; the "effective controls" column lists what the agent must defeat; the "unknown" verdict marks controls the tool cannot vouch for.

## Worked example

`examples/orders-service/output/traceability-matrix.md` for the sample service shows, worst first:

* the insider agent starting at the processes that hold the Stripe key and read the stores, with no control that can apply;
* a compromised Stripe responder reaching the charge path with no control on the response;
* anonymous and authenticated clients reaching the Postgres and Redis holders of PII through the JWT, rate-limit and validation controls, with the store links flagged because their authentication and encryption are unknown.

Each row is a question the team can answer with an override (for example, declaring the Postgres link as `encryption: tls, authentication: credentials` from the infrastructure they know), after which the row's verdict changes on the next run.

## Not covered on purpose

* **Risk rating and prioritization** (likelihood, impact, CVSS, DREAD). Black Duck's process scores threats after the matrix; that belongs in the downstream tool, and the IR carries no scores.
* **Threat methodology choice.** The tool is methodology-neutral. STRIDE-per-element is the default export because it maps mechanically to DFD elements; PASTA, VAST, Trike and attack trees consume the same model through the OTM, pytm and Threat Dragon exports.
* **Attacker profiling beyond defaults.** Derived agents are placeholders. The goals and skills of real threat agents are a human input.
