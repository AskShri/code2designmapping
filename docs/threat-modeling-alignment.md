# Alignment with the Black Duck threat modeling model

**References (all Black Duck, formerly Synopsys Software Integrity Group):**
* Glossary: "What Is Threat Modeling and How Does It Work?" https://www.blackduck.com/glossary/what-is-threat-modeling.html
* "The Step-by-Step Guide to Threat Modeling" (six steps) https://www.blackduck.com/blog/threat-modeling-guide.html
* "The 5 Pillars of a Successful Threat Model" https://www.blackduck.com/blog/5-pillars-successful-threat-model.html
* "Guide to Creating a System Model in Threat Modeling" https://www.blackduck.com/blog/creating-a-system-model-in-threat-modeling.html
* AppSec Decoded series (five steps: scoping, data gathering, system model, attack model, risk analysis): https://www.blackduck.com/blog/appsec-decoded-scoping-data-gathering-in-threat-modeling.html , https://www.blackduck.com/blog/appsec-decoded-attack-model.html , https://www.blackduck.com/blog/appsec-decoded-threat-modeling-risk-analysis.html
* Threat modeling datasheet and Architecture Risk Analysis (ARA) datasheet: https://www.blackduck.com/content/dam/black-duck/en-us/datasheets/threat-modeling-datasheet.pdf , https://www.blackduck.com/content/dam/black-duck/en-us/datasheets/architecture-risk-analysis-datasheet.pdf
* "Effective Threat Modeling in SDLC" https://www.blackduck.com/blog/threat-modeling-sdlc.html

**Caveat:** blackduck.com is not reachable from the sandbox this document was written in, so every page above was read through search-engine summaries rather than verbatim. The quoted phrases are the ones those summaries attribute to Black Duck. Re-check against the live pages before quoting externally.

## Black Duck's guidance in one place

Black Duck describes the same practice at three granularities, and the tool is aligned to all three:

| Granularity | Steps | Where code2design supports it |
|---|---|---|
| Glossary, four steps | Diagram; Identify threats; Mitigate; Validate | Section "The four steps" below |
| AppSec Decoded, five steps | Scoping; Data gathering; System model; Attack model; Risk analysis | Section "The five steps" below |
| Step-by-step guide, six activities | Scoping with stakeholders; reading the development team's artifacts; the component diagram; adding assets, controls, threat agents and trust zones; threat analysis along control paths with a traceability matrix; documentation of system descriptions, potential risks, actual risks, likelihood and impact | Covered by the two sections above plus "Documentation" |

Black Duck's Architecture Risk Analysis service adds a fourth lens: build the threat model (components, assets, threat agents, controls and their relationships), prioritize software risks by business impact, and analyze three ways: known attacks, system-specific attacks against established security principles, and **dependency analysis** of third-party components. The tool's attack-surface report now lists declared third-party dependencies for that last analysis.

## What Black Duck's model asks of a DFD

Black Duck describes threat modeling as a structured process whose artifacts are "an abstraction of the system," "profiles of potential attackers, including their goals and methods," and "a catalog of threats that could arise." It describes four steps: **Diagram** (what are we building?), **Identify threats** (what could go wrong?), **Mitigate** (what are we doing to defend against threats?), **Validate** (have we acted on each of the previous steps?). Its best practices are:

1. **Define the scope and depth of analysis** with stakeholders.
2. **Gain a visual understanding**: diagram the major system components and the interactions among them.
3. **Model the attack possibilities**: "identify software assets, security controls, and threat agents and diagram their locations to create a security model of the system." The step-by-step guide names the elements added to the component diagram as **assets, controls, threat agents and trust zones**.
4. **Identify threats** by asking "Are there paths where a threat agent can reach an asset without going through a control?", "Could a threat agent defeat this security control?" and "What must a threat agent do to defeat this control?"
5. **Create a traceability matrix of missing or weak security controls**: for every threat agent and asset pair, follow the agent along the control path; reaching the asset without passing a control is a potential attack, and each control crossed is judged on whether it would halt the agent or could be bypassed.

## The five steps (AppSec Decoded, "Threat Modeling, Decoded")

| Step | What Black Duck says it needs | What code2design produces | Gap the human fills |
|---|---|---|---|
| 1. Scoping | Stakeholders set the parameters and boundaries for which components are reviewed, and the depth. | `provenance.scope` records include/exclude globs, depth and out-of-scope element IDs; the report's coverage table states which files and languages were analyzed and which were not. | Decide the boundary of the review; the tool only records it. |
| 2. Data gathering | Read and review the artifacts the development team provides: architecture documents, existing diagrams, code, configuration, deployment descriptors. | Code, compose and Kubernetes manifests, Dockerfiles, package manifests, Prisma schemas and committed env files are read automatically; the report lists what was read and what produced no facts. Overrides and imported OTM files bring in human-held knowledge. | Supply what the code does not contain: network topology, managed-service settings, business context. |
| 3. System model | A component diagram with data flows, then assets, controls, threat agents and trust zones added to make the security model of the system. | Leveled DFDs with every element evidence-backed, plus the `assets`, `controls`, `threat_agents` and `boundaries` collections. | Correct names and groupings; declare assets and agents the heuristics cannot see. |
| 4. Attack model | How well are the assets protected against threats: attack surface (entry points), threat agents and their paths to assets through the controls. | The attack-surface section of the report (entry points by protocol with and without authn, listeners, exit points carrying sensitive data, dependency count), the STRIDE-per-element table, and the control-path traceability matrix. | Judge whether each control actually halts the agent or can be bypassed. |
| 5. Risk analysis | Likelihood and impact per threat; assets prioritized by risk, threats by likelihood; a prioritized remediation plan. | Not produced. Exports (OTM, Threat Dragon, pytm, Threagile) carry the model into tools that score risk; the matrix's ordering (no effective control first) is an input, not a rating. | All of it. |

## Documentation (step six of the guide)

Black Duck closes with documenting "all your models, system descriptions, potential risks, actual risks, and their associated likelihood and impact." The report is the system description; the STRIDE table is the catalog of potential risks; the "no effective control" and "weakness" rows are the candidates for actual risks; likelihood and impact are left blank for the analyst. Everything is regenerated from code on every run, which is what keeps the documentation from drifting.

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
| Attack surface | Report section: entry points per protocol (with the count lacking authn), listeners and ports, exit points carrying sensitive data, declared third-party dependencies | Added |
| Dependency analysis (ARA) | Dependency count and manifests in the attack-surface section; packages recognized as stores, SDKs or auth middleware become model elements, the rest are listed as unmodeled surface | Partial: inventory only, no vulnerability data |

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
4. Among the routes, take the one that crosses the fewest **blocking** controls the agent does not hold (authentication and authorization; an authenticated user holds `authn`), ties broken by length and then by ID. Controls registered only under a condition do not count as blocking. Other controls on the route (validation, rate limiting, CSRF, security headers) are listed separately because they reduce risk without stopping the agent. External entities other than the agent's own starting point are not traversed.
5. Verdict: no route is "unreachable"; a route with no blocking control is a potential attack path; a route where the agent's credentials pass authentication and no authorization check is detected is flagged for object- and function-level access review; a route whose non-local links have `unknown` authentication or encryption is "blocked at entry" with the unanswered link named; otherwise "blocked". An agent that starts inside the asset holder's element gets its own verdict, since no flow-level control can apply.

The matrix answers Black Duck's three questions directly: the "no blocking control" rows are the paths where an agent reaches an asset without a control; the "blocking controls" column lists what the agent must defeat; the "unknown" verdict marks controls the tool cannot vouch for.

## Evidence that the alignment holds on real code

`docs/evaluation.md` runs the prototype over 23 sample applications (Express, NestJS, Flask, FastAPI, Django, Spring, Gin, ASP.NET Core, gRPC microservices, compose and Kubernetes deployments) and checks, for each, that the security model elements above are produced: entry points with their controls, declared and used data stores, external dependencies, trust boundaries from deployment descriptors, derived threat agents, assets, and a traceability matrix. The misses found there (dynamic route tables, aliased database clients, unsupported languages) are listed with the fixes applied or the gap recorded.

## Worked example

`examples/orders-service/output/traceability-matrix.md` for the sample service shows, worst first:

* the insider agent starting at the processes that hold the Stripe key and read the stores, with no control that can apply;
* a compromised Stripe responder reaching the charge path with no control on the response;
* the authenticated client reaching the PII and financial data with only `requireJwt` on the path and no authorization check, flagged for object-level access review;
* the anonymous client blocked by `requireJwt`, with the store links named as open questions because their authentication and encryption are unknown.

Each row is a question the team can answer with an override (for example, declaring the Postgres link as `encryption: tls, authentication: credentials` from the infrastructure they know), after which the row's verdict changes on the next run.

## Status of the earlier limitations

The first evaluation listed six limitations against this alignment. Their status after the second iteration (details in `evaluation.md`):

| Limitation | Status |
|---|---|
| Controls credited by path, including plumbing | Fixed: registration-order aware, plumbing excluded, conditional registration flagged |
| File-level attribution of accesses | Fixed: function-level call graph; each entry point lists what its handler reaches |
| Go, Java, C# invisible | Fixed at recognizer level for the mainstream frameworks; Ruby, PHP, Kotlin, Rust remain gaps |
| No schemas, no assets | Fixed: request fields read in handlers become schemas; overrides can declare assets and agents |
| Infrastructure routes polluting the attack surface | Fixed: tagged and counted separately |
| No precision/recall measurement | Fixed: ground truth for ten samples; entry points, authentication, stores, entities and reachability edges scored |
| Weaknesses without a standard classification | Fixed in v0.5: each weakness kind carries a CWE, a severity and its STRIDE categories, and is exported as OTM threats and SARIF results |

## Not covered on purpose

* **Risk rating and prioritization** (likelihood, impact, CVSS, DREAD). Black Duck's process scores threats after the matrix; that belongs in the downstream tool, and the IR carries no scores.
* **Threat methodology choice.** The tool is methodology-neutral. STRIDE-per-element is the default export because it maps mechanically to DFD elements; PASTA, VAST, Trike and attack trees consume the same model through the OTM, pytm and Threat Dragon exports.
* **Attacker profiling beyond defaults.** Derived agents are placeholders. The goals and skills of real threat agents are a human input.
