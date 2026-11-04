# Landscape research: tools that turn code into design or threat models

**Date:** 2026-11-04
**Purpose:** Survey what exists in the market, on GitHub and in the literature, and extract lessons for code2design (see `design.md`). Each section ends with a "lesson" line that is either adopted in the design, rejected with a reason, or left open.

The field splits into four families. None of them covers the whole of our goal (accurate, consistent, clear DFDs from code or a PR, usable for threat modeling), but each solved part of it.

| Family | Representative tools | What they do well | Where they stop |
|---|---|---|---|
| A. Static DFD extraction from code | Code2DFD (TUHH), Peldszus/Tuma model-code compliance, Structurizr component finder, vibeX importers, threatmap (IaC) | Evidence-backed elements, precision in the 85–95% range, traceability | Single ecosystem each (Java/Spring, IaC, Prisma/OpenAPI); no PR mode; dated notation |
| B. LLM-driven architecture diagrams | GitDiagram, DeepWiki, Swark, CodeBoarding, archify and dozens of Claude Code skills | Fast, readable, popular (GitDiagram 18.7k stars, archify 93k) | Non-deterministic, unverifiable relationships, no security attributes; the better ones add static analysis and path validation |
| C. Threat modeling as code / model consumers | Threagile, pytm, OWASP Threat Dragon, FlowStrider, AWS Threat Composer, IriusRisk/OTM and StartLeft, ThreatModeler IaC-Assist | Mature attribute vocabularies, rule engines, CI gating, interchange formats | They consume a model; someone or something still has to produce it |
| D. Commercial code graphs / runtime | Apiiro Software Graph, Backslash App Graph, Endor Labs, AppMap | Continuous models, code-to-runtime linkage, PR-level behavioral diffs | Closed, platform-bound, no exportable DFD; AppMap needs runtime recording |

---

## A. Static extraction of DFDs from code

### Code2DFD (TU Hamburg, Schneider and Scandariato, JSS 2023)

The closest prior work to our goal. It extracts security-enriched DFDs from Java/Spring microservice repositories by running a set of technology-specific extractors (about 40: `spring_gateway`, `feign_client`, `resttemplate`, `kafka`, `rabbitmq`, `database_connections`, `spring_oauth`, `spring_encryption`, `ssl`, `http_security`, `plaintext_credentials`, `docker_compose`, `consul`, `eureka`, `zuul`, `nginx`, `prometheus`, …) that scan code and configuration for evidence of DFD items. Outputs: PlantUML, a JSON architecture file, an edges file, a results text file and a traceability file that links items to code, which the README admits is "not created for all items as of now." Reported precision 93% and recall 85% on the authors' benchmark. The companion dataset microSecEnD (MSR 2023) has 17 hand-made, security-annotated DFDs of open-source Java microservice apps, each item traceable to code, with 17 architectural security rules and compliant/non-compliant variants.

Lessons:
* **Adopted.** Technology-specific extractors that emit *evidence* rather than graph edges, and a separate synthesis step, is exactly our detector/fact design. Their extractor list is a good checklist for our Java/Spring recognizers.
* **Adopted.** Security features as first-class annotations on nodes and edges (OAuth, encryption, plaintext credentials, circuit breakers). Our `controls` collection covers this; we should add `plaintext_credentials` style *negative* findings, which the current design lacks (see "Changes to the design" below).
* **Adopted.** microSecEnD is a ready-made ground-truth benchmark. Use it for the Java recall/precision targets instead of hand-building all 20 benchmark repos ourselves.
* **Avoid.** Traceability as an afterthought. Code2DFD bolted it on partially; we make evidence a schema requirement.
* **Avoid.** Non-standard rendering (their CodeableModels output does not follow DFD notation). One notation, always.

### Model-to-code compliance (Peldszus, Tuma, Strüber, Jürjens, Scandariato; MODELS 2019 and SoSyM 2023)

The inverse problem: given a hand-drawn security DFD and the code, map DFD elements to program elements with name similarity plus structural heuristics, then check that the code's data flows comply with the model. Mapping suggestions reached up to 87.2% precision; the two compliance checks averaged 79.6% and 100% precision with recall 65.5% and 94.5%. They explain the recall gap as the "gap between design and implementation" and report up to 62% fewer false alarms than a plain data-flow analyzer because the model narrows what matters.

Lessons:
* **Adopted.** The identity tuple plus override file in our design is a lightweight version of their model-code mapping. Their heuristics (name similarity between a DFD node and a package or class, plus structural matching of flows) are a good fallback when SCIP cross-references are missing.
* **Open.** Their compliance-check framing suggests a second mode for code2design: given a *declared* DFD (overrides or an imported OTM file), report divergence from the extracted one. This is the same machinery as PR diff and is cheap to add later.

### Structurizr component finder (Java) and go-structurizr

Structurizr's component finder derives C4 component diagrams from compiled Java using pluggable matching rules such as "classes annotated `@Controller`" or "classes implementing Spring Data `Repository`", exposed in the DSL as `!components`. The rules are explicit, deterministic and user-extensible.

Lessons:
* **Adopted.** Recognizers should be declarative where possible (annotation, base class, call-site pattern) so teams can add their own without touching the core, the way Structurizr strategies and Semgrep rules work. We add a YAML recognizer format to the roadmap.
* **Adopted.** C4 is the de facto model for context/container views; our L0/L1 map onto Context and Container, and the Structurizr DSL export stays in scope.

### vibeX (Raja0sama/vibex, 2026)

"Your architecture diagram is a lie." Deterministic importers for Prisma, OpenAPI and GraphQL SDL, plus a code reader for NestJS, Express, TypeORM and SQL migrations, produce JSON specs rendered as a single HTML file (ERD, C4, endpoints, lifecycle, sequence). Its distinctive feature is *checkable docs*: each prose claim carries a source that is `derived` (computed from a spec), `anchored` (pinned to a file and symbol by a content hash) or `asserted` (a named person, with an expiry). `vibex docs --check` exits non-zero when a claim no longer holds, with "no model in the verification path." Stated limit: it catches drift, not initial error.

Lessons:
* **Adopted.** Content-hash anchoring of evidence. Our evidence records `path` and line range; adding a hash of the referenced span lets `verify` detect that the code under an element changed even when the lines still exist. Added to the schema.
* **Adopted.** Expiring human assertions. Our `overrides.yaml` entries get an optional `expires` date and an `author`, so declared facts cannot silently outlive the code they described.
* **Adopted.** "Catches drift, not initial error" is the honest framing for PR mode too: the first full model needs a human read; from then on the tool guards it.

### threatmap (PyPI) and ThreatModeler IaC-Assist

threatmap parses Terraform, CloudFormation and Kubernetes manifests into a STRIDE report plus DFD, offline, with per-cloud rule sets and a CI fail-on-severity switch. IaC-Assist does the same commercially (CloudFormation, Terraform for AWS/Azure/GCP, ARM) with a VS Code plugin and a HashiCorp run task on `terraform plan` output. Both only see what the templates declare.

Lessons:
* **Adopted.** IaC is the best source of trust boundaries and store identities; code is the best source of flows. Our boundary_hint detectors should read Terraform *references* (an IAM policy or security group that permits A to reach B is itself evidence of a flow), not just resources.
* **Adopted.** Fail-on-severity as a CI gate. Already in the design; keep it.

---

## B. LLM-driven architecture diagrams

### GitDiagram (18.7k stars)

Input is the GitHub file tree, the README and a bounded, integrity-checked set of source excerpts. One model call streams an overview and a strict graph (groups, nodes, edges, labels, repo paths). The server validates the graph and every linked path against the real repository, and a deterministic compiler turns the validated AST into Mermaid; the model never writes Mermaid. Stated limits: the model sees only an excerpt of the tree; large repos get a shallow read; no accuracy figure.

Lessons:
* **Adopted.** Never let the model emit diagram syntax. Our design already renders only from the IR; GitDiagram confirms this is what makes LLM output stable and safe to render.
* **Adopted.** Validate every path the model mentions against the repo and drop what does not resolve. Our proposal validator does this by fact ID.
* **Avoid.** Tree-and-README as the primary input. It produces plausible diagrams that cannot distinguish a dead module from a live one, and cannot see a data store that is only visible at a call site.

### CodeBoarding (MIT, 2025–2026)

Static analysis via language servers extracts symbols, call-graph nodes and edges for Python, TypeScript, JavaScript, Java, Kotlin, Go, PHP, Rust and C#; an LLM then groups code into components and describes them. Output is `analysis.json` with "source references," rendered to Markdown/Mermaid, HTML, MDX or RST, plus a GitHub Action, VS Code extension and an incremental mode that re-analyzes only what changed against a baseline in `.codeboarding/`. Nesting is capped by `--depth-cap` (default 3), and components past a leaf ceiling are marked "expandable" and expanded on demand.

Lessons:
* **Adopted.** Static structure first, LLM for grouping and naming, is the same split as ours; CodeBoarding is evidence the split works across nine languages with off-the-shelf language servers.
* **Adopted.** Incremental analysis against a cached baseline. Our PR mode computes base and head from scratch; caching the base IR by commit makes it cheap and is now in the design.
* **Adopted.** "Expandable" leaf components instead of silently collapsing. We keep the node budget but mark collapsed nodes visibly.
* **Open.** CodeBoarding does not state determinism guarantees. Grouping by LLM can change between runs; our rule that the LLM may only *propose* groupings that are then canonicalized is the fix.

### Swark, DeepWiki, archify and the Claude Code skill ecosystem

Swark (VS Code) sends code to Copilot and asks for a Mermaid diagram; there are no per-language rules. DeepWiki (Cognition) indexes a repository into a wiki with diagrams and source links. archify (93k stars) and a long tail of Claude Code skills (`claude-d2-diagrams`, `codemap`, `diagram-skill`, `software-architecture-skill`) generate diagrams from a prompt over the codebase. The common critique, stated by a reviewer of Swark, is that the output is "a generated interpretation rather than a mechanical graph of imports and calls, so you can't debug why a relationship is missing."

Lessons:
* **Adopted.** Packaging matters: the most-used tools are one-command skills, VS Code extensions and GitHub Actions. We add an MCP server and a Claude Code skill wrapper to the delivery plan so the IR can be queried by assistants.
* **Avoid.** Diagrams without a debuggable derivation. Every edge in ours has a fact ID.

### RECoRD (AAAI 2026) and related evaluations

RECoRD is a multi-agent LLM framework that reverse-engineers a codebase into a causal relational diagram by combining AST parsing and data-flow analysis with LLM refinement, and reports entity-level precision and recall under different inputs. LLMCFG-TGen (Dec 2025) evaluates LLM-generated control-flow graphs node- and edge-wise against hand-built ground truth and reports node F1 above 0.9. LLMDFA (NeurIPS 2024) reports 87.1% precision and 80.8% recall for LLM-driven dataflow analysis on the Juliet suite. A registered report by Mbaka and Tuma (2024) is testing whether LLM advice plus a DFD helps practitioners validate threats.

Lessons:
* **Adopted.** Evaluate at node *and* edge level, matched by identity, not by picture. Our section 10 already does this; we add edge-level F1 as the headline metric because flows are what threat modeling consumes.
* **Adopted.** Report precision/recall with and without the LLM stage, as an ablation, so users can see what the model adds.

---

## C. Threat modeling as code and interchange formats

### Threagile (Go, YAML model, ~40 risk rules)

A YAML architecture model checked into git, evaluated by built-in and custom risk rules (written in Go), with DFD, data-asset diagram, JSON, Excel and PDF outputs and a risk-tracking section for accepted risks. Its vocabulary is the most complete of the open tools. Technical assets carry `type` (external-entity, process, datastore), `technology`, `size`, `machine` (physical, virtual, container, serverless), `encryption` (none, transparent, data-with-symmetric-shared-key, …), `internet`, `multi_tenant`, `data_assets_processed`, `data_assets_stored`, CIA ratings. Communication links carry `protocol`, `authentication` (none, credentials, session-id, token, client-certificate, two-factor), `authorization` (none, technical-user, end-user-identity-propagation), `data_assets_sent`, `data_assets_received`, and tags such as `vpn`, `ip_filtered`, `readonly`. Data assets carry `quantity`, `confidentiality` (public → strictly-confidential), `integrity`, `availability`, `origin`, `owner`.

Lessons:
* **Adopted.** Threagile's link attributes are what a rule engine needs and what reviewers ask first: "is this flow authenticated, and how?" Our flows gain `authentication` and `encryption` fields with Threagile-compatible values, derived from controls when a detector can tell and `unknown` otherwise. Stores gain `encryption_at_rest`.
* **Adopted.** Separate *data assets* from flows. Our `schemas` collection already plays this role; the STRIDE export now also lists per data class where it is processed and stored, Threagile-style.
* **Adopted.** A Threagile YAML export, so teams already running its rules can point them at a generated model.
* **Avoid.** CIA ratings and risk scores in the extracted model. They are human judgments; we leave them to overrides or the downstream tool.

### OWASP pytm

Python classes (`Actor`, `Server`, `Process`, `Datastore`, `Dataflow`, `Boundary`, `Lambda`, and recently `LLM` and `Agent`) describe the system; a threat library of condition expressions finds threats; `--dfd` emits Graphviz DOT and `--seq` PlantUML. Dataflow carries `protocol`, `srcPort`/`dstPort`, `tlsVersion`, `data` (a set of `Data` objects with `classification`, `isPII`, `isCredentials`, `isStored`, encryption-at-rest flags, `credentialsLife`), `order`, `isResponse`/`responseTo`, `usesVPN`, `usesSessionTokens`; security properties sit on `controls` (`isEncrypted`, `authenticatesDestination`, `hasAccessControl`, `isHardened`, …). Classification is an ordered enum (UNKNOWN, PUBLIC, RESTRICTED, SENSITIVE, SECRET, TOP_SECRET), and elements can carry `sourceFiles`.

Lessons:
* **Adopted.** `order` and `isResponse`/`responseTo` on flows are how pytm derives sequence diagrams from the same model that draws the DFD. Our `call_chain` plus `direction: request_response` does the same; the export maps onto these fields directly.
* **Adopted.** pytm already has `sourceFiles` on elements, so our evidence paths survive the export.
* **Noted.** pytm's new `LLM` and `Agent` element types and Shostack's PHANTOM-B argue that DFDs need no new notation for AI components; we add `llm_api` as a recognizer family (OpenAI, Anthropic, Bedrock SDK clients) because PII reaching a model provider is the "exit point" reviewers now ask about first.

### OWASP Threat Dragon, FlowStrider, AWS Threat Composer

Threat Dragon (1.7k stars) is a diagram editor with a JSON v2 model and per-element STRIDE threat generation. FlowStrider (DLR, ASE 2025 tool track) takes a DFD as JSON, reports which metadata each element is missing for the selected threat catalogs, lets a human fill it in, merges it back, and can fail CI on undecided threats. Threat Composer (AWS Labs) stores threat statements in `.tc.json`, git-friendly, with a VS Code extension and a `threat-composer-ai` CLI/MCP server that drafts a model from a codebase with Bedrock.

Lessons:
* **Adopted.** FlowStrider's "missing metadata" report is a better interaction than guessing: when a detector cannot determine authentication or encryption for a flow, the IR says `unknown` and the HTML report lists the unknowns as questions for the team. This reuses the `gaps` list.
* **Adopted.** Threat state tracking (`undecided`, `todo`, `accepted`) belongs in the downstream tool, not in the IR. We export; we do not track.
* **Noted.** Threat Composer confirms the direction of travel: every threat-model vendor is adding "draft it from the code with an LLM." The differentiator is not the draft, it is evidence and repeatability.

### Open Threat Model (OTM, IriusRisk, CC-BY-SA-4.0, schema 0.2.0) and StartLeft

OTM is a YAML/JSON interchange format with `trustZones` (id, name, `risk.trustRating`, `type`, optional `parent`), `components` (id, name, `type`, exactly one `parent` which is a trust zone or a component, `tags`, `assets.processed`/`stored`), `dataflows` (id, name, `source`, `destination`, `bidirectional`, `assets`), `assets` with CIA ratings, `threats` and `mitigations`. `representations` can be of type `code` with a `repository.url`, and any element can point into it with `file`, `line` and `codeSnippet`. IriusRisk's StartLeft converts Terraform, CloudFormation, Visio, draw.io and Lucid into OTM via mapping files, and IriusRisk builds a full threat model from an OTM file through its rules engine. The spec's docs are loose (the README example uses `target` where the spec says `destination`; some typos), so validate against `otm_schema.json`.

Lessons:
* **Adopted.** OTM becomes a first-class export. It is the only open format with native code references (file and line), nested trust zones and a commercial consumer. Our IR maps cleanly: boundaries to trust zones, processes/entities/stores to components with `type`, flows to dataflows, schemas to assets, evidence to `code` representations.
* **Adopted.** StartLeft's mapping-file approach for IaC (resource type → component type, reference → dataflow) is the shape of our `boundary_hint` detectors for Terraform.
* **Noted.** OTM requires a single parent per component and a trust rating per zone; we emit the default `repository` zone with a neutral rating when IaC gives us nothing, and say so in `gaps`.

### LLM threat modelers: StrideGPT (1.1k stars), TaaC-AI, threat-composer-ai

StrideGPT 0.20 analyzes a codebase directory with an LLM agent that has `read_file`, `grep_content` and `list_directory` tools, capped by `--max-tool-calls` per subsystem. It then produces STRIDE tables, Mermaid DFDs (also exposed as a `data_flow_diagram` JSON field), attack trees, DREAD scores, SARIF with file and line ranges, and run manifests with hashes and git SHA. Its changelog states that "every quoted snippet is checked against the file on disk before the threat is recorded" and unmatched claims are kept as "unverified" rather than dropped. TaaC-AI takes a hand-written YAML service description, not code, and optionally cross-validates with a second model. threat-composer-ai drafts a Threat Composer model from a repo with Bedrock.

Lessons:
* **Adopted.** StrideGPT's post-hoc snippet verification is the LLM-side counterpart of our evidence rule; we go one step further by not letting the model create elements at all, but we keep their "unverified" bucket for proposals that fail validation, so reviewers can see what the model wanted to add.
* **Adopted.** Run manifests (git SHA, hashes of inputs, per-stage outcomes). Our `provenance` block gains input hashes.
* **Avoid.** Tool-call budgets as the only bound on coverage. Coverage should be stated per file, not implied by a budget.

### drawing-agent (Destiny-63, alpha)

A small, recent project with exactly our philosophy: `facts.json` is "the only intermediate source of truth," diagrams are projections of it, nodes and edges carry a grep-able `anchor`, titles prefer source identifiers, and "the LLM is an engine, not an evidence source." Veto checks run before a weighted rubric scores the output, and an eval compares facts to a gold IR with node and edge recall of at least 0.8 required to pass. Real extraction exists only for Java/Spring; synthesis is stubbed.

Lessons:
* **Adopted.** Veto-before-score. A structural veto (unevidenced element, dangling edge, store-to-store flow) must fail the run before any quality rubric is considered. Our lint has the same split between errors and warnings; the research confirms the ordering.
* **Adopted.** A clarity rubric with explicit scores so "clear" becomes measurable in CI, not only in the reviewer study.

---

## D. Commercial code graphs and runtime approaches

### Apiiro Software Graph and AI Threat Modeling

Apiiro's pitch is that "most threat models are built on static DFDs disconnected from the actual code, and as the system evolves, these diagrams drift." Its Software Graph is built by deep code analysis plus code-to-runtime context and covers repositories, modules, pipelines, APIs in code and at runtime, data models and secrets; the 2025 visualization maps data flows, cross-boundary movement and "ungoverned exit points" (their example: whether PII can reach a GenAI client). The 2026 "AI Threat Modeling" agent generates STRIDE models from specs and tickets against that graph and explains the code evidence behind each threat. All claims are vendor material.

Lessons:
* **Adopted.** The framing. A DFD that is not regenerated from code drifts; the product is the continuous model, and the diagram is a view. Our PR mode and stable IDs are the open equivalent.
* **Adopted.** "Exit points" as a first-class query: every flow to an external entity that carries `pii`, `financial`, `credential` or `secret`. Added to the STRIDE export's priority hints.

### Backslash App Graph and Endor Labs

Both build deterministic code graphs for reachability: Endor documents function-level call-graph reachability from application code to vulnerable library functions and marks results "potentially reachable" where call-graph support is missing for a language or package manager. Backslash markets a "digital twin" app graph connecting code elements and deployment posture.

Lessons:
* **Adopted.** Endor's honesty pattern: when analysis support is missing, say "potentially" and show which languages are covered. Our `gaps` list and recognizer coverage statements serve this purpose.

### AppMap

AppMap records execution traces (Java, Python, Ruby, JavaScript agents) and renders sequence diagrams and dependency maps; its GitHub Action (2023) compares runtime behavior before and after a PR and posts "sequence diffs" and API changes (new, deleted or modified routes, changed response attributes) as a PR comment.

Lessons:
* **Adopted.** The PR comment that shows a *behavioral diff* rather than a new picture is the best precedent for our design delta. Their route-change summary is the shape we want for entry-point changes.
* **Deferred.** Runtime evidence is powerful for confirming flows that static analysis cannot resolve (reflection, DI). Phase 4 keeps an OpenTelemetry/AppMap-style importer; AppMap's open `.appmap.json` spec is a candidate input.

### Program-analysis backends worth reusing

Joern builds a code property graph (AST, CFG, CDG, DDG) for several languages with user-defined sources and sinks and `reachableBy` queries. CodeQL and Semgrep ship curated sink and source libraries (database clients, HTTP clients, file I/O) per language. Sourcegraph's SCIP indexers give precise cross-file symbol resolution. code2flow (4.6k stars) and crabviz (1.4k) produce call graphs for dynamic languages with heuristics and LSP respectively.

Lessons:
* **Adopted.** Do not write sink/source libraries from scratch. Semgrep and CodeQL already encode "this call writes to Postgres" for every mainstream framework; a detector that runs a curated Semgrep rule pack and converts matches to facts covers most of our recognizer catalog at low cost. Added to Phase 2.
* **Adopted.** Keep Joern as the optional deep-analysis backend for intra-service payload tracking (what fields actually reach the outbound call), which is the one thing none of the diagram tools do.

---

## What this changes in the design

The following were applied to `design.md`, `schema/dfd-ir.schema.json` and the worked example in the same commit as this document.

| # | Change | Learned from |
|---|---|---|
| 1 | Evidence spans carry a `content_hash` of the referenced text; `verify` reports elements whose code changed even when the lines still resolve. | vibeX anchored claims, StrideGPT manifests |
| 2 | Flows gain `authentication` (none, credentials, session_id, token, client_certificate, two_factor, unknown) and `encryption` (tls, none, unknown); stores gain `encryption_at_rest` (yes, no, unknown). Unknowns are listed as questions in the report. | Threagile, pytm, FlowStrider |
| 3 | New `weaknesses` collection for negative findings a detector can prove (plaintext credentials, missing TLS, unauthenticated entry point, secret in env read at import). | Code2DFD extractors (`plaintext_credentials`, `ssl`, `http_security`) |
| 4 | OTM and Threagile YAML added as exports; OTM `code` representations carry our evidence. | OTM spec, StartLeft, IriusRisk |
| 5 | Semgrep/CodeQL rule packs as a fact source in Phase 2 instead of hand-writing every sink. Declarative YAML recognizers for teams. | Structurizr component finder, Joern/Semgrep/CodeQL |
| 6 | PR mode caches the base IR by commit; incremental re-analysis of changed files. | CodeBoarding incremental mode |
| 7 | Collapsed nodes are rendered as "expandable" with a count rather than hidden. | CodeBoarding |
| 8 | microSecEnD (17 Java microservice DFDs) is the Java benchmark; edge-level F1 is the headline metric; results reported with and without the LLM stage. | Code2DFD, LLMCFG-TGen, RECoRD |
| 9 | "Exit points" (flows to external entities carrying pii, financial, credential or secret) and LLM API clients get a dedicated priority hint and recognizer family. | Apiiro, pytm `LLM`/`Agent`, PHANTOM-B |
| 10 | Overrides carry `author` and optional `expires`; stale overrides surface in the report. | vibeX asserted claims |
| 11 | Rejected LLM proposals are kept in an `unverified` list in the report rather than discarded silently. | StrideGPT |
| 12 | Delivery adds an MCP server and a Claude Code skill wrapper around the CLI. | GitDiagram, archify, CodeBoarding adoption pattern |
| 13 | Open item recorded: a compliance mode that diffs a declared model (overrides or imported OTM) against the extracted one. | Peldszus/Tuma |

## What we deliberately do not copy

* **Tree-plus-README generation** (GitDiagram, Swark). It is fast and pretty, and it cannot tell a live data store from a dead import.
* **Risk scoring inside the extractor** (Threagile CIA ratings, StrideGPT DREAD). Risk is a human judgment on top of an accurate model; mixing the two makes the model less trustworthy.
* **Runtime-only evidence** (AppMap) as the primary source. It misses code paths that tests do not exercise, and needs instrumented environments. It stays an optional confirmer.
* **Threat state tracking in the IR.** Threat Dragon, FlowStrider, IriusRisk and Threat Composer all do this better; we export to them.

## Gaps nobody fills yet

1. **Cross-service flows in monorepos.** Code2DFD does it for Spring (Feign, Eureka, gateways); nothing does it generally. Service discovery config is the lever (compose service names, Kubernetes Services, env vars that name hosts).
2. **Payload-level accuracy.** No diagram tool says *which fields* reach an external service. Joern or CodeQL taint queries from a schema field to an outbound call site would make the PII hints precise instead of schema-wide. Phase 4.
3. **Determinism as a stated guarantee.** No tool we found promises byte-identical output across runs. It is cheap to promise and test, and it is what makes PR diffs reviewable.
4. **A PR-level design delta.** AppMap does it from runtime traces; Apiiro does it in a closed platform. An open, static, evidence-backed delta posted on the PR is the clearest gap and the most useful first deliverable.

## Sources

Academic
* Schneider, Scandariato. "Automatic extraction of security-rich dataflow diagrams for microservice applications written in Java." JSS 202 (2023). https://github.com/tuhh-softsec/code2DFD , https://arxiv.org/abs/2304.12769 (paper not fetched from this sandbox; figures from the abstract and README)
* Schneider, Özen, Chen, Scandariato. "microSecEnD: A dataset of security-enriched dataflow diagrams for microservice applications." MSR 2023. https://github.com/tuhh-softsec/microSecEnD
* Peldszus, Tuma, Strüber, Jürjens, Scandariato. "Secure data-flow compliance checks between models and code based on automated mappings." MODELS 2019; journal version "Checking security compliance between models and code," SoSyM 2023. https://arxiv.org/abs/2108.08579
* Gruner, Erthel, Brust. "FlowStrider: Low-friction continuous threat modeling." ASE 2025 tool track. https://pypi.org/project/flowstrider/
* Mbaka, Tuma. "Usefulness of data flow diagrams and large language models for security threat validation: a registered report." https://arxiv.org/abs/2408.07537
* LLMDFA (NeurIPS 2024) https://arxiv.org/abs/2402.10754 ; LLMCFG-TGen https://arxiv.org/abs/2512.06401 ; RECoRD (AAAI 2026, not fetched; from search summary)
* Shostack. PHANTOM-B whitepaper. https://shostack.org/files/papers/PHANTOM-B_Whitepaper_Shostack.pdf

Open source
* GitDiagram https://github.com/ahmedkhaleel2004/gitdiagram (18.7k stars) and its docs/architecture.md
* CodeBoarding https://github.com/CodeBoarding/CodeBoarding
* vibeX https://github.com/Raja0sama/vibex
* drawing-agent https://github.com/Destiny-63/drawing-agent
* Swark https://github.com/swark-io/swark ; archify https://github.com/tt-a1i/archify ; code2flow https://github.com/scottrogowski/code2flow ; crabviz https://github.com/chanhx/crabviz
* Threagile https://github.com/Threagile/threagile ; pytm https://github.com/OWASP/pytm ; Threat Dragon https://github.com/OWASP/threat-dragon ; Threat Composer https://github.com/awslabs/threat-composer
* Open Threat Model https://github.com/iriusrisk/OpenThreatModel ; StartLeft https://iriusrisk.github.io/startleft/ (not fetched from this sandbox)
* StrideGPT https://github.com/mrwadams/stride-gpt ; TaaC-AI https://github.com/yevh/TaaC-AI ; threatmap https://pypi.org/project/threatmap/
* Structurizr component finder https://docs.structurizr.com/java/component ; go-structurizr https://pkg.go.dev/github.com/krzysztofreczek/go-structurizr
* Joern https://joern.io ; AppMap https://github.com/getappmap/appmap and https://dev.to/appmap/announcing-appmap-for-github-runtime-code-reviews-for-every-pull-request-47km

Commercial (vendor material, not independently verified)
* Apiiro: https://apiiro.com/blog/software-graph-visualization , https://apiiro.com/blog/introducing-ai-threat-modeling/
* Backslash: https://backslash.security ; Endor Labs reachability docs: https://docs.api.endorlabs.com/introduction/reachability-analysis/
* IriusRisk IaC import: https://www.iriusrisk.com/documentation/import-from-a-diagramming-tool-or-iac ; ThreatModeler IaC-Assist: https://threatmodeler.com/iac-assist/
* DeepWiki: https://docs.devin.ai/work-with-devin/deepwiki
