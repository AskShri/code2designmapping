# Standards the output follows

code2design does not invent formats where a standard exists. This table lists each standard, where
it appears, and what the tool does to conform.

| Standard | Used for | How code2design conforms |
|---|---|---|
| Data flow diagram notation (Yourdon/DeMarco and Gane-Sarson elements, Microsoft Threat Modeling Tool conventions) | Every diagram | Four element types only: external entity (rectangle), process (rounded), data store (cylinder), data flow (arrow); trust boundaries as dashed groups; a legend on every DFD. Lint rejects store-to-store and entity-to-entity flows. Leveled views: L0 context, L1 services or packages, L2 handlers and modules |
| STRIDE per element | `stride-table.md`, weakness `stride` field, OTM threat categories | Entities S R, processes S T R I D E, stores T R I D, flows T I D. Each weakness kind maps to its STRIDE categories in `model.WEAKNESSES` |
| CWE | Weakness `cwe`, SARIF rules, OTM `cwes` | Every weakness kind has one CWE: 798 hard-coded credentials, 295 certificate validation, 319 cleartext transmission, 942 permissive CORS, 352 CSRF, 284 public data store, 311 unencrypted storage, 489 debug code, 306 missing authentication |
| Open Threat Model (OTM) 0.2.0 | `model.otm.json`, `export --format otm` | Boundaries to `trustZones`, elements to `components` with one parent each, flows to `dataflows`, controls to `mitigations`, weaknesses to `threats` attached to the components they affect, evidence as `code` representations or attributes. Validated against the official `otm_schema.json` on every evaluation sample |
| SARIF 2.1.0 | `findings.sarif`, `export --format sarif` | One rule per weakness kind with CWE tag, help link and `security-severity`; one result per weakness with its file and line and the DFD elements it applies to. Uploadable to GitHub code scanning |
| JSON Schema 2020-12 | `schema/dfd-ir.schema.json` | The IR validates on every run in the evaluation; schema enumerations are tested to match the model's vocabularies |
| Threagile link attributes | Flow `authentication`, `encryption`; store `encryption_at_rest` | Same value sets, `unknown` when code cannot tell; every `unknown` on a boundary-crossing link becomes a question in the report |
| Mermaid | `diagrams/*.mmd` | Labels are sanitised (quotes, brackets, angle brackets, pipes, comment markers); every diagram is parsed and rendered in headless Chromium during evaluation |
| Black Duck threat modeling guidance | Report, STRIDE table, traceability matrix | Components, trust zones, assets, threat agents, controls, and a control-path traceability matrix; risk ratings and likelihood are left to the team. See `threat-modeling-alignment.md` |
