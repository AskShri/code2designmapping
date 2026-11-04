# code2design

Turn a repository or a pull request into a design: data flow diagrams (DFDs),
per-entry-point control flows, and a threat-model-ready element inventory.

The transformation is built around three properties:

| Property    | How it is guaranteed                                                                 |
|-------------|--------------------------------------------------------------------------------------|
| Accurate    | Every element and flow carries code evidence (`file:line`). Nothing is drawn without a fact behind it, and inferred items are visibly marked. |
| Consistent  | A single canonical intermediate representation (IR) with content-addressed stable IDs, a deterministic pipeline, and determinism tests. Same input, same bytes out. |
| Clear       | Leveled diagrams (L0/L1/L2) with hard node budgets, explicit trust boundaries, a fixed notation, and controlled naming. |

Start with [docs/design.md](docs/design.md). [docs/research.md](docs/research.md) surveys the existing tools and papers (Code2DFD, CodeBoarding, GitDiagram, Threagile, pytm, OTM, Apiiro, AppMap and others) and lists what the design borrowed from each. The IR is specified in
[schema/dfd-ir.schema.json](schema/dfd-ir.schema.json), and
[examples/orders-service](examples/orders-service) walks one small service
from source to IR to rendered diagram.

## Intended uses

* Understanding an unfamiliar service or a large PR quickly.
* Threat modeling: assets, threat agents, controls and trust boundaries are first-class, so the tool emits a STRIDE-per-element table and a control-path traceability matrix (see [docs/threat-modeling-alignment.md](docs/threat-modeling-alignment.md)), and exports to OTM, Threagile, OWASP Threat Dragon and pytm.
* Architecture drift detection: a PR comment that lists new external entities, new data stores, new boundary crossings, and removed controls.
