# code2design

Turn a repository or a pull request into a design: data flow diagrams (DFDs),
per-entry-point control flows, and a threat-model-ready element inventory.

The transformation is built around three properties:

| Property    | How it is guaranteed                                                                 |
|-------------|--------------------------------------------------------------------------------------|
| Accurate    | Every element and flow carries code evidence (`file:line`). Nothing is drawn without a fact behind it, and inferred items are visibly marked. |
| Consistent  | A single canonical intermediate representation (IR) with content-addressed stable IDs, a deterministic pipeline, and determinism tests. Same input, same bytes out. |
| Clear       | Leveled diagrams (L0/L1/L2) with hard node budgets, explicit trust boundaries, a fixed notation, and controlled naming. |

Start with [docs/design.md](docs/design.md). The IR is specified in
[schema/dfd-ir.schema.json](schema/dfd-ir.schema.json), and
[examples/orders-service](examples/orders-service) walks one small service
from source to IR to rendered diagram.

## Intended uses

* Understanding an unfamiliar service or a large PR quickly.
* Threat modeling: export to OWASP Threat Dragon, pytm, or a STRIDE-per-element table.
* Architecture drift detection: a PR comment that lists new external entities, new data stores, new boundary crossings, and removed controls.
