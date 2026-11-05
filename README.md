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

## Prototype

`code2design/` is a working prototype of the pipeline (tree-sitter parsing; detectors for Express-style JavaScript/TypeScript, Flask/FastAPI/Django Python, gRPC, docker compose, Kubernetes, Dockerfiles, Prisma and package manifests; synthesis; lint; Mermaid, STRIDE, traceability-matrix and report renderers; IR diff). It is deterministic and evidence-backed by construction, and it is evaluated on 17 sample applications in [docs/evaluation.md](docs/evaluation.md).

```bash
pip install tree-sitter tree-sitter-javascript tree-sitter-typescript tree-sitter-python pyyaml jsonschema
python3 -m code2design analyze path/to/repo --out .code2design
python3 -m code2design diff base/model.ir.json head/model.ir.json
python3 scripts/evaluate.py evaluation/samples.json      # reruns the evaluation (expects the sample clones listed in samples.json)
```

Outputs: `model.ir.json`, `report.md` (coverage, attack surface, lint, gaps and questions), `stride-table.md`, `traceability-matrix.md`, `diagrams/*.mmd` (L0, L1, one L2 per L1 process, one sequence diagram per entry point), `facts.jsonl`, `lint.json`.

## Intended uses

* Understanding an unfamiliar service or a large PR quickly.
* Threat modeling: assets, threat agents, controls and trust boundaries are first-class, so the tool emits a STRIDE-per-element table and a control-path traceability matrix (see [docs/threat-modeling-alignment.md](docs/threat-modeling-alignment.md)), and exports to OTM, Threagile, OWASP Threat Dragon and pytm.
* Architecture drift detection: a PR comment that lists new external entities, new data stores, new boundary crossings, and removed controls.
