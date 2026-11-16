# code2design

Turn a repository or a pull request into a design: data flow diagrams (DFDs),
per-entry-point control flows, and a threat-model-ready element inventory.

The transformation is built around three properties:

| Property    | How it is guaranteed                                                                 |
|-------------|--------------------------------------------------------------------------------------|
| Accurate    | Every element and flow carries code evidence (`file:line` plus a content hash that `verify` re-checks). Nothing is drawn without a fact behind it; inferred items carry confidence and a rationale and are drawn dashed. Measured against hand-written ground truth on 10 samples. |
| Consistent  | One fact vocabulary and one routing model for every framework, a single canonical IR with content-addressed IDs that ignore line numbers and checkout paths, and sorted iteration everywhere. Outputs are byte-identical across runs and Python hash seeds. |
| Clear       | Leveled diagrams (L0/L1/L2) with node and edge budgets, explicit trust boundaries, a fixed notation with a legend, unique sanitised labels, and controls drawn in execution order. |

Start with [docs/design.md](docs/design.md). [docs/research.md](docs/research.md) surveys existing tools and papers (Code2DFD, CodeBoarding, GitDiagram, Threagile, pytm, OTM, Apiiro, AppMap and others). The IR is specified in [schema/dfd-ir.schema.json](schema/dfd-ir.schema.json); [docs/facts.md](docs/facts.md) describes the fact vocabulary and routing model; [docs/standards.md](docs/standards.md) lists the standards the outputs follow (DFD notation, STRIDE, CWE, OTM 0.2.0, SARIF 2.1.0). [examples/orders-service](examples/orders-service) walks one small service from source to diagrams.

## Prototype (v0.5)

`code2design/` is a working implementation: tree-sitter parsing, a class-aware function-level call graph, and detectors for Express/Fastify, NestJS, Flask, FastAPI, Django, Go (net/http including Go 1.22 patterns, gin, gorilla, chi, gRPC), Spring MVC and Security, ASP.NET Core (controllers, minimal APIs, Razor Pages, gRPC), ORMs resolved to tables (SQLAlchemy, SQLModel, Django, mongoose, Prisma, TypeORM, Spring Data, GORM, EF Core), docker compose, Kubernetes, Dockerfiles and Terraform.

```bash
pip install -e ".[dev]"
code2design analyze path/to/repo --out .code2design          # reads path/to/repo/.code2design/overrides.yaml if present
code2design diff base/model.ir.json head/model.ir.json        # design delta for a pull request
code2design verify .code2design/model.ir.json --repo path/to/repo
code2design export .code2design/model.ir.json --format sarif  # or otm
python -m pytest                                              # 34 tests: frameworks, determinism, ID stability, standards, overrides
python scripts/evaluate.py evaluation/samples.json            # 23-sample evaluation (expects the clones listed there)
```

Outputs: `model.ir.json`, `model.otm.json`, `findings.sarif`, `report.md` (coverage, attack surface, weaknesses, lint, gaps and questions), `stride-table.md`, `traceability-matrix.md`, `diagrams/*.mmd` (L0, L1, one L2 per L1 process, one sequence diagram per entry point), `facts.jsonl`, `lint.json`.

Evaluation ([docs/evaluation.md](docs/evaluation.md)): 23 open-source applications in five languages. All runs are deterministic across hash seeds, schema-valid, OTM- and SARIF-valid, free of lint errors, and every diagram renders. On the 10 samples with ground truth, entry points, authentication, data stores and route-to-store reachability are at or near 1.0 precision and recall.

## Intended uses

* Understanding an unfamiliar service or a large PR quickly.
* Threat modeling: assets, threat agents, controls, weaknesses (with CWE and severity) and trust boundaries are first-class, so the tool emits a STRIDE-per-element table and a control-path traceability matrix (see [docs/threat-modeling-alignment.md](docs/threat-modeling-alignment.md)), and exports OTM for threat modeling tools and SARIF for code scanning.
* Architecture drift detection: a PR comment that lists new entry points, external entities, data stores and boundary crossings, and changed or removed controls, security-relevant changes first.
