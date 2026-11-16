# Evaluation on 23 sample applications

**Date:** 2026-11-16
**Tool:** code2design 0.5.2 (IR 0.2)
**Reproduce:** `python3 scripts/evaluate.py evaluation/samples.json && python3 scripts/write_evaluation_doc.py`
(the sample repositories are public GitHub repositories, shallow-cloned at the paths in `evaluation/samples.json`; each sample's `report.md` records the commit analyzed).

## What is checked

Each sample is analyzed twice, in separate processes with different `PYTHONHASHSEED` values, and:

| Check | Meaning |
|---|---|
| Deterministic | Every output file (IR, OTM, SARIF, diagrams, tables, report, lint) is byte-identical across the two processes. |
| Schema | `model.ir.json` validates against `schema/dfd-ir.schema.json` (JSON Schema 2020-12). |
| OTM | `model.otm.json` validates against the official Open Threat Model 0.2.0 schema. |
| SARIF | `findings.sarif` is SARIF 2.1.0 with a rule and a location for every result. |
| Lint errors | Structural rules: unevidenced elements, dangling references of any kind, store-to-store or entity-to-entity flows, level-order violations, inferred elements without confidence. |
| Diagrams | Every generated Mermaid diagram (L0, L1, one L2 per L1 process, one sequence diagram per entry point) parses and renders in headless Chromium. |
| Expectations | Named elements expected from reading each repository (entities, stores, controls, a minimum entry-point count). |
| Ground truth | For 10 samples, hand-written lists of entry points, infrastructure endpoints, authenticated entry points, stores, external entities and route-to-target reachability edges (`evaluation/ground-truth/`), scored for precision and recall. |

The samples cover Express (JavaScript and TypeScript, Prisma, mongoose), NestJS with TypeORM, Flask with Flask-SQLAlchemy, FastAPI with SQLModel, Django, Spring MVC with Spring Data JPA, Gin with GORM, ASP.NET Core (MVC, Razor Pages, minimal APIs, EF Core), a polyglot Stripe sample, Google's Online Boutique microservices (Go, C#, Java, Python, Node, Kubernetes), and the docker/awesome-compose stacks.

## Results

Totals: 23 samples, 370 entry points, 842 flows, 64 external entities, 56 data stores, 224 weaknesses, 411 diagrams rendered with 0 failures, 0 lint errors, 0 expectation misses. Deterministic: 23/23. Schema-valid: 23/23. OTM-valid: 23/23. SARIF-valid: 23/23.

| Sample | Processes | Entities | Stores | Boundaries | Flows | Entry points | Controls | Weaknesses | Assets | Agents | Gaps | Deterministic | Schema | OTM | SARIF | Lint errors | Diagrams | Expectations | Time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [orders-service-example](../evaluation/orders-service-example/report.md) | 9 | 2 | 2 | 3 | 11 | 2 | 3 | 0 | 3 | 5 | 5 | yes | ok | ok | ok | 0 | 6 ok / 0 fail | 6/6 | 0.13 |
| [node-express-boilerplate](../evaluation/node-express-boilerplate/report.md) | 32 | 2 | 2 | 2 | 49 | 15 | 11 | 9 | 2 | 4 | 6 | yes | ok | ok | ok | 0 | 21 ok / 0 fail | 6/6 | 0.3 |
| [node-express-realworld](../evaluation/node-express-realworld/report.md) | 31 | 1 | 4 | 1 | 48 | 20 | 4 | 9 | 3 | 3 | 6 | yes | ok | ok | ok | 0 | 24 ok / 0 fail | 3/3 | 0.21 |
| [node-express-mongodb](../evaluation/node-express-mongodb/report.md) | 14 | 1 | 1 | 1 | 14 | 8 | 1 | 8 | 0 | 2 | 3 | yes | ok | ok | ok | 0 | 12 ok / 0 fail | 2/2 | 0.15 |
| [hackathon-starter](../evaluation/hackathon-starter/report.md) | 107 | 27 | 3 | 1 | 213 | 90 | 12 | 63 | 23 | 4 | 21 | yes | ok | ok | ok | 0 | 46 ok / 0 fail | 10/10 | 1.1 |
| [stripe-checkout-sample](../evaluation/stripe-checkout-sample/report.md) | 26 | 3 | 0 | 1 | 21 | 23 | 0 | 24 | 2 | 3 | 6 | yes | ok | ok | ok | 0 | 30 ok / 0 fail | 2/2 | 0.2 |
| [microservices-demo](../evaluation/microservices-demo/report.md) | 52 | 8 | 2 | 14 | 59 | 33 | 0 | 19 | 2 | 17 | 11 | yes | ok | ok | ok | 0 | 46 ok / 0 fail | 2/2 | 1.11 |
| [compose-react-express-mongodb](../evaluation/compose-react-express-mongodb/report.md) | 5 | 1 | 1 | 4 | 3 | 2 | 1 | 1 | 0 | 3 | 2 | yes | ok | ok | ok | 0 | 5 ok / 0 fail | 2/2 | 0.13 |
| [compose-react-express-mysql](../evaluation/compose-react-express-mysql/report.md) | 6 | 2 | 1 | 4 | 4 | 2 | 1 | 3 | 1 | 4 | 4 | yes | ok | ok | ok | 0 | 5 ok / 0 fail | 2/2 | 0.13 |
| [compose-nginx-nodejs-redis](../evaluation/compose-nginx-nodejs-redis/report.md) | 4 | 1 | 1 | 2 | 3 | 1 | 0 | 1 | 0 | 2 | 2 | yes | ok | ok | ok | 0 | 4 ok / 0 fail | 2/2 | 0.11 |
| [compose-flask](../evaluation/compose-flask/report.md) | 3 | 1 | 0 | 2 | 1 | 1 | 0 | 1 | 0 | 2 | 1 | yes | ok | ok | ok | 0 | 4 ok / 0 fail | 1/1 | 0.13 |
| [compose-flask-redis](../evaluation/compose-flask-redis/report.md) | 3 | 1 | 1 | 1 | 3 | 1 | 0 | 2 | 0 | 2 | 2 | yes | ok | ok | ok | 0 | 4 ok / 0 fail | 2/2 | 0.1 |
| [compose-nginx-flask-mongo](../evaluation/compose-nginx-flask-mongo/report.md) | 4 | 1 | 1 | 3 | 2 | 1 | 0 | 1 | 0 | 2 | 2 | yes | ok | ok | ok | 0 | 4 ok / 0 fail | 2/2 | 0.12 |
| [compose-nginx-flask-mysql](../evaluation/compose-nginx-flask-mysql/report.md) | 4 | 1 | 1 | 3 | 3 | 1 | 0 | 2 | 0 | 2 | 2 | yes | ok | ok | ok | 0 | 4 ok / 0 fail | 2/2 | 0.14 |
| [compose-fastapi](../evaluation/compose-fastapi/report.md) | 3 | 1 | 0 | 1 | 1 | 1 | 0 | 1 | 0 | 2 | 1 | yes | ok | ok | ok | 0 | 4 ok / 0 fail | 1/1 | 0.14 |
| [compose-django](../evaluation/compose-django/report.md) | 3 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | yes | ok | ok | ok | 0 | 2 ok / 0 fail | 1/1 | 0.16 |
| [compose-nginx-wsgi-flask](../evaluation/compose-nginx-wsgi-flask/report.md) | 6 | 1 | 0 | 2 | 4 | 4 | 0 | 4 | 0 | 2 | 1 | yes | ok | ok | ok | 0 | 7 ok / 0 fail | 1/1 | 0.16 |
| [spring-petclinic](../evaluation/spring-petclinic/report.md) | 25 | 1 | 6 | 1 | 41 | 17 | 3 | 20 | 1 | 2 | 9 | yes | ok | ok | ok | 0 | 20 ok / 0 fail | 1/1 | 0.34 |
| [golang-gin-realworld](../evaluation/golang-gin-realworld/report.md) | 28 | 1 | 8 | 1 | 56 | 20 | 1 | 7 | 2 | 3 | 12 | yes | ok | ok | ok | 0 | 25 ok / 0 fail | 2/2 | 0.39 |
| [nestjs-realworld](../evaluation/nestjs-realworld/report.md) | 32 | 1 | 5 | 1 | 54 | 21 | 3 | 9 | 2 | 3 | 8 | yes | ok | ok | ok | 0 | 28 ok / 0 fail | 2/2 | 0.3 |
| [fastapi-full-stack](../evaluation/fastapi-full-stack/report.md) | 33 | 2 | 2 | 2 | 72 | 23 | 7 | 9 | 8 | 4 | 5 | yes | ok | ok | ok | 0 | 26 ok / 0 fail | 2/2 | 0.94 |
| [flask-microblog](../evaluation/flask-microblog/report.md) | 40 | 3 | 8 | 1 | 85 | 35 | 4 | 10 | 4 | 4 | 13 | yes | ok | ok | ok | 0 | 39 ok / 0 fail | 2/2 | 0.25 |
| [eshoponweb](../evaluation/eshoponweb/report.md) | 67 | 2 | 7 | 3 | 95 | 49 | 9 | 21 | 6 | 5 | 13 | yes | ok | ok | ok | 0 | 45 ok / 0 fail | 1/1 | 0.62 |

## Precision and recall against ground truth

P / R (predicted/true). Edges are reachability edges: the handler of an entry point reaches a store, an external entity or another service through its own call graph, which is the question a threat model asks ("does this route reach the users table?"). `authenticated` scores the entry points the tool credits with an unconditional authentication or authorization control.

| Sample | Entry points | Infrastructure | Authenticated | Stores | Entities | Reachability edges | Remaining differences |
|---|---|---|---|---|---|---|---|
| orders-service-example | 1.0 / 1.0 (2/2) | n/a | 1.0 / 1.0 (2/2) | 1.0 / 1.0 (2/2) | 1.0 / 1.0 (1/1) | 1.0 / 1.0 (5/5) | - |
| node-express-boilerplate | 1.0 / 1.0 (13/13) | 1.0 / 1.0 (2/2) | 1.0 / 1.0 (6/6) | 1.0 / 1.0 (2/2) | 1.0 / 1.0 (1/1) | 1.0 / 1.0 (21/21) | - |
| microservices-demo | 1.0 / 1.0 (21/21) | 1.0 / 1.0 (3/3) | n/a | 1.0 / 1.0 (2/2) | 0.8 / 1.0 (5/3) | 1.0 / 1.0 (35/35) | extra entities: Unresolved grpc target |
| compose-react-express-mongodb | 1.0 / 1.0 (2/2) | n/a | n/a | 1.0 / 1.0 (1/1) | n/a | 1.0 / 1.0 (2/2) | - |
| compose-flask-redis | 1.0 / 1.0 (1/1) | n/a | n/a | 1.0 / 1.0 (1/1) | n/a | 1.0 / 1.0 (1/1) | - |
| spring-petclinic | 1.0 / 1.0 (17/17) | n/a | n/a | 1.0 / 1.0 (6/6) | n/a | 1.0 / 1.0 (17/17) | - |
| golang-gin-realworld | 1.0 / 1.0 (19/19) | 1.0 / 1.0 (1/1) | 1.0 / 1.0 (12/12) | 1.0 / 1.0 (8/1) | n/a | 1.0 / 1.0 (38/18) | - |
| nestjs-realworld | 1.0 / 1.0 (21/21) | n/a | 1.0 / 1.0 (12/12) | 1.0 / 1.0 (5/5) | n/a | 1.0 / 1.0 (30/30) | - |
| fastapi-full-stack | 1.0 / 1.0 (22/22) | 1.0 / 1.0 (1/1) | 1.0 / 1.0 (17/17) | 1.0 / 1.0 (2/2) | 1.0 / 1.0 (1/1) | 1.0 / 1.0 (28/28) | - |
| flask-microblog | 1.0 / 1.0 (35/35) | n/a | 1.0 / 1.0 (25/25) | 0.88 / 1.0 (8/7) | 1.0 / 1.0 (2/2) | n/a | extra stores: postgres:* |

### Before and after

Recall per collection for the v0.4 code (commit `24d7ae3`, run from git on the same clones and scored by the same scorer; `evaluation/v0.4-baseline-scores.json`) against v0.5.

| Sample | Entry points | Authenticated | Stores | Reachability edges |
|---|---|---|---|---|
| orders-service-example | 1.0 | 1.0 | 1.0 | 1.0 |
| node-express-boilerplate | 1.0 | 1.0 | 1.0 | 1.0 |
| microservices-demo | 1.0 | n/a | 1.0 | 1.0 |
| compose-react-express-mongodb | 1.0 | n/a | 1.0 | 1.0 |
| compose-flask-redis | 1.0 | n/a | 1.0 | 1.0 |
| spring-petclinic | 0.94 -> 1.0 | n/a | 0.67 -> 1.0 | 0.0 -> 1.0 |
| golang-gin-realworld | 0.0 -> 1.0 | 0.0 -> 1.0 | 0.0 -> 1.0 | 0.0 -> 1.0 |
| nestjs-realworld | 0.0 -> 1.0 | 0.0 -> 1.0 | 0.0 -> 1.0 | 0.0 -> 1.0 |
| fastapi-full-stack | 0.0 -> 1.0 | 0.0 -> 1.0 | 0.0 -> 1.0 | 0.0 -> 1.0 |
| flask-microblog | 0.29 -> 1.0 | 0.4 -> 1.0 | 0.86 -> 1.0 | n/a |

Per-sample outputs are committed under `evaluation/<sample>/` (model, OTM, SARIF, report, STRIDE table, traceability matrix, L0/L1/L2 diagrams and the first five sequence diagrams by priority).

### The remaining differences

* **microservices-demo, extra entity "Unresolved grpc target".** The product catalog service dials its tracing collector through a helper that receives the address as a parameter (`mustConnGRPC(ctx, &conn, addr)`), and the Java ad service ships a standalone client. Both are real outbound connections whose target is not knowable from the call site, so the tool reports them as unresolved targets with a gap rather than guessing. The ground truth lists only the application's own services.
* **flask-microblog, extra store "Postgres (table unresolved)".** `PaginatedAPIMixin.to_collection_dict` runs `db.paginate(query)` on a query passed in by its callers. The access is real; its table depends on the caller, which the tool does not trace across call boundaries. It is shown as a separate store with a gap.

## What changed in v0.5, and why

The six samples added in this round (Spring PetClinic, Gin RealWorld, NestJS RealWorld, the FastAPI full-stack template, Flask Microblog, eShopOnWeb) and an independent review of v0.4 (40 findings, `review-findings.md`) showed that framework-specific patches were not converging. v0.5 restructured the pipeline instead:

| Area | Before | v0.5 |
|---|---|---|
| Detector output | Ad hoc dictionaries per detector | 19 registered fact kinds with required fields, validated on every `add` (`facts.md`) |
| Routes and controls | Per-framework prefix and control logic in synthesis | One routing model: routers, mounts, global prefixes; controls scoped to route, router (ordered, path-scoped), service (with Nest `forRoutes` selection) or handler |
| Call graph | Name-based, JavaScript and Python | Class-aware for six languages: typed fields, DI constructors, generics, interface implementations, re-exports, Go import paths, extra edges for `Depends` and `@ModelAttribute` |
| Stores | Driver-level (`Postgres`) | Table-level through ORMs: SQLAlchemy, SQLModel, Django, mongoose, Prisma, TypeORM, Spring Data, GORM, EF Core; engine from code, configuration or manifest drivers; `candidate_engines` when a profile selects it |
| Handlers | One process per entry point | One process per handler function, so multi-method routes share it and cannot leak reach into each other |
| Weaknesses | Kind and name | Kind, CWE, severity and STRIDE; identity without line numbers; exported as OTM threats and SARIF results |
| Traceability matrix | Shortest path, any control counted | Path with the fewest blocking controls; authentication-only paths flagged for authorization review; conditional controls not counted |
| Determinism check | Same process twice | Separate processes with different hash seeds; elapsed time removed from the report; model name independent of the checkout directory |

The "Before and after" table above shows the effect: the samples v0.4 already handled keep their scores (microservices-demo edge precision rises from 0.95 to 1.0), and the five new ground-truth samples, on which v0.4 found few or none of the routes, now score 1.0 recall on entry points, authentication, stores and edges.

## Known limitations

* **Per-call-site table resolution.** A query built in one function and executed in another (a pagination helper, a repository base class with a generic `T`) is attributed to an unresolved table.
* **Same-named tables in different services merge.** Store identity is technology plus table name. Services that share a database are modelled correctly; separate databases that both have a `users` table become one store.
* **gRPC service scope.** A gRPC service implemented by a class is scoped to that class; one registered from a Go package starts from that package's receiver methods; Node and Python servers are scoped to the registering file.
* **Conditional middleware** is shown and flagged but its condition is not evaluated; it does not count as blocking in the matrix.
* **Unanalyzed languages.** Ruby, PHP, Kotlin and Rust files are listed as gaps.
* **Ground truth is small and single-author.** Ten samples, written by reading the code; the microservices edges cover the services whose code is analyzable.
