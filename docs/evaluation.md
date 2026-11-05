# Evaluation of the prototype on 17 sample applications

**Date:** 2026-11-05
**Tool:** `code2design/` prototype (see `design.md` section 3.4 for what it implements)
**Reproduce:** `python3 scripts/evaluate.py evaluation/samples.json && python3 scripts/write_evaluation_doc.py`
(the sample repositories are expected at the paths in `evaluation/samples.json`; all are public GitHub repositories, shallow-cloned at the commits recorded in each sample's `report.md`).

## What was tested

Each sample is analyzed twice from scratch and the following is checked:

| Check | Meaning |
|---|---|
| Deterministic | Every output file is byte-identical across the two runs (the report's commit line excluded). |
| Schema | `model.ir.json` validates against `schema/dfd-ir.schema.json`. |
| Lint errors | Structural rules that veto the run: unevidenced elements, dangling flows, store-to-store or entity-to-entity flows, inferred elements without confidence, broken references. |
| Mermaid | Every generated diagram (L0, L1, one L2 per L1 process, one sequence diagram per entry point) parses and renders in headless Chromium. |
| Expectations | Hand-written expectations per sample (from reading each repository's dependencies and routes): named external entities, stores, controls, and a minimum entry-point count. |

The samples span single-service Express apps (JavaScript and TypeScript), a large Express app with 100+ routes and ~30 external APIs, Flask/FastAPI/Django apps from docker/awesome-compose, a polyglot Stripe sample, and Google's Online Boutique microservices (Go, C#, Java, Python, Node with Kubernetes manifests).

## Results

Totals: 17 samples, 180 entry points, 410 flows, 56 external entities, 23 data stores, 187 diagrams rendered, 0 render failures, 0 lint errors, 0 expectation misses, all runs deterministic: yes.

| Sample | Processes | Entities | Stores | Boundaries | Flows | Entry points | Controls | Weaknesses | Assets | Agents | Gaps | Deterministic | Schema | Lint errors | Diagrams | Expectations | Time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [orders-service-example](../evaluation/orders-service-example/report.md) | 9 | 2 | 2 | 3 | 10 | 2 | 2 | 1 | 3 | 4 | 3 | yes | ok | 0 | 6 ok / 0 fail | 6/6 | 0.05 |
| [node-express-boilerplate](../evaluation/node-express-boilerplate/report.md) | 32 | 2 | 3 | 2 | 27 | 15 | 11 | 10 | 0 | 4 | 5 | yes | ok | 0 | 21 ok / 0 fail | 6/6 | 0.1 |
| [node-express-realworld](../evaluation/node-express-realworld/report.md) | 31 | 1 | 4 | 1 | 48 | 20 | 7 | 6 | 1 | 3 | 6 | yes | ok | 0 | 24 ok / 0 fail | 3/3 | 0.07 |
| [node-express-mongodb](../evaluation/node-express-mongodb/report.md) | 14 | 1 | 2 | 1 | 18 | 8 | 1 | 8 | 0 | 2 | 11 | yes | ok | 0 | 12 ok / 0 fail | 2/2 | 0.02 |
| [hackathon-starter](../evaluation/hackathon-starter/report.md) | 118 | 28 | 2 | 1 | 240 | 101 | 12 | 88 | 21 | 30 | 23 | yes | ok | 0 | 45 ok / 0 fail | 10/10 | 0.46 |
| [stripe-checkout-sample](../evaluation/stripe-checkout-sample/report.md) | 22 | 3 | 0 | 1 | 23 | 10 | 0 | 13 | 2 | 4 | 8 | yes | ok | 0 | 16 ok / 0 fail | 2/2 | 0.04 |
| [microservices-demo](../evaluation/microservices-demo/report.md) | 21 | 7 | 1 | 7 | 15 | 9 | 0 | 4 | 0 | 14 | 10 | yes | ok | 0 | 16 ok / 0 fail | 2/2 | 0.28 |
| [compose-react-express-mongodb](../evaluation/compose-react-express-mongodb/report.md) | 8 | 2 | 2 | 4 | 6 | 2 | 1 | 3 | 0 | 4 | 7 | yes | ok | 0 | 6 ok / 0 fail | 2/2 | 0.03 |
| [compose-react-express-mysql](../evaluation/compose-react-express-mysql/report.md) | 7 | 2 | 1 | 4 | 4 | 2 | 1 | 6 | 1 | 4 | 5 | yes | ok | 0 | 6 ok / 0 fail | 2/2 | 0.02 |
| [compose-nginx-nodejs-redis](../evaluation/compose-nginx-nodejs-redis/report.md) | 4 | 1 | 1 | 4 | 3 | 1 | 0 | 1 | 0 | 3 | 2 | yes | ok | 0 | 4 ok / 0 fail | 2/2 | 0.01 |
| [compose-flask](../evaluation/compose-flask/report.md) | 3 | 1 | 0 | 2 | 1 | 1 | 0 | 1 | 0 | 2 | 1 | yes | ok | 0 | 4 ok / 0 fail | 1/1 | 0.01 |
| [compose-flask-redis](../evaluation/compose-flask-redis/report.md) | 4 | 1 | 1 | 2 | 3 | 1 | 0 | 1 | 0 | 2 | 2 | yes | ok | 0 | 4 ok / 0 fail | 2/2 | 0.01 |
| [compose-nginx-flask-mongo](../evaluation/compose-nginx-flask-mongo/report.md) | 3 | 1 | 1 | 3 | 1 | 1 | 0 | 1 | 0 | 2 | 2 | yes | ok | 0 | 4 ok / 0 fail | 2/2 | 0.01 |
| [compose-nginx-flask-mysql](../evaluation/compose-nginx-flask-mysql/report.md) | 4 | 1 | 3 | 3 | 5 | 1 | 0 | 2 | 0 | 2 | 4 | yes | ok | 0 | 4 ok / 0 fail | 2/2 | 0.01 |
| [compose-fastapi](../evaluation/compose-fastapi/report.md) | 3 | 1 | 0 | 1 | 1 | 1 | 0 | 1 | 0 | 2 | 1 | yes | ok | 0 | 4 ok / 0 fail | 1/1 | 0.01 |
| [compose-django](../evaluation/compose-django/report.md) | 4 | 1 | 0 | 2 | 1 | 1 | 0 | 2 | 1 | 2 | 1 | yes | ok | 0 | 4 ok / 0 fail | 1/1 | 0.01 |
| [compose-nginx-wsgi-flask](../evaluation/compose-nginx-wsgi-flask/report.md) | 6 | 1 | 0 | 2 | 4 | 4 | 0 | 4 | 0 | 2 | 1 | yes | ok | 0 | 7 ok / 0 fail | 1/1 | 0.01 |

Per-sample outputs are committed under `evaluation/<sample>/` (model, report, STRIDE table, traceability matrix, L0/L1/L2 diagrams and the first five sequence diagrams).

## What the outputs look like on real code

* **node-express-boilerplate.** Fifteen entry points (auth, users, docs and the CORS preflight `OPTIONS *`) with their full `/v1/...` paths, resolved through the boilerplate's `{ path, route }` mount table. Every route carries the app-level controls in registration order (helmet, xss-clean, mongo-sanitize, cors) plus the route-level ones (`validate`, `auth`, and `authLimiter` on `/v1/auth/*` only). `passport.initialize` is deliberately not counted as an authn control, so the attack-surface section reports which routes lack the route-level `auth` guard. Stores: `MongoDB: User`, `MongoDB: Token` from the mongoose models. External: SMTP relay via nodemailer.
* **node-express-realworld (TypeScript, Prisma).** Twenty routes under `/api` resolved through chained anonymous routers (`Router().use(a).use(b)` mounted at `/api`), `auth.required` and `auth.optional` as route-level controls, four Postgres stores from the Prisma schema (User, Article, Comment, Tag) merged with the `prisma.<model>` client calls.
* **hackathon-starter.** 101 routes on a root `app.js`, 28 external entities (OAuth identity providers, SMTP, Stripe, Twilio, GitHub, Last.fm, Google APIs, LLM APIs via LangChain), lusca CSRF, per-route rate limiters (`loginLimiter`, `strictLimiter`), 18 weaknesses (mostly client secrets read at import in `config/passport.js`). The L1 view collapses the 9 lowest-degree externals under the 25-node budget; the handler-to-controller flows went from 750 (every handler to every controller) to 236 once controller references were resolved to their file.
* **microservices-demo (Online Boutique).** The Kubernetes manifests give one trust boundary per service and the service hosts. The Python recommendation service's gRPC client address, held in a variable read from `PRODUCT_CATALOG_SERVICE_ADDR`, resolves through the manifest's env to `productcatalogservice`, which appears as a named service entity because its Go source is not analyzable. Redis for the cart service comes from the manifests. The shopping-assistant service's Gemini and AlloyDB clients are recognized. Go, C# and Java files (40) are listed as unanalyzed, so the matrix has no rows: no schemas, no assets.
* **compose samples.** Each compose service becomes a boundary; databases declared in compose appear as stores even when the client code is not recognized, with a gap saying no code access was detected. Plaintext credentials in compose `environment` blocks become weaknesses.
* **Design delta across 60 commits of node-express-boilerplate** (`evaluation/node-express-boilerplate/design-delta.md`): two new entry points (`POST /v1/auth/send-verification-email`, `POST /v1/auth/verify-email`), a new route-level `auth` control, their inbound flows, and the boundary and threat-agent membership changes. No removals. This is the PR-comment shape from the design, produced by diffing two IRs by stable ID.

## Issues found by the larger sample, and what was done

| # | Issue | Found in | Fix |
|---|---|---|---|
| 1 | Database clients aliased across files (`const Tutorial = db.tutorials`, `const pool = new Pool()`, `cur = conn.cursor()`, `self.cursor`) were not tied to their store | node-express-mongodb, flask samples | Alias pass run twice, cross-file resolution of imported locals to the store package in the target file, attribute-aware Python aliases |
| 2 | Any imported identifier in `app.use('/prefix', x)` was treated as a router mount, so `authLimiter` became a mount and `authRoutes` could become a control | node-express-boilerplate, realworld | Mount only when the target file looks like a router; router-likeness takes precedence over control-name matching |
| 3 | Dynamic mount tables (`defaultRoutes.forEach(r => router.use(r.path, r.route))`) hid the `/v1` prefixes | node-express-boilerplate | Recognize `{ path, route }` object literals as mounts |
| 4 | Chained anonymous routers (`export default Router().use('/api', api)`) were not followed | realworld | Chained-call callee parsing and composition of same-file router chains |
| 5 | Handlers given as controller references (`app.get('/x', userController.getLogin)`) produced a flow from every handler to every imported module | hackathon-starter (750 flows) | Resolve the reference's module and link only to it (236 flows) |
| 6 | Databases declared in compose/Kubernetes with no recognized client code were invisible | compose and k8s samples | Declared stores are emitted with a gap, and merged with code-level stores of the same technology |
| 7 | ORM clients with no technology (knex, Prisma client) duplicated the schema's store | react-express-mysql, realworld | Unknown technology adopts the single declared database; logical names are normalized (case, plural) |
| 8 | gRPC client addresses held in variables or env vars were unresolved; IPv6 loopback `[::]:8080` became a host named "[" | microservices-demo | Variables traced to env reads, env names resolved through Kubernetes manifests, loopback targets dropped |
| 9 | Multi-line inline middleware and config objects became control names and broke 60 sequence diagrams | hackathon-starter, realworld | Inline functions are never controls; names are single-line; sequence-diagram text is sanitized |
| 10 | The "unknown TLS" question repeated on every inbound route | all Express samples | One question per listener |
| 11 | The Mermaid render check silently reported 0 files when the mermaid module was missing | harness | Pinned `mermaid` dev dependency in `package.json` |
| 12 | `passport.initialize`, `express-session` and body parsers were credited as authentication | node-express-boilerplate, hackathon-starter | Plumbing names are excluded from control classification |

## Known limitations observed

* **Control attribution is path-based, not flow-sensitive.** App-level middleware is attached to every route it precedes (by path prefix when one is given). Session and parser plumbing (`passport.initialize`, `express-session`, body parsers) is excluded from controls, so authn is only credited to explicit guards (`auth(...)`, `isAuthenticated`, `passport.authenticate`, `jwt_required`, `Depends(get_current_user)`). Conditional registration (`if (env === 'production') app.use(...)`) is counted unconditionally.
* **File-level attribution of flows.** Store and outbound calls inside non-handler modules are attributed to the module, and request data classes are propagated along import edges (depth 3). This over-approximates which handler touches which store; the payload is labelled "request fields (propagated)" so the reader can tell.
* **Unsupported languages are visible but absent.** Go, Java, C#, Ruby and PHP services appear only as boundaries (from manifests) or named entities (from other services' clients). The report and gaps say so.
* **No schemas means no assets.** Where no validation schema, ORM model, SQL column list or secret is found, the asset list is empty and the matrix has no rows. Overrides are the intended way to declare assets in that case; the overrides file is not yet implemented in the prototype.
* **Entry-point noise.** `app.options('*', cors())` and health-check gRPC services are reported as entry points. They are real listeners, but a future "infrastructure" tag would keep them out of the L1 view.
* **Hosts are hostnames.** Outbound calls to URLs built from variables are reported as "Unresolved HTTP target" with a gap; relative URLs in frontend code are skipped.

## How this relates to the design's targets

The design's evaluation plan (section 10) asks for precision and recall against hand-made ground truth and a determinism rate. This run establishes determinism (17/17), schema validity (17/17), structural soundness (0 lint errors), rendering (all diagrams), and named-element recall against the expectations above (all hit after the fixes). It does not yet measure precision or edge-level recall against full ground-truth IRs; building those (starting from microSecEnD for Java once a Java recognizer exists, and from hand-made IRs for three of the samples here) is the next step.
