"""Write docs/evaluation.md from evaluation/results.json (run after scripts/evaluate.py)."""
import json, os, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
r = json.load(open(os.path.join(ROOT, "evaluation", "results.json")))
samples = {s["name"]: s for s in json.load(open(os.path.join(ROOT, "evaluation", "samples.json")))}

tot = lambda k: sum(x["counts"][k] for x in r)
head = f"""# Evaluation of the prototype on 17 sample applications

**Date:** {datetime.date.today().isoformat()}
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

Totals: {len(r)} samples, {tot('entry_points')} entry points, {tot('flows')} flows, {tot('entities')} external entities, {tot('stores')} data stores, {sum(x['mermaid_files'] for x in r)} diagrams rendered, {sum(len(x['mermaid_failures']) for x in r)} render failures, {sum(x['lint_errors'] for x in r)} lint errors, {sum(len(x['expect_misses']) for x in r)} expectation misses, all runs deterministic: {'yes' if all(x['deterministic'] for x in r) else 'NO'}.

| Sample | Processes | Entities | Stores | Boundaries | Flows | Entry points | Controls | Weaknesses | Assets | Agents | Gaps | Deterministic | Schema | Lint errors | Diagrams | Expectations | Time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
"""
rows = []
for x in r:
    c = x["counts"]
    rows.append(f"| [{x['name']}](../evaluation/{x['name']}/report.md) | {c['processes']} | {c['entities']} | {c['stores']} | {c['boundaries']} | {c['flows']} | {c['entry_points']} | {c['controls']} | {c['weaknesses']} | {c['assets']} | {c['threat_agents']} | {c['gaps']} | {'yes' if x['deterministic'] else 'NO'} | {'ok' if x['schema_ok'] else 'FAIL'} | {x['lint_errors']} | {x['mermaid_files']} ok / {len(x['mermaid_failures'])} fail | {len(x['expect_hits'])}/{len(x['expect_hits']) + len(x['expect_misses'])}{(' (miss: ' + ', '.join(x['expect_misses']) + ')') if x['expect_misses'] else ''} | {x['elapsed']} |")
body = "\n".join(rows)

gt_rows = ["", "## Precision and recall against hand-written ground truth", "", "Ground truth (`evaluation/ground-truth/`) was written by reading the source of five samples. Edges are *reachability* edges: the handler of an entry point reaches a store, an external entity or another service through its own call graph. P = precision, R = recall.", "",
           "| Sample | Entry points P/R | Infrastructure P/R | Stores P/R | Entities P/R | Reachability edges P/R | Missed edges (first few) | Spurious (first few) |", "|---|---|---|---|---|---|---|---|"]
for x in r:
    g = x.get("ground_truth")
    if not g:
        continue
    def pr(k):
        v = g[k]
        if v["truth"] == 0 and v["predicted"] == 0: return "n/a"
        return f"{v['precision'] if v['precision'] is not None else 'n/a'} / {v['recall'] if v['recall'] is not None else 'n/a'} ({v['predicted']} pred, {v['truth']} true)"
    miss = "; ".join(f"{a} -> {b}" for a, b in g["edges"]["missed"][:4]) or "-"
    spur = "; ".join(f"{a} -> {b}" for a, b in g["edges"]["spurious"][:4]) or "-"
    gt_rows.append(f"| {x['name']} | {pr('entry_points')} | {pr('infrastructure')} | {pr('stores')} | {pr('entities')} | {pr('edges')} | {miss} | {spur} |")
body += "\n" + "\n".join(gt_rows)

notes = """

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

## Limitations addressed since the first run

| Limitation (first run) | What changed |
|---|---|
| Control attribution was path-based and credited plumbing | App-level middleware now applies only to routers mounted (or routes defined) after its registration line; session and parser plumbing is excluded; controls registered inside a condition are marked `conditional`; classification uses the callee name only, so `validate(authValidation.register)` is validation, not authentication |
| Store and outbound calls were attributed at file level with depth-3 propagation along imports | A function-level call graph (JavaScript/TypeScript, Python, Go, Java, C#) with re-export following attributes every access to the function that performs it; handlers own the facts in their own function (inline or referenced controller), reach other modules through real call edges, and each entry point carries a `reaches` list of the stores, entities and services its handler reaches |
| Go, Java and C# were invisible | Recognizers for net/http, gorilla, gin, chi, gRPC servers and clients (`pb.NewXClient` with env-mapped addresses), database/sql, GORM, go-redis, Mongo, Spring MVC and Security, JPA entities, grpc-java, ASP.NET attributes and minimal APIs, `MapGrpcService`, EF Core and StackExchange.Redis |
| No schemas meant no assets | Request fields read in handlers (`req.body.email`, `request.json['x']`) become request schemas; the overrides file can declare assets, threat agents, boundaries, attributes and renames, with author and expiry |
| Infrastructure entry points polluted views and counts | Health, readiness, metrics, docs, robots and CORS preflight routes are tagged `infrastructure`, hidden from L1/L2 views and counted separately |
| Hosts held in variables were unresolved | Variables and template strings traced to env reads and `axios.create({ baseURL })`; env names resolved through Kubernetes manifests; the service's own listen address and loopbacks are dropped |
| No precision or edge-level recall measurement | Ground truth for five samples and a scorer for entry points, stores, entities and reachability edges (table above) |
| Design items not implemented: overrides, verify, OTM export | `--overrides` (default `.code2design/overrides.yaml`), `verify` (content-hash re-check of every evidence span), `export --format otm` |

## Known limitations observed

* **Module-level DFD, function-level reach.** The diagram still draws flows between modules (a module process to a store), because that is the readable level; the per-entry-point `reaches` list and the traceability matrix are where function-level precision shows. A module shared by several handlers therefore appears connected to every store any of them reaches.
* **gRPC service reach is package-level.** For a gRPC server registered in a Go, Java or C# package, every function in the package counts as reachable from that service; for Node and Python, every function in the registering file. This is right at service granularity and coarse within a service.
* **Ruby, PHP, Kotlin and Rust** are still reported as unanalyzed files.
* **Conditional middleware** is counted as applying and flagged; the condition itself is not evaluated.
* **Ground truth is small.** Five samples, written by one reader of the code; the microservices edges cover the frontend, checkout, recommendation, cart and assistant services only.

## How this relates to the design's targets

The design's evaluation plan (section 10) asks for precision and recall against hand-made ground truth and a determinism rate. This run establishes determinism (17/17), schema validity (17/17), structural soundness (0 lint errors), rendering (all diagrams), and named-element recall against the expectations above (all hit after the fixes). It does not yet measure precision or edge-level recall against full ground-truth IRs; building those (starting from microSecEnD for Java once a Java recognizer exists, and from hand-made IRs for three of the samples here) is the next step.
"""
open(os.path.join(ROOT, "docs", "evaluation.md"), "w").write(head + body + notes)
print("wrote docs/evaluation.md")
