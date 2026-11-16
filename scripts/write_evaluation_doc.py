"""Write docs/evaluation.md from evaluation/results.json (run after scripts/evaluate.py)."""
import datetime, json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
r = [x for x in json.load(open(os.path.join(ROOT, "evaluation", "results.json"))) if not x.get("error")]
errors = [x for x in json.load(open(os.path.join(ROOT, "evaluation", "results.json"))) if x.get("error")]


def tot(k):
    return sum(x["counts"][k] for x in r)


def yn(b):
    return "yes" if b else "NO"


gt = [x for x in r if x.get("ground_truth")]
head = f"""# Evaluation on {len(r)} sample applications

**Date:** {datetime.date.today().isoformat()}
**Tool:** code2design 0.5.0 (IR 0.2)
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
| Ground truth | For {len(gt)} samples, hand-written lists of entry points, infrastructure endpoints, authenticated entry points, stores, external entities and route-to-target reachability edges (`evaluation/ground-truth/`), scored for precision and recall. |

The samples cover Express (JavaScript and TypeScript, Prisma, mongoose), NestJS with TypeORM, Flask with Flask-SQLAlchemy, FastAPI with SQLModel, Django, Spring MVC with Spring Data JPA, Gin with GORM, ASP.NET Core (MVC, Razor Pages, minimal APIs, EF Core), a polyglot Stripe sample, Google's Online Boutique microservices (Go, C#, Java, Python, Node, Kubernetes), and the docker/awesome-compose stacks.

## Results

Totals: {len(r)} samples, {tot('entry_points')} entry points, {tot('flows')} flows, {tot('entities')} external entities, {tot('stores')} data stores, {tot('weaknesses')} weaknesses, {sum(x['mermaid_files'] for x in r)} diagrams rendered with {sum(len(x['mermaid_failures']) for x in r)} failures, {sum(x['lint_errors'] for x in r)} lint errors, {sum(len(x['expect_misses']) for x in r)} expectation misses. Deterministic: {sum(1 for x in r if x['deterministic'])}/{len(r)}. Schema-valid: {sum(1 for x in r if x['schema_ok'])}/{len(r)}. OTM-valid: {sum(1 for x in r if x['otm_schema_ok'])}/{len(r)}. SARIF-valid: {sum(1 for x in r if x['sarif_ok'])}/{len(r)}.{(' Runs that failed: ' + ', '.join(e['name'] for e in errors) + '.') if errors else ''}

| Sample | Processes | Entities | Stores | Boundaries | Flows | Entry points | Controls | Weaknesses | Assets | Agents | Gaps | Deterministic | Schema | OTM | SARIF | Lint errors | Diagrams | Expectations | Time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
"""
rows = []
for x in r:
    c = x["counts"]
    exp = f"{len(x['expect_hits'])}/{len(x['expect_hits']) + len(x['expect_misses'])}" + ((" (miss: " + ", ".join(x["expect_misses"]) + ")") if x["expect_misses"] else "")
    rows.append(f"| [{x['name']}](../evaluation/{x['name']}/report.md) | {c['processes']} | {c['entities']} | {c['stores']} | {c['boundaries']} | {c['flows']} | {c['entry_points']} | {c['controls']} | {c['weaknesses']} | {c['assets']} | {c['threat_agents']} | {c['gaps']} | "
                f"{yn(x['deterministic'])} | {'ok' if x['schema_ok'] else 'FAIL'} | {'ok' if x['otm_schema_ok'] else ('n/a' if x['otm_schema_ok'] is None else 'FAIL')} | {'ok' if x['sarif_ok'] else 'FAIL'} | {x['lint_errors']} | "
                f"{x['mermaid_files']} ok / {len(x['mermaid_failures'])} fail | {exp} | {x['elapsed']} |")
body = "\n".join(rows)


def pr(g, k):
    v = g.get(k)
    if not v or (v["truth"] == 0 and v["predicted"] == 0):
        return "n/a"
    p = v["precision"] if v["precision"] is not None else "n/a"
    rc = v["recall"] if v["recall"] is not None else "n/a"
    return f"{p} / {rc} ({v['predicted']}/{v['truth']})"


gt_rows = ["", "## Precision and recall against ground truth", "",
           "P / R (predicted/true). Edges are reachability edges: the handler of an entry point reaches a store, an external entity or another service through its own call graph, which is the question a threat model asks (\"does this route reach the users table?\"). `authenticated` scores the entry points the tool credits with an unconditional authentication or authorization control.", "",
           "| Sample | Entry points | Infrastructure | Authenticated | Stores | Entities | Reachability edges | Remaining differences |", "|---|---|---|---|---|---|---|---|"]
for x in gt:
    g = x["ground_truth"]
    diffs = []
    for k, v in g.items():
        for m in v["missed"][:3]:
            diffs.append(f"missed {k}: {m}")
        for s_ in v["spurious"][:3]:
            diffs.append(f"extra {k}: {s_}")
    gt_rows.append(f"| {x['name']} | {pr(g, 'entry_points')} | {pr(g, 'infrastructure')} | {pr(g, 'authenticated')} | {pr(g, 'stores')} | {pr(g, 'entities')} | {pr(g, 'edges')} | {'; '.join(diffs) or '-'} |")
body += "\n" + "\n".join(gt_rows)

base_path = os.path.join(ROOT, "evaluation", "v0.4-baseline-scores.json")
if os.path.exists(base_path):
    base = json.load(open(base_path))

    def rec(g, k):
        v = (g or {}).get(k)
        if not v or not v["truth"]:
            return "n/a"
        return f"{v['recall']}"
    cmp_rows = ["", "### Before and after", "",
                "Recall per collection for the v0.4 code (commit `24d7ae3`, run from git on the same clones and scored by the same scorer; `evaluation/v0.4-baseline-scores.json`) against v0.5.", "",
                "| Sample | Entry points | Authenticated | Stores | Reachability edges |", "|---|---|---|---|---|"]
    now = {x["name"]: x["ground_truth"] for x in gt}
    for name in sorted(base, key=lambda n: list(now).index(n) if n in now else 99):
        if name not in now:
            continue
        cells = [f"{rec(base[name], k)} -> {rec(now[name], k)}" if rec(base[name], k) != rec(now[name], k) else rec(now[name], k) for k in ("entry_points", "authenticated", "stores", "edges")]
        cmp_rows.append(f"| {name} | " + " | ".join(cells) + " |")
    body += "\n" + "\n".join(cmp_rows)

notes = """

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
"""
open(os.path.join(ROOT, "docs", "evaluation.md"), "w").write(head + body + notes)
print("wrote docs/evaluation.md")
