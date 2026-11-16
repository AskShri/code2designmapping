# Review findings and their resolution (v0.5)

An independent review of the v0.4 prototype (commit `24d7ae3`) ran the tool against the 23 sample repositories and small purpose-built fixtures, under three `PYTHONHASHSEED` values. It reported 40 findings, most confirmed by a reproducing input. This file records each one and what v0.5 did about it. "Test" names the regression test or evaluation check that now covers it.

Status values: **fixed** (the defect is gone and covered), **redesigned** (the code that had the defect was replaced by a different mechanism), **documented** (a limitation kept on purpose and stated in the docs).

| # | Finding | Status | What changed | Test |
|---|---|---|---|---|
| 1 | Crash on a lower-case env var in a template URL | fixed | Env-host extraction is one guarded helper (`_env_host`) that never dereferences a failed match; it also stops treating API keys in query strings as hosts | evaluation (hackathon-starter) |
| 2 | Router-scope controls applied to every route in the file | redesigned | One routing model (`routing.py`): controls are attached to router objects, with registration order and optional path prefix | `test_nest_global_prefix_and_for_routes_middleware`, ground truth `authenticated` |
| 3 | Routers with an unresolved mount inherited app controls from every app file | redesigned | Controls flow only along resolved mount chains; an unmounted router gets no inherited controls and a gap says so | ground truth `authenticated` |
| 4 | Model schemas never reached store data classes | fixed | `_data_classes` maps ORM model schemas (SQLAlchemy, SQLModel, TypeORM, JPA, mongoose, EF) onto the stores of the same table | `test_flask_blueprint_prefix_methods_and_auth` |
| 5 | Schema ID collision | fixed | Request schemas are identified per enclosing function (`request fields (fn)`); named schemas by file and name | schema validation, determinism |
| 6 | Every validation schema in a file attached to every route | fixed | A validation schema is attached only when the route registration or the handler body names it (directly, by import, or as `module.member`) | ground truth on node-express-boilerplate |
| 7 | Byte offsets used to slice a `str` | redesigned | All spans are line based (`handler_span=(start_line, end_line)`), resolved through the call graph | `verify` re-checks every span on the example in CI |
| 8 | Matrix verdict depended on hash-ID order | fixed | The matrix computes the path with the fewest blocking controls (Dijkstra, ties by length and ID), counts only authn/authz as blocking, lists other controls separately, and ignores conditional registrations | determinism across hash seeds |
| 9 | Nondeterminism from iterating the `app_files` set | redesigned | Every collection in synthesis is iterated sorted; output is byte-identical across seeds | `test_byte_identical_across_hash_seeds`, evaluation (3 processes per sample) |
| 10 | Nondeterminism from iterating `cg.calls` sets | fixed | Call-graph neighbours are iterated sorted in `reach` and in synthesis | as above |
| 11 | `suppress` left dangling references; render crashed | fixed | Suppression removes the element and every reference (flows, entry-point controls and reaches, boundary members, assets, agents, weakness targets, children); lint checks every reference field | `test_suppress_removes_every_reference`, `test_lint_reports_dangling_references` |
| 12 | `set_data_class` on a flow without a payload raised | fixed | The payload is created first, then extended | `test_set_data_class_on_a_flow_without_payload` |
| 13 | L1 process ID collided with the root | fixed | Process identities carry their level (`process, L0/L1/module/handler, ...`); lint checks level order | `level-order` lint rule |
| 14 | Control misclassification by substring | fixed | Classification uses the callee name only, with plumbing (body parsers, sessions, `passport.initialize`) and optional auth (`auth.optional`, `AuthMiddleware(false)`) excluded; `security_headers` is its own kind | `test_classify_control_names`, ground truth `authenticated` |
| 15 | Common Express mount/app idioms missed | fixed | Inline `require` mounts, `{ path, route }` mount tables, `routes(app)` functions, Fastify `register`, chained anonymous routers | ground truth on Express samples |
| 16 | Middleware in an array ignored | fixed | Arrays are flattened for both `use` and per-route middleware | node-express-boilerplate |
| 17 | Inline handler wrapped in a call not treated as the handler | fixed | Wrappers (`catchAsync(fn)`, `asyncHandler(fn)`) are unwrapped | node-express-boilerplate edges |
| 18 | Alias pass tainted results of client/store calls | fixed | Aliases come only from constructors and factories; query results, responses and TypeORM query builders are not clients | nestjs-realworld stores |
| 19 | Chained calls created extra flows and stores | fixed | `.exec()/.then()/.lean()` chains are skipped; SQL statement builders (`select`, `func.count`) are not accesses | fastapi-full-stack, flask-microblog |
| 20 | `from pkg import submodule` resolved to `pkg/__init__.py` | fixed | `resolve_symbol` resolves a submodule import to the submodule file | flask-microblog, fastapi-full-stack |
| 21 | Stacked route decorators overwrote each other | fixed | Each decorator yields its own route; one entry point per method | flask-microblog entry points |
| 22 | `@limiter.limit` also emitted as an app-scope control | fixed | Decorators produce route- or handler-scope controls only | ground truth |
| 23 | `members` split inside call arguments | fixed | `_chain()` parses dotted chains with arguments removed | evaluation |
| 24 | f-string URLs never resolved | fixed | f-strings and env-variable tracing in the Python outbound recognizer | flask-microblog entities |
| 25 | Two kinds of stores never appeared | fixed | `client_init`-only stores (boto3 S3/DynamoDB/SQS, imported clients) become stores with an inferred flow and confidence | evaluation |
| 26 | Spring route detection | redesigned | New Java detector: class-level `@RequestMapping` prefixes, multi-path and bare mappings, repositories resolved to `@Table` names, `@ModelAttribute` pre-handlers as call edges | `test_spring_repository_to_table`, spring-petclinic ground truth |
| 27 | Name-only call resolution | fixed | Class-aware call graph (typed fields, DI constructors, interfaces to implementations, re-exports); Go member calls resolve to receiver methods only | ground truth edges on all samples |
| 28 | Go store regex fired on any `.Get(`/`.Set(` | fixed | Redis calls are gated on the receiver's declared client type; SQL needs a SQL statement (literal or held in a variable) | golang-gin-realworld, microservices-demo |
| 29 | Dead second Go route branch; Go 1.22 patterns | fixed | One route recognizer; `"GET /items/{id}"` ServeMux patterns and `{name...}` wildcards | `test_go_122_servemux_patterns` |
| 30 | Weakness identity was `file:line` | fixed | Identity is (kind, file, name, ordinal); line numbers never enter an ID | `test_ids_survive_whitespace_edits_and_directory_moves` |
| 31 | Compose service misclassification | fixed | Images classified by repository name with admin tools excluded; `infra` services (proxies) kept out of service boundaries | compose samples |
| 32 | Compose line lookup by substring from line 0 | fixed | Service lines anchored to the `services:` block indentation | evidence verification |
| 33 | Duplicate boundaries and a phantom Mermaid node | fixed | Boundaries with identical membership are emitted once; `style` lines only for subgraphs that were drawn | Mermaid render check (all diagrams) |
| 34 | Labels not neutralised for `<...>`; truncation produced duplicates | fixed | `<`/`>` replaced with guillemets, truncation with an ellipsis, duplicate labels disambiguated by ID suffix | `test_mermaid_labels_are_safe_and_unique` |
| 35 | Table cells not escaped for `|` | fixed | Every Markdown cell goes through `cell()` | `test_mermaid_labels_are_safe_and_unique` |
| 36 | Sequence diagrams misrepresented order and scope | fixed | Sequences use the entry point's ordered controls, its `call_chain`, and only flows to elements in its `reaches` | evaluation diagrams |
| 37 | Store technology promoted but flow protocol not | fixed | Flow protocol is taken from the store's final technology | schema validation |
| 38 | `classify_field` substring and ordering errors | fixed | Tokenised matching on word boundaries; financial before credential (`card_token`); configuration names (`*_EXPIRATION_MINUTES`) are internal | `test_classify_field_tokens` |
| 39 | Environment-dependent output (elapsed time, directory name) | fixed | No timing in outputs; the model name comes from the root manifest, else the repository's own git remote, else the directory; the recorded commit is the last one touching the analyzed tree. Override expiry still uses today's date by design | `test_byte_identical_across_hash_seeds`, `test_ids_survive_whitespace_edits_and_directory_moves` |
| 40a | `rename` on a process changed only `display_name` | fixed | `rename` changes `name` and keeps `code_name` | `test_rename_changes_the_displayed_name_and_keeps_the_code_name` |
| 40b | `add_boundary` did not recompute crossings | fixed | Crossings are recomputed after boundary additions and suppressions | `test_add_boundary_recomputes_crossings` |
| 40c | Only the first 40 entry points by hash order got flow diagrams | fixed | Diagram priority: public and unauthenticated first, then by number of stores and services reached | evaluation |
| 40d | Dockerfile without `EXPOSE` gave a misleading gap and a boundary named `container: .` | fixed | Dockerfiles always yield a hint named after the directory or project; the "no descriptors" gap appears only when there are none | evaluation |
| 40e | `_go_env_for` recursion | fixed | Depth-limited | `test_go_env_for_terminates_on_cycles` |
| 40f | Same-named tables of different services merge | documented | Store identity is technology plus table; services sharing a database is common, separate databases with the same table name are merged. See "Known limitations" in `evaluation.md` | none |
| 40g | An Ingress hint overwrote a same-named Deployment in host resolution | fixed | Only container hints resolve hosts | evaluation (microservices-demo) |
| 40h | Dead statements | fixed | The modules containing them were rewritten | none |
| - | Fact kinds and fields emitted but never read | redesigned | `FactStore.add` validates every fact against a registry of kinds and required fields (`model.FACT_KINDS`); synthesis reads each kind it registers; documented in `docs/facts.md` | `FactStore` raises on unknown kinds or missing fields |

## Round 2 (v0.5.1)

A second review (eight reviewers by area, findings reproduced on fixtures and new repositories) was stopped early to limit cost. The highest-impact reproduced findings were fixed; the rest are listed as open.

| Finding | Status | Test |
|---|---|---|
| Express middleware passed in the same `app.use('/p', auth, router)` call as a mount was dropped | fixed (`routing.py`) | `test_express_middleware_in_mount_call_guards_the_router` |
| A middleware file containing `req.get('...')` was read as a router, so `app.use(auth)` lost its control | fixed (stricter router-file test) | same |
| gin/echo/fiber `Group(prefix, mw...)` middleware ignored | fixed | `test_gin_group_middleware` |
| `@csrf_exempt` modelled as a CSRF control | fixed | `test_flask_before_request_guard_and_csrf_exempt` |
| Flask `before_request` / `before_app_request` auth guards not modelled | fixed | same |
| FastAPI `include_router(..., dependencies=[...])` controls did not reach the included routes | fixed | ground truth |
| Nest `@UseGuards` with nested or multi-line arguments lost guards; `@Public()` ignored | fixed | ground truth |
| `@FeignClient` interfaces became entry points | fixed | none yet |
| `analyze` deleted hand-written `.mmd` files in the output directory | fixed (only tool-named files) | none yet |
| Malformed override entries crashed `analyze` | fixed (reported as gaps) | `test_malformed_overrides_do_not_crash` |

## Round 3 (v0.5.2): open items from round 2

| Finding | Status | Test |
|---|---|---|
| Django REST Framework ViewSets, routers, `@action`, class-based views per method, `permission_classes`, `DEFAULT_PERMISSION_CLASSES` | fixed | `test_drf_viewsets_views_and_permissions` |
| Django nested `urls.py` treated as root, dropping `include()` prefixes | fixed (root from `ROOT_URLCONF`) | same |
| Next.js `pages/api/**` and App Router `route.ts` files | fixed (route groups and dynamic segments handled) | `test_nextjs_file_system_routes` |
| Fastify plugin modules, `register(require(...), {prefix})`, `addHook`, route `preHandler` | fixed | `test_fastify_plugin_routes_and_prehandler` |
| Imported HTTP clients named `api`/`server` read as routers | fixed (an imported object is a router only if its file builds one) | `test_imported_http_client_named_api_is_not_a_router` |
| chi `r.Route`/`r.Group` closures and `r.With(...)` | fixed (closure scopes; middleware no longer leaks) | `test_chi_route_group_closures_and_with` |
| Go wrapper middleware `requireAuth(http.HandlerFunc(h))` | fixed | `test_go_wrapper_middleware` |
| Go calls through struct fields (`h.users.Get()`) | fixed (receiver struct field types) | `test_go_calls_through_struct_fields` |
| Spring Security `requestMatchers(...).permitAll()/hasRole()/anyRequest().authenticated()` | fixed (per-rule controls, first match wins) | `test_spring_security_rules_first_match_wins` |
| ASP.NET `MapGroup` authorization on a following line or statement; inherited `[Authorize]` | fixed | `test_minimal_api_group_authorization_across_statements` |
| Same route in two apps of one repository merged | fixed (split by package) | none |
| `compose.override.yml` ignored | fixed | none |
| OTM placed every unbounded element in the Internet zone | fixed (a "deployment" zone; only external entities on the Internet) | none |
| `lint`/`diff`/`export` accepted IRs of another version | fixed (version check) | none |
| Schema-valid IRs could crash consumers | fixed (asset and threat-agent fields required) | schema validation |

Still open: Koa routers; Flask-RESTful resources; JavaScript model instances tracked per file rather than per function; compose services that share one build context with different Dockerfiles.
