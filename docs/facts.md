# Fact vocabulary and the routing model

Detectors never build diagram elements. They emit flat **facts**, each with an evidence span, into a
`FactStore` that checks every fact against a registry (`code2design/model.py`, `FACT_KINDS`): an
unknown kind, a missing required field or a fact without evidence raises at once. Synthesis is the
only consumer. This keeps every language and framework on one vocabulary, so a Flask blueprint, an
Express router, a gin group, a Spring controller and a Nest controller all reach the model through
the same few facts and the same code path.

## Kinds

| Kind | Required fields | Optional fields | Meaning |
|---|---|---|---|
| `module` | path, name | | A package manifest (`package.json`, `pyproject.toml`, `pom.xml`, `go.mod`); the root one names the model |
| `dependencies` | file, ecosystem, packages | | Declared third-party packages, for the attack-surface count |
| `app` | file | | A framework bootstrap |
| `listener` | file, port, tls | | A server listen call; `tls` when the listener itself terminates TLS |
| `router` | file, local, own_prefix, root | | A router object: an app, Express `Router`, Flask `Blueprint`, FastAPI `APIRouter`, gin group, controller class. `root` marks objects that serve without being mounted |
| `router_mount` | file, parent, prefix, child_file, child_local | | `parent --prefix--> child`. `child_local` null means "the router(s) that file exports" |
| `global_prefix` | file, prefix | | A prefix applied to every route of the service (Nest `app.setGlobalPrefix`) |
| `entry_point` | file, protocol, method, path, router | handler_span, handler_file, handler_symbol, handler_ref, handler_scope, handler_class, route_controls, payload_types, anonymous | A route, RPC service, consumer or task. Exactly one way of naming the handler is set |
| `control` | file, control_kind, name, scope | router, router_file, ordered, path_prefix, conditional, routes, router_names, handler_file, handler_symbol | A security control and where it is registered (see scopes below) |
| `call_edge` | file, line, target_file, target_symbol | | A call the call graph cannot see syntactically: FastAPI `Depends`, Spring `@ModelAttribute` |
| `store_access` | file, technology, operation | logical_name, method, package, encryption_at_rest, iac, host | `read`, `write`, `unknown`, or the non-usage kinds `client_init`, `model_definition`, `service_definition` |
| `outbound_call` | file, protocol, operation | host, sdk_service, entity_kind, service_hint, insecure, package | A call to something outside the process. `host` may be `env:NAME`, `svc:Name` or `variable:expr` until synthesis resolves it |
| `schema` | file, name, fields, schema_kind | class_name | `validation`, `request`, `model` or `sql`; fields carry names and types, data classes are assigned in synthesis |
| `config_value` | file, name, data_class | | A configuration value; `secret` ones become credential assets |
| `weakness` | file, weakness_kind, name | | A provable negative finding; kinds and their CWE, severity and STRIDE categories are in `model.WEAKNESSES` |
| `boundary_hint` | name, boundary_kind, source | context, host, exposed, holds_store, technology, infra, env_hosts, ports, image | A deployment unit from compose, Kubernetes, Dockerfile or Terraform |
| `service_host` | host, file | | A hostname a deployment descriptor defines |
| `declared_link` | file, source_service, target_host | via | An environment variable of one service naming another service's host |
| `unresolved` | file, detail | | Something a detector saw but could not resolve; becomes a gap |

## The routing model (`code2design/routing.py`)

For each `entry_point`, the router chain is walked upward through `router_mount` facts until a root
router: prefixes are joined (with the service's `global_prefix`) and normalized to `{param}` syntax
without a trailing slash. A router mounted by name in the same file is preferred over a wildcard
"whatever that file exports" mount.

Controls are collected along the same chain, which is what makes control attribution the same for
every framework:

| Scope | Registered on | Applies to |
|---|---|---|
| `router` | a router object (`app.use(x)`, `router.use(x)`, `@UseGuards` on a controller, `[Authorize]` on a controller, gin `group.Use(x)`) | routes of that router and its mounted children; when `ordered`, only routes and mounts registered after it; when `path_prefix` is set, only routes under it |
| `route` | the route registration itself (middleware arguments, decorators, `[Authorize]` on an action) | that entry point |
| `service` | the whole service (Spring Security filter chain, `APP_GUARD`, `useGlobalGuards`, Nest `consumer.apply().forRoutes()`) | every entry point of the service, or the ones selected by `routes` (method and path pattern, relative to the global prefix) and `router_names` (controller classes) |
| `handler` | inside the handler (`Depends` parameters, `Schema.parse(req.body)`, Django view decorators) | the entry points whose handler function contains it |

An entry point with `anonymous` (ASP.NET `[AllowAnonymous]`) drops inherited authn and authz controls.
The resulting list keeps registration order, which is execution order for middleware, and is what the
sequence diagrams draw.

## Handlers, the call graph and `reaches`

Synthesis turns the handler naming into a call-graph key: an inline span is matched to the function
node it covers, a symbol is looked up in its file, a reference (`userController.create`) is resolved
through imports and re-exports, and gRPC services use a scope (`class`, `file` or `package`, where Go
starts from receiver methods only). Every store access, outbound call and schema is owned by the
function that contains it. An entry point's `reaches` is the set of stores, external entities and other
services whose backing facts are owned by functions reachable from its handler (calls through
interfaces fan out to their implementations). Callers of the handler are never counted.
