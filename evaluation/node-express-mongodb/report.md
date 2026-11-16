# code2design report: node-express-mongodb

Commit `30851145f343`, code2design 0.5.0, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 6 |
| (test files, not modelled) | 0 |

Detectors: config@0.5, js@0.5, synth@0.5.0

Facts: app 1, control 1, dependencies 1, entry_point 8, listener 1, module 1, router 3, router_mount 2, schema 5, store_access 8

## Model

| Collection | Count |
|---|---|
| processes | 14 |
| entities | 1 |
| stores | 1 |
| boundaries | 1 |
| flows | 14 |
| entry_points | 8 |
| controls | 1 |
| weaknesses | 8 |
| schemas | 2 |
| assets | 0 |
| threat_agents | 2 |
| gaps | 3 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 8 entry points, 8 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: server.js port PORT
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 3 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 8 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /api/tutorials | unknown | cors | MongoDB: tutorial |
| DELETE /api/tutorials/{id} | unknown | cors | - |
| GET /api/tutorials/{id} | unknown | cors | MongoDB: tutorial |
| DELETE /api/tutorials | unknown | cors | MongoDB: tutorial |
| GET /api/tutorials/published | unknown | cors | MongoDB: tutorial |
| POST /api/tutorials | unknown | cors | MongoDB: tutorial |
| PUT /api/tutorials/{id} | unknown | cors | MongoDB: tutorial |
| GET / | unknown | cors | - |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| info | CWE-306 | no authentication control detected on DELETE /api/tutorials/{id} | app/routes/turorial.routes.js:22 |
| info | CWE-306 | no authentication control detected on PUT /api/tutorials/{id} | app/routes/turorial.routes.js:19 |
| info | CWE-306 | no authentication control detected on GET /api/tutorials | app/routes/turorial.routes.js:10 |
| info | CWE-306 | no authentication control detected on DELETE /api/tutorials | app/routes/turorial.routes.js:25 |
| info | CWE-306 | no authentication control detected on GET / | server.js:33 |
| info | CWE-306 | no authentication control detected on GET /api/tutorials/published | app/routes/turorial.routes.js:13 |
| info | CWE-306 | no authentication control detected on GET /api/tutorials/{id} | app/routes/turorial.routes.js:16 |
| info | CWE-306 | no authentication control detected on POST /api/tutorials | app/routes/turorial.routes.js:7 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| MongoDB: tutorial | mongodb | - | unknown | - |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/tutorials handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/tutorials/published handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/tutorials/{id} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> DELETE /api/tutorials/{id} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/tutorials handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> DELETE /api/tutorials handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> PUT /api/tutorials/{id} handler
- **info** `black-hole-or-miracle` process GET /api/tutorials/published handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/tutorials handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process DELETE /api/tutorials/{id} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/tutorials/{id} handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` PUT /api/tutorials/{id} handler -> MongoDB: tutorial: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /api/tutorials handler -> MongoDB: tutorial: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MongoDB: tutorial -> GET /api/tutorials/{id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MongoDB: tutorial -> GET /api/tutorials/published handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` DELETE /api/tutorials handler -> MongoDB: tutorial: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MongoDB: tutorial -> GET /api/tutorials handler: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: node-express-mongodb (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Anonymous HTTP caller (confidence 0.9): 8 entry points are reachable from outside, 8 of them without a detected authentication control
- Insider with access to repository: node-express-mongodb (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `no_boundary_info` : no docker compose, Dockerfile, Kubernetes or Terraform descriptors were found; the repository is the only trust boundary
- `unknown_attribute` server.js: Question: is TLS terminated in front of the HTTP listener of node-express-mongodb? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` app/controllers/tutorial.controller.js:77: Question: what is the authentication and encryption of the link to MongoDB: tutorial?
