# code2design report: node-express-mongodb

Commit `30851145f343`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 6 |
| (test files skipped) | 0 |

Detectors that ran: config@0.3, js@0.3

Facts: app_entry 1, control 1, dependencies 1, entry_point 8, listener 1, module 1, schema 5, store_access 7

## Model

| Collection | Count |
|---|---|
| processes | 14 |
| entities | 1 |
| stores | 1 |
| boundaries | 1 |
| flows | 15 |
| entry_points | 8 |
| controls | 1 |
| weaknesses | 8 |
| schemas | 1 |
| assets | 0 |
| threat_agents | 2 |
| gaps | 10 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 8 entry points, 8 without a detected authn control
- **listeners**: server.js port PORT
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 3 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| PUT /:id | cors |
| GET /published | cors |
| DELETE /:id | cors |
| POST / | cors |
| DELETE / | cors |
| GET / | cors |
| GET / | cors |
| GET /:id | cors |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| MongoDB: tutorials | mongodb | - | - |

## Lint

- **warning** `unknown-link-attributes` PUT /:id handler -> MongoDB: tutorials: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` POST / handler -> MongoDB: tutorials: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: tutorials -> GET /published handler: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: tutorials -> GET / handler: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` DELETE / handler -> MongoDB: tutorials: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: tutorials -> GET /:id handler: authentication=unknown, encryption=unknown
- **info** `black-hole-or-miracle` process GET /:id handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /published handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process tutorial.controller has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: node-express-mongodb (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Anonymous HTTP caller (confidence 0.9): 8 http entry points, 8 without a detected authn control
- Insider with access to repository: node-express-mongodb (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` app/routes/turorial.routes.js:7: router for POST / is not mounted from a detected app entry; path shown without prefix
- `unresolved` app/routes/turorial.routes.js:10: router for GET / is not mounted from a detected app entry; path shown without prefix
- `unresolved` app/routes/turorial.routes.js:13: router for GET /published is not mounted from a detected app entry; path shown without prefix
- `unresolved` app/routes/turorial.routes.js:16: router for GET /:id is not mounted from a detected app entry; path shown without prefix
- `unresolved` app/routes/turorial.routes.js:19: router for PUT /:id is not mounted from a detected app entry; path shown without prefix
- `unresolved` app/routes/turorial.routes.js:22: router for DELETE /:id is not mounted from a detected app entry; path shown without prefix
- `unresolved` app/routes/turorial.routes.js:25: router for DELETE / is not mounted from a detected app entry; path shown without prefix
- `no_boundary_info` : No compose, Dockerfile or Kubernetes manifests found; the repository is the only trust boundary.
- `unknown_attribute` server.js: Question for the team: is TLS terminated in front of the HTTP listener on port PORT? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` app/controllers/tutorial.controller.js:20: Question for the team: how is the link to MongoDB: tutorials authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
