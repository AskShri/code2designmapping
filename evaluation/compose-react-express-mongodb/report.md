# code2design report: compose-react-express-mongodb

Commit `30f4b7f6a6c3`, code2design 0.5.0, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 14 |
| (test files, not modelled) | 2 |

Detectors: config@0.5, js@0.5, synth@0.5.0

Facts: app 1, boundary_hint 5, control 1, dependencies 2, entry_point 2, listener 1, module 2, router 3, router_mount 2, schema 1, store_access 6, weakness 1

## Model

| Collection | Count |
|---|---|
| processes | 5 |
| entities | 1 |
| stores | 1 |
| boundaries | 4 |
| flows | 3 |
| entry_points | 2 |
| controls | 1 |
| weaknesses | 1 |
| schemas | 1 |
| assets | 0 |
| threat_agents | 3 |
| gaps | 2 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 2 entry points, 2 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: backend/server.js port 3000
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 15 declared in backend/package.json, frontend/package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 1 medium (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /api | internal | cors | MongoDB: Todo |
| POST /api/todos | internal | cors | MongoDB: Todo |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| medium | CWE-942 | cors() with default or wildcard origin | backend/server.js:18 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Internal HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| MongoDB: Todo | mongodb | - | unknown | container: mongo |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> POST /api/todos handler
- **warning** `weakness-permissive-cors` CWE-942 cors() with default or wildcard origin (backend/server.js:18)
- **info** `black-hole-or-miracle` process GET /api handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` MongoDB: Todo -> GET /api handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /api/todos handler -> MongoDB: Todo: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: compose-react-express-mongodb (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: backend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Workload inside the deployment calling HTTP client endpoints (confidence 0.7): these entry points are not published outside the deployment; a caller must already be inside it
- Insider with access to container: frontend (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unknown_attribute` backend/server.js: Question: is TLS terminated in front of the HTTP listener of backend? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` backend/routes/index.js:25: Question: what is the authentication and encryption of the link to MongoDB: Todo?
