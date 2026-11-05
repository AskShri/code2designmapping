# code2design report: compose-react-express-mongodb

Commit `30f4b7f6a6c3`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 14 |
| (test files skipped) | 1 |

Detectors that ran: config@0.3, js@0.3

Facts: app_entry 1, boundary_hint 5, control 1, dependencies 2, entry_point 2, listener 1, module 2, outbound_call 5, store_access 5, weakness 1

## Model

| Collection | Count |
|---|---|
| processes | 8 |
| entities | 2 |
| stores | 2 |
| boundaries | 4 |
| flows | 6 |
| entry_points | 2 |
| controls | 1 |
| weaknesses | 3 |
| schemas | 0 |
| assets | 0 |
| threat_agents | 4 |
| gaps | 7 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 2 entry points, 2 without a detected authn control
- **listeners**: backend/server.js port 3000
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 15 declared in backend/package.json, frontend/package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| POST /todos | cors |
| GET / | cors |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Unresolved HTTP target | system | - |
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| MongoDB | mongodb | - | container: mongo |
| MongoDB: Todo | mongodb | - | container: mongo |

## Lint

- **warning** `unknown-link-attributes` App -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` POST /todos handler -> MongoDB: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: Todo -> GET / handler: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` serviceWorker -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **info** `black-hole-or-miracle` process serviceWorker has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process App has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: compose-react-express-mongodb (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: backend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 2 http entry points, 2 without a detected authn control
- Compromised third party: Unresolved HTTP target (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: frontend (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` backend/routes/index.js:9: router for POST /todos is not mounted from a detected app entry; path shown without prefix
- `unresolved` backend/routes/index.js:24: router for GET / is not mounted from a detected app entry; path shown without prefix
- `unresolved` frontend/src/serviceWorker.js:103: outbound call target is a variable:swUrl expression; host not resolvable statically
- `unknown_attribute` backend/server.js: Question for the team: is TLS terminated in front of the HTTP listener on port 3000? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` backend/routes/index.js:14: Question for the team: how is the link to MongoDB authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` backend/routes/index.js:25: Question for the team: how is the link to MongoDB: Todo authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` frontend/src/App.js:17: Question for the team: how is the link to Unresolved HTTP target authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
