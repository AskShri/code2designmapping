# code2design report: compose-react-express-mysql

Commit `30f4b7f6a6c3`, code2design 0.5.0, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 12 |
| (test files, not modelled) | 4 |

Detectors: config@0.5, js@0.5, synth@0.5.0

Facts: app 1, boundary_hint 5, config_value 1, control 1, declared_link 1, dependencies 2, entry_point 2, module 2, outbound_call 1, router 1, store_access 2, weakness 2

## Model

| Collection | Count |
|---|---|
| processes | 6 |
| entities | 2 |
| stores | 1 |
| boundaries | 4 |
| flows | 4 |
| entry_points | 2 |
| controls | 1 |
| weaknesses | 3 |
| schemas | 0 |
| assets | 1 |
| threat_agents | 4 |
| gaps | 4 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 1 entry points, 1 without a detected authentication control (1 of them published outside the deployment); 1 infrastructure entry points (health, preflight, docs) not counted
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 6 declared in backend/package.json, frontend/package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 2 high, 1 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /healthz (infrastructure) | public | morgan | - |
| GET / | public | morgan | - |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| high | CWE-798 | MYSQL_ROOT_PASSWORD_FILE set in compose service 'db' | compose.yaml:46 |
| high | CWE-798 | DATABASE_PASSWORD set in compose service 'backend' | compose.yaml:12 |
| info | CWE-306 | no authentication control detected on GET / | backend/src/server.js:22 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Unresolved HTTP target | system | - |
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| MySQL | mysql | - | unknown | container: db |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /healthz handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `weakness-plaintext-credentials` CWE-798 MYSQL_ROOT_PASSWORD_FILE set in compose service 'db' (compose.yaml:46)
- **warning** `weakness-plaintext-credentials` CWE-798 DATABASE_PASSWORD set in compose service 'backend' (compose.yaml:12)
- **info** `black-hole-or-miracle` process healthcheck has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /healthz handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` healthcheck -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` backend -> MySQL: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: compose-react-express-mysql (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- backend -> MySQL (confidence 0.7): DATABASE_HOST of service 'backend' names host 'db' in compose.yaml; no call site was resolved in code
- Compromised external service (confidence 0.7): each of the 1 outbound dependencies is a potentially hostile responder
- Insider with access to container: backend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 1 entry points are reachable from outside, 1 of them without a detected authentication control
- Insider with access to container: frontend (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` backend/healthcheck.js:10: the target of an outbound call is built from a variable; the host is not resolvable statically
- `unknown_attribute` backend/src/server.js: Question: is TLS terminated in front of the HTTP listener of backend? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` backend/healthcheck.js:10: Question: what is the authentication and encryption of the link to Unresolved HTTP target?
- `unknown_attribute` compose.yaml:13: Question: what is the authentication and encryption of the link to MySQL?
