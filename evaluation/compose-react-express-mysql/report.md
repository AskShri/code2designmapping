# code2design report: compose-react-express-mysql

Commit `30f4b7f6a6c3`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 12 |
| (test files skipped) | 4 |

Detectors that ran: config@0.3, js@0.3

Facts: app_entry 1, boundary_hint 4, config_value 2, control 1, dependencies 2, entry_point 2, module 2, outbound_call 1, store_access 2, weakness 2

## Model

| Collection | Count |
|---|---|
| processes | 6 |
| entities | 2 |
| stores | 1 |
| boundaries | 4 |
| flows | 3 |
| entry_points | 2 |
| controls | 1 |
| weaknesses | 5 |
| schemas | 0 |
| assets | 1 |
| threat_agents | 4 |
| gaps | 4 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 1 entry points, 1 without a detected authn control; 1 infrastructure entry points (health, preflight, docs) not counted
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 6 declared in backend/package.json, frontend/package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| GET /healthz (infrastructure) | morgan |
| GET / | morgan |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Unresolved HTTP target | system | - |
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| MySQL | mysql | - | container: db |

## Lint

- **warning** `unknown-link-attributes` healthcheck -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **warning** `weakness` plaintext_credentials: MYSQL_ROOT_PASSWORD_FILE set in compose service 'db' (compose.yaml:46)
- **warning** `weakness` plaintext_credentials: DATABASE_PASSWORD set in compose service 'backend' (compose.yaml:12)
- **info** `black-hole-or-miracle` process healthcheck has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /healthz handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: compose-react-express-mysql (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: backend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 2 http entry points, 2 without a detected authn control
- Compromised third party: Unresolved HTTP target (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: frontend (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` backend/healthcheck.js:10: outbound call target is a variable:options expression; host not resolvable statically
- `unresolved` compose.yaml:31: MySQL is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unknown_attribute` backend/src/server.js: Question for the team: is TLS terminated in front of the HTTP listener? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` backend/healthcheck.js:10: Question for the team: how is the link to Unresolved HTTP target authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
