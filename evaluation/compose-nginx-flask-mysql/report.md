# code2design report: compose-nginx-flask-mysql

Commit `30f4b7f6a6c3`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| python | 1 |
| (test files skipped) | 0 |

Detectors that ran: config@0.3, py@0.3

Facts: app_entry 1, boundary_hint 4, dependencies 1, entry_point 1, schema 2, store_access 6, weakness 1

## Model

| Collection | Count |
|---|---|
| processes | 4 |
| entities | 1 |
| stores | 3 |
| boundaries | 3 |
| flows | 6 |
| entry_points | 1 |
| controls | 0 |
| weaknesses | 2 |
| schemas | 1 |
| assets | 0 |
| threat_agents | 2 |
| gaps | 5 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 1 entry points, 1 without a detected authn control
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 2 declared in backend/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| GET / | none |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| MySQL: blog | mysql | - | container: db |
| MySQL (collection unresolved) | mysql | - | container: db |
| MySQL: IF | mysql | - | container: db |

## Lint

- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **warning** `unknown-link-attributes` hello -> MySQL: IF: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MySQL: blog -> hello: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` hello -> MySQL (collection unresolved): authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` hello -> MySQL: blog: authentication=unknown, encryption=unknown
- **warning** `weakness` plaintext_credentials: MYSQL_ROOT_PASSWORD_FILE set in compose service 'db' (compose.yaml:22)

## Inferred elements (dashed in diagrams)

- repository: compose-nginx-flask-mysql (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: backend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 1 http entry points, 1 without a detected authn control

## Gaps and questions

- `unresolved` backend/hello.py:23: mysql access through a document or connection variable whose collection could not be resolved; shown as a separate store
- `unknown_attribute` backend/hello.py: Question for the team: is TLS terminated in front of the HTTP listener? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` backend/hello.py:20: Question for the team: how is the link to MySQL: IF authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` backend/hello.py:21: Question for the team: how is the link to MySQL: blog authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` backend/hello.py:23: Question for the team: how is the link to MySQL (collection unresolved) authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
