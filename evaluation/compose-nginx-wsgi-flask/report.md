# code2design report: compose-nginx-wsgi-flask

Commit `30f4b7f6a6c3`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| python | 2 |
| (test files skipped) | 0 |

Detectors that ran: config@0.3, py@0.3

Facts: app_entry 1, boundary_hint 3, dependencies 1, entry_point 4

## Model

| Collection | Count |
|---|---|
| processes | 6 |
| entities | 1 |
| stores | 0 |
| boundaries | 2 |
| flows | 4 |
| entry_points | 4 |
| controls | 0 |
| weaknesses | 4 |
| schemas | 0 |
| assets | 0 |
| threat_agents | 2 |
| gaps | 1 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 4 entry points, 4 without a detected authn control
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 2 declared in flask/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| GET /cache-me | none |
| GET /flask-health-check | none |
| GET /info | none |
| GET / | none |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|

## Lint

- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /flask-health-check handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /info handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /cache-me handler
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /cache-me handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /info handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /flask-health-check handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: compose-nginx-wsgi-flask (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: flask-app (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 4 http entry points, 4 without a detected authn control

## Gaps and questions

- `unknown_attribute` flask/app.py: Question for the team: is TLS terminated in front of the HTTP listener? Inbound flows are marked encryption=unknown until answered.
