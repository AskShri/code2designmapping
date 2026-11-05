# code2design report: compose-flask

Commit `30f4b7f6a6c3`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| python | 1 |
| (test files skipped) | 0 |

Detectors that ran: config@0.3, py@0.3

Facts: app_entry 2, boundary_hint 1, dependencies 1, entry_point 1, listener 1

## Model

| Collection | Count |
|---|---|
| processes | 3 |
| entities | 1 |
| stores | 0 |
| boundaries | 2 |
| flows | 1 |
| entry_points | 1 |
| controls | 0 |
| weaknesses | 1 |
| schemas | 0 |
| assets | 0 |
| threat_agents | 2 |
| gaps | 1 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 1 entry points, 1 without a detected authn control
- **listeners**: app/app.py port (host='0.0.0.0', port=8000)
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 1 declared in app/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

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

## Lint

- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: compose-flask (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: web (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 1 http entry points, 1 without a detected authn control

## Gaps and questions

- `unknown_attribute` app/app.py: Question for the team: is TLS terminated in front of the HTTP listener on port (host='0.0.0.0', port=8000)? Inbound flows are marked encryption=unknown until answered.
