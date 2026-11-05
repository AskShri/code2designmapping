# code2design report: compose-flask-redis

Commit `30f4b7f6a6c3`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| python | 1 |
| (test files skipped) | 0 |

Detectors that ran: config@0.3, py@0.3

Facts: app_entry 2, boundary_hint 2, dependencies 1, entry_point 1, listener 1, store_access 4

## Model

| Collection | Count |
|---|---|
| processes | 4 |
| entities | 1 |
| stores | 1 |
| boundaries | 2 |
| flows | 3 |
| entry_points | 1 |
| controls | 0 |
| weaknesses | 1 |
| schemas | 0 |
| assets | 0 |
| threat_agents | 2 |
| gaps | 2 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 1 entry points, 1 without a detected authn control
- **listeners**: app.py port (host="0.0.0.0", port=8000, debug=True)
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 2 declared in requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

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
| Redis: hits:* | redis | - | container: redis |

## Lint

- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **warning** `unknown-link-attributes` Redis: hits:* -> GET / handler: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` GET / handler -> Redis: hits:*: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- Insider with access to container: web (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 1 http entry points, 1 without a detected authn control

## Gaps and questions

- `unknown_attribute` app.py: Question for the team: is TLS terminated in front of the HTTP listener on port (host="0.0.0.0", port=8000, debug=True)? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` app.py:9: Question for the team: how is the link to Redis: hits:* authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
