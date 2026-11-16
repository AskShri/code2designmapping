# code2design report: compose-nginx-wsgi-flask

Commit `30f4b7f6a6c3`, code2design 0.5.0, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| python | 2 |
| (test files, not modelled) | 0 |

Detectors: config@0.5, py@0.5, synth@0.5.0

Facts: app 1, boundary_hint 4, declared_link 1, dependencies 1, entry_point 4, router 1

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

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 4 entry points, 4 without a detected authentication control (4 of them published outside the deployment)
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 2 declared in flask/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 4 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /info | public | none | - |
| GET /cache-me | public | none | - |
| GET /flask-health-check | public | none | - |
| GET / | public | none | - |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| info | CWE-306 | no authentication control detected on GET / | flask/app.py:5 |
| info | CWE-306 | no authentication control detected on GET /cache-me | flask/app.py:9 |
| info | CWE-306 | no authentication control detected on GET /flask-health-check | flask/app.py:25 |
| info | CWE-306 | no authentication control detected on GET /info | flask/app.py:13 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /cache-me handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /info handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /flask-health-check handler
- **info** `black-hole-or-miracle` process GET /flask-health-check handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /cache-me handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /info handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: compose-nginx-wsgi-flask (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: flask-app (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 4 entry points are reachable from outside, 4 of them without a detected authentication control

## Gaps and questions

- `unknown_attribute` flask/app.py: Question: is TLS terminated in front of the HTTP listener of flask-app? Inbound flows are marked encryption=unknown until answered.
