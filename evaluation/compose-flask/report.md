# code2design report: compose-flask

Commit `30f4b7f6a6c3`, code2design 0.5.2, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| python | 1 |
| (test files, not modelled) | 0 |

Detectors: config@0.5, py@0.5, synth@0.5.2

Facts: app 1, boundary_hint 2, dependencies 1, entry_point 1, listener 1, router 1

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

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 1 entry points, 1 without a detected authentication control (1 of them published outside the deployment)
- **listeners**: app/app.py port 8000
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 1 declared in app/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 1 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET / | public | none | - |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| info | CWE-306 | no authentication control detected on GET / | app/app.py:4 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: compose-flask (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: web (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 1 entry points are reachable from outside, 1 of them without a detected authentication control

## Gaps and questions

- `unknown_attribute` app/app.py: Question: is TLS terminated in front of the HTTP listener of web? Inbound flows are marked encryption=unknown until answered.
