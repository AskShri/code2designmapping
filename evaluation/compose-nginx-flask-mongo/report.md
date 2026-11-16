# code2design report: compose-nginx-flask-mongo

Commit `30f4b7f6a6c3`, code2design 0.5.0, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| python | 1 |
| (test files, not modelled) | 0 |

Detectors: config@0.5, py@0.5, synth@0.5.0

Facts: app 1, boundary_hint 4, declared_link 1, dependencies 1, entry_point 1, listener 1, router 1, store_access 2, weakness 1

## Model

| Collection | Count |
|---|---|
| processes | 4 |
| entities | 1 |
| stores | 1 |
| boundaries | 3 |
| flows | 2 |
| entry_points | 1 |
| controls | 0 |
| weaknesses | 1 |
| schemas | 0 |
| assets | 0 |
| threat_agents | 2 |
| gaps | 2 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 1 entry points, 1 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: flask/server.py port os.environ.get("FLASK_SERVER_PORT", 9090
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 2 declared in flask/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 1 medium (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET / | internal | none | - |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| medium | CWE-489 | debug=True on the application server | flask/server.py:21 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Internal HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| MongoDB | mongodb | - | unknown | container: mongo |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> GET / handler
- **warning** `weakness-debug-mode-enabled` CWE-489 debug=True on the application server (flask/server.py:21)
- **info** `black-hole-or-miracle` process flask has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` flask -> MongoDB: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: compose-nginx-flask-mongo (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- flask -> MongoDB (confidence 0.6): the mongodb client library is imported in flask/server.py but no call site could be resolved
- Insider with access to container: backend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Workload inside the deployment calling HTTP client endpoints (confidence 0.7): these entry points are not published outside the deployment; a caller must already be inside it

## Gaps and questions

- `unknown_attribute` flask/server.py: Question: is TLS terminated in front of the HTTP listener of backend? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` flask/server.py:5: Question: what is the authentication and encryption of the link to MongoDB?
