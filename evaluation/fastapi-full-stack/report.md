# code2design report: fastapi-full-stack

Commit `aabb90126964`, code2design 0.5.1, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| python | 43 |
| tsx | 70 |
| typescript | 38 |
| (test files, not modelled) | 27 |

Detectors: config@0.5, js@0.5, py@0.5, synth@0.5.1

Facts: app 1, boundary_hint 6, call_edge 40, config_value 6, control 24, declared_link 1, dependencies 2, entry_point 23, module 4, outbound_call 2, router 7, router_mount 6, schema 31, store_access 31, weakness 4

## Model

| Collection | Count |
|---|---|
| processes | 33 |
| entities | 2 |
| stores | 2 |
| boundaries | 2 |
| flows | 64 |
| entry_points | 23 |
| controls | 7 |
| weaknesses | 4 |
| schemas | 31 |
| assets | 8 |
| threat_agents | 3 |
| gaps | 5 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 22 entry points, 5 without a detected authentication control (0 of them published outside the deployment); 1 infrastructure entry points (health, preflight, docs) not counted
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 37 declared in frontend/package.json, packages/react-email/package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 4 high (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /api/v1/utils/health-check (infrastructure) | internal | CORSMiddleware | - |
| POST /api/v1/utils/test-email | internal | CORSMiddleware, Depends(get_current_active_superuser) | Postgres: user |
| PUT /api/v1/items/{id} | internal | CORSMiddleware, Depends(get_current_user) | Postgres: item, Postgres: user |
| DELETE /api/v1/items/{id} | internal | CORSMiddleware, Depends(get_current_user) | Postgres: item, Postgres: user |
| POST /api/v1/login/test-token | internal | CORSMiddleware, Depends(get_current_user) | Postgres: user |
| GET /api/v1/users/{user_id} | internal | CORSMiddleware, Depends(get_current_user) | Postgres: user |
| GET /api/v1/items/{id} | internal | CORSMiddleware, Depends(get_current_user) | Postgres: item, Postgres: user |
| GET /api/v1/items | internal | CORSMiddleware, Depends(get_current_user) | Postgres: item, Postgres: user |
| DELETE /api/v1/users/me | internal | CORSMiddleware, Depends(get_current_user) | Postgres: user |
| POST /api/v1/private/users | internal | CORSMiddleware | Postgres: user |
| GET /api/v1/users/me | internal | CORSMiddleware, Depends(get_current_user) | Postgres: user |
| GET /api/v1/users | internal | CORSMiddleware, Depends(get_current_active_superuser) | Postgres: user |
| POST /api/v1/items | internal | CORSMiddleware, Depends(get_current_user) | Postgres: item, Postgres: user |
| DELETE /api/v1/users/{user_id} | internal | CORSMiddleware, Depends(get_current_active_superuser), Depends(get_current_user) | Postgres: item, Postgres: user |
| PATCH /api/v1/users/{user_id} | internal | CORSMiddleware, Depends(get_current_active_superuser) | Postgres: user |
| PATCH /api/v1/users/me/password | internal | CORSMiddleware, Depends(get_current_user) | Postgres: user |
| POST /api/v1/users/signup | internal | CORSMiddleware | Postgres: user |
| POST /api/v1/reset-password | internal | CORSMiddleware | Postgres: user |
| POST /api/v1/password-recovery-html-content/{email} | internal | CORSMiddleware, Depends(get_current_active_superuser) | Postgres: user |
| PATCH /api/v1/users/me | internal | CORSMiddleware, Depends(get_current_user) | Postgres: user |
| POST /api/v1/users | internal | CORSMiddleware, Depends(get_current_active_superuser) | Postgres: user |
| POST /api/v1/login/access-token | internal | CORSMiddleware | Postgres: user |
| POST /api/v1/password-recovery/{email} | internal | CORSMiddleware | Postgres: user |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| high | CWE-798 | POSTGRES_PASSWORD committed in .env | .env:17 |
| high | CWE-798 | SECRET_KEY committed in .env | .env:6 |
| high | CWE-798 | hard-coded token_type | backend/app/models.py:116 |
| high | CWE-798 | FIRST_SUPERUSER_PASSWORD committed in .env | .env:8 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Internal HTTP client | system | - |
| Sentry | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| Postgres: item | postgres | - | unknown | container: db |
| Postgres: user | postgres | credential | unknown | container: db |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> POST /api/v1/password-recovery/{email} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> POST /api/v1/private/users handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> POST /api/v1/reset-password handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> POST /api/v1/login/access-token handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> GET /api/v1/utils/health-check handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> POST /api/v1/users/signup handler
- **warning** `weakness-plaintext-credentials` CWE-798 POSTGRES_PASSWORD committed in .env (.env:17)
- **warning** `weakness-plaintext-credentials` CWE-798 SECRET_KEY committed in .env (.env:6)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded token_type (backend/app/models.py:116)
- **warning** `weakness-plaintext-credentials` CWE-798 FIRST_SUPERUSER_PASSWORD committed in .env (.env:8)
- **info** `black-hole-or-miracle` process GET /api/v1/utils/health-check handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process app has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process deps has only inputs; a detector may be missing
- **info** `unknown-link-attributes` PUT /api/v1/items/{id} handler -> Postgres: item: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: user -> GET /api/v1/users/{user_id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` PATCH /api/v1/users/me handler -> Postgres: user: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: user -> db: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: user -> PATCH /api/v1/users/{user_id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: item -> GET /api/v1/items/{id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` DELETE /api/v1/users/me handler -> Postgres: user: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: item -> GET /api/v1/items handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: user -> DELETE /api/v1/users/{user_id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` DELETE /api/v1/users/{user_id} handler -> Postgres: item: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` DELETE /api/v1/users/{user_id} handler -> Postgres: user: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: item -> DELETE /api/v1/items/{id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` PATCH /api/v1/users/me/password handler -> Postgres: user: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: user -> crud: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: user -> GET /api/v1/users handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /api/v1/items handler -> Postgres: item: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` crud -> Postgres: item: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: user -> deps: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /api/v1/private/users handler -> Postgres: user: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` DELETE /api/v1/items/{id} handler -> Postgres: item: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` app -> Sentry: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` Postgres: item -> PUT /api/v1/items/{id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` crud -> Postgres: user: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: fastapi-full-stack (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Compromised external service (confidence 0.7): each of the 1 outbound dependencies is a potentially hostile responder
- Insider with access to repository: fastapi-full-stack (confidence 0.8): one insider agent per trust boundary, placed inside it
- Workload inside the deployment calling HTTP client endpoints (confidence 0.7): these entry points are not published outside the deployment; a caller must already be inside it

## Gaps and questions

- `unknown_attribute` backend/app/api/routes/utils.py: Question: is TLS terminated in front of the HTTP listener of backend? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` backend/app/api/routes/items.py:93: Question: what is the authentication and encryption of the link to Postgres: item?
- `unknown_attribute` backend/app/api/routes/users.py:169: Question: what is the authentication and encryption of the link to Postgres: user?
- `unknown_attribute` backend/app/main.py:19: Question: what is the authentication of the link to Sentry?
- `unknown_attribute` backend/app/models.py:51: Question: is Postgres: user encrypted at rest? It holds credential.
