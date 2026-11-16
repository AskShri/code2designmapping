# code2design report: flask-microblog

Commit `a975ef648643`, code2design 0.5.1, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| python | 24 |
| (test files, not modelled) | 0 |

Detectors: config@0.5, py@0.5, synth@0.5.1

Facts: app 1, boundary_hint 1, config_value 2, control 24, dependencies 1, entry_point 35, outbound_call 7, router 6, router_mount 5, schema 27, store_access 77

## Model

| Collection | Count |
|---|---|
| processes | 40 |
| entities | 3 |
| stores | 8 |
| boundaries | 1 |
| flows | 85 |
| entry_points | 35 |
| controls | 4 |
| weaknesses | 10 |
| schemas | 24 |
| assets | 4 |
| threat_agents | 4 |
| gaps | 13 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 35 entry points, 10 without a detected authentication control (0 of them published outside the deployment)
- **exit points carrying sensitive data**: SMTP mail relay
- **third-party dependencies**: 54 declared in requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 10 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| POST /auth/reset_password/{token} | unknown | none | Postgres: User |
| POST /api/users | unknown | none | Postgres: User |
| GET /api/users | unknown | token_auth.login_required | - |
| GET /auth/register | unknown | none | Postgres: User |
| GET /explore | unknown | login_required | - |
| GET /auth/reset_password/{token} | unknown | none | Postgres: User |
| GET /export_posts | unknown | login_required | - |
| GET /messages | unknown | login_required | - |
| GET /notifications | unknown | login_required | Postgres: Notification |
| GET /auth/login | unknown | none | Postgres: User |
| GET / | unknown | login_required | Postgres: Post |
| GET /user/{username} | unknown | login_required | Postgres: User |
| GET /edit_profile | unknown | login_required | - |
| DELETE /api/tokens | unknown | token_auth.login_required | - |
| POST /send_message/{recipient} | unknown | login_required | Postgres: User, Postgres: Message |
| POST /index | unknown | login_required | Postgres: Post |
| GET /api/users/{id}/following | unknown | token_auth.login_required | Postgres: User |
| GET /user/{username}/popup | unknown | login_required | Postgres: User |
| POST /auth/reset_password_request | unknown | none | SMTP mail relay, Postgres: User |
| POST /follow/{username} | unknown | login_required | Postgres: User |
| GET /auth/reset_password_request | unknown | none | SMTP mail relay, Postgres: User |
| POST /translate | unknown | login_required | api.cognitive.microsofttranslator.com |
| GET /api/users/{id}/followers | unknown | token_auth.login_required | Postgres: User |
| PUT /api/users/{id} | unknown | token_auth.login_required | Postgres: User |
| POST /api/tokens | unknown | basic_auth.login_required | - |
| GET /api/users/{id} | unknown | token_auth.login_required | Postgres: User |
| GET /search | unknown | login_required | Postgres (table unresolved), Postgres: Post, Elasticsearch |
| GET /send_message/{recipient} | unknown | login_required | Postgres: User, Postgres: Message |
| GET /auth/logout | unknown | none | - |
| GET /index | unknown | login_required | Postgres: Post |
| POST /unfollow/{username} | unknown | login_required | Postgres: User |
| POST /edit_profile | unknown | login_required | - |
| POST / | unknown | login_required | Postgres: Post |
| POST /auth/register | unknown | none | Postgres: User |
| POST /auth/login | unknown | none | Postgres: User |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| info | CWE-306 | no authentication control detected on GET /auth/reset_password_request | app/auth/routes.py:55 |
| info | CWE-306 | no authentication control detected on POST /auth/reset_password_request | app/auth/routes.py:55 |
| info | CWE-306 | no authentication control detected on POST /auth/login | app/auth/routes.py:14 |
| info | CWE-306 | no authentication control detected on GET /auth/logout | app/auth/routes.py:33 |
| info | CWE-306 | no authentication control detected on POST /auth/register | app/auth/routes.py:39 |
| info | CWE-306 | no authentication control detected on GET /auth/login | app/auth/routes.py:14 |
| info | CWE-306 | no authentication control detected on POST /api/users | app/api/users.py:45 |
| info | CWE-306 | no authentication control detected on POST /auth/reset_password/{token} | app/auth/routes.py:72 |
| info | CWE-306 | no authentication control detected on GET /auth/register | app/auth/routes.py:39 |
| info | CWE-306 | no authentication control detected on GET /auth/reset_password/{token} | app/auth/routes.py:72 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| api.cognitive.microsofttranslator.com | system | api.cognitive.microsofttranslator.com |
| SMTP mail relay | system | - |
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| Postgres: Task | postgres | - | unknown | - |
| Postgres (table unresolved) | postgres | - | unknown | - |
| Postgres: Post | postgres | - | unknown | - |
| Redis: rq:* | redis | - | unknown | - |
| Elasticsearch | elasticsearch | - | unknown | - |
| Postgres: Notification | postgres | - | unknown | - |
| Postgres: User | postgres | credential, pii | unknown | - |
| Postgres: Message | postgres | - | unknown | - |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET|POST /auth/login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET|POST /auth/register handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET|POST /auth/reset_password_request handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/users handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /auth/logout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET|POST /auth/reset_password/{token} handler
- **info** `black-hole-or-miracle` process GET /explore handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/logout handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /api/tokens handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process PUT /api/users/{id} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /messages handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process DELETE /api/tokens handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/users/{id}/following handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /unfollow/{username} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET|POST /auth/login handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/users/{id} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/users/{id}/followers handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /notifications handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/users handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET|POST /edit_profile handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /user/{username}/popup handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /user/{username} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /follow/{username} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /export_posts handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` app -> SMTP mail relay: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` GET / handler (+1 routes) -> Postgres: Post: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` GET|POST /send_message/{recipient} handler -> Postgres: Message: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> Postgres: Notification: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Post -> GET /search handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET /api/users/{id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` email -> SMTP mail relay: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` tests -> Postgres: Post: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET /api/users/{id}/following handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> POST /api/users handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> Redis: rq:*: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` translate -> api.cognitive.microsofttranslator.com: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` Postgres: User -> forms: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET|POST /auth/reset_password_request handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> tasks: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET /api/users/{id}/followers handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET /user/{username} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Elasticsearch -> search: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET|POST /send_message/{recipient} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Post -> tasks: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Task -> tasks: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Notification -> GET /notifications handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> forms: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Message -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> PUT /api/users/{id} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> tests: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` tests -> Postgres: User: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres (table unresolved) -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET /user/{username}/popup handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` GET|POST /auth/register handler -> Postgres: User: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> Postgres (table unresolved): authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` search -> Elasticsearch: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> POST /unfollow/{username} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Task -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> GET|POST /auth/login handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> POST /follow/{username} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /api/users handler -> Postgres: User: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> auth: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres (table unresolved) -> tasks: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> Postgres: Task: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- Compromised external service (confidence 0.7): each of the 2 outbound dependencies is a potentially hostile responder
- Anonymous HTTP caller (confidence 0.9): 35 entry points are reachable from outside, 10 of them without a detected authentication control
- Authenticated HTTP caller (confidence 0.9): 25 entry points require authentication; a holder of valid credentials is a distinct agent
- Insider with access to container: app (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` app/models.py:30: a postgres access could not be traced to a table; it is shown as a separate store
- `unknown_attribute` app/auth/routes.py: Question: is TLS terminated in front of the HTTP listener of app? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` app/__init__.py:38: Question: what is the authentication and encryption of the link to SMTP mail relay?
- `unknown_attribute` app/main/routes.py:37: Question: what is the authentication and encryption of the link to Postgres: Post?
- `unknown_attribute` app/main/routes.py:189: Question: what is the authentication and encryption of the link to Postgres: Message?
- `unknown_attribute` app/models.py:203: Question: what is the authentication and encryption of the link to Postgres: Notification?
- `unknown_attribute` app/api/users.py:13: Question: what is the authentication and encryption of the link to Postgres: User?
- `unknown_attribute` app/models.py:210: Question: what is the authentication and encryption of the link to Redis: rq:*?
- `unknown_attribute` app/translate.py:14: Question: what is the authentication of the link to api.cognitive.microsofttranslator.com?
- `unknown_attribute` app/search.py:22: Question: what is the authentication and encryption of the link to Elasticsearch?
- `unknown_attribute` app/tasks.py:20: Question: what is the authentication and encryption of the link to Postgres: Task?
- `unknown_attribute` app/models.py:30: Question: what is the authentication and encryption of the link to Postgres (table unresolved)?
- `unknown_attribute` app/models.py:98: Question: is Postgres: User encrypted at rest? It holds credential, pii.
