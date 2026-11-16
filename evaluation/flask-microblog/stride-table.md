# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| email -> SMTP mail relay | Data flow | T I D | pii | container: app | none | EXIT POINT: sensitive data leaves the system; authentication=unknown, encryption=unknown: question for the team |
| Postgres: User | Data store | T R I D | credential, pii | in no boundary | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| app (ntsz) -> SMTP mail relay | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| GET / handler (+1 routes) -> Postgres: Post | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| GET/POST /send_message/{recipient} handler -> Postgres: Message | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| models -> Postgres: Notification | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Post -> GET /search handler | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/users/{id}/following handler | Data flow | T I D | internal | container: app | token_auth.login_required | authentication=token, encryption=unknown: question for the team |
| HTTP client -> GET/POST /auth/login handler | Data flow | T I D | credential, pii | container: app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres: User -> GET /api/users/{id} handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> models | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /user/{username}/popup handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| tests -> Postgres: Post | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /follow/{username} handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres: User -> GET /api/users/{id}/following handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> POST /api/users handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| models -> Redis: rq:* | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET/POST /auth/register handler | Data flow | T I D | credential, pii | container: app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /explore handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /search handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| translate -> api.cognitive.microsofttranslator.com | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=tls: question for the team |
| Postgres: User -> forms (d3aj) | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> GET/POST /auth/reset_password_request handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> tasks | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /messages handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres: User -> GET /api/users/{id}/followers handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET/POST /auth/reset_password_request handler | Data flow | T I D | pii | container: app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /notifications handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres: User -> GET /user/{username} handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Elasticsearch -> search | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/users handler | Data flow | T I D | - | container: app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /unfollow/{username} handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /export_posts handler | Data flow | T I D | - | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres: User -> GET/POST /send_message/{recipient} handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Post -> tasks | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Task -> tasks | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Notification -> GET /notifications handler | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> forms (ibuk) | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Message -> models | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/tokens handler | Data flow | T I D | - | container: app | basic_auth.login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres: User -> PUT /api/users/{id} handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /translate handler | Data flow | T I D | - | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres: User -> tests | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| tests -> Postgres: User | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres (table unresolved) -> models | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> GET /user/{username}/popup handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| GET/POST /auth/register handler -> Postgres: User | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| models -> Postgres (table unresolved) | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| search -> Elasticsearch | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> POST /unfollow/{username} handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Task -> models | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> GET/POST /auth/login handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> PUT /api/users/{id} handler | Data flow | T I D | - | container: app | token_auth.login_required | authentication=token, encryption=unknown: question for the team |
| HTTP client -> GET/POST /edit_profile handler | Data flow | T I D | pii | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /user/{username} handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/users/{id}/followers handler | Data flow | T I D | internal | container: app | token_auth.login_required | authentication=token, encryption=unknown: question for the team |
| HTTP client -> GET / handler (+1 routes) | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres: User -> POST /follow/{username} handler | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/users handler | Data flow | T I D | internal | container: app | token_auth.login_required | authentication=token, encryption=unknown: question for the team |
| POST /api/users handler -> Postgres: User | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /auth/logout handler | Data flow | T I D | - | container: app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres: User -> auth (hde2) | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET/POST /send_message/{recipient} handler | Data flow | T I D | internal | container: app | login_required | authentication=session_id, encryption=unknown: question for the team |
| Postgres (table unresolved) -> tasks | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET/POST /auth/reset_password/{token} handler | Data flow | T I D | credential | container: app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| models -> Postgres: Task | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/users/{id} handler | Data flow | T I D | - | container: app | token_auth.login_required | authentication=token, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/tokens handler | Data flow | T I D | - | container: app | token_auth.login_required | authentication=token, encryption=unknown: question for the team |
| api.cognitive.microsofttranslator.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| SMTP mail relay | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Postgres: Task | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres (table unresolved) | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: Post | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Redis: rq:* | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Elasticsearch | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: Notification | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: Message | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| POST /translate handler | Process | S T R I D E | - | - | login_required | entry point |
| GET /explore handler | Process | S T R I D E | - | - | login_required | entry point |
| search | Process | S T R I D E | - | - | n/a (internal) |  |
| GET\|POST /auth/reset_password_request handler | Process | S T R I D E | - | - | none | entry point |
| GET /auth/logout handler | Process | S T R I D E | - | - | none | entry point |
| POST /api/tokens handler | Process | S T R I D E | - | - | basic_auth.login_required | entry point |
| translate | Process | S T R I D E | - | - | n/a (internal) |  |
| tasks | Process | S T R I D E | - | - | n/a (internal) |  |
| forms | Process | S T R I D E | - | - | n/a (internal) |  |
| PUT /api/users/{id} handler | Process | S T R I D E | - | - | token_auth.login_required | entry point |
| models | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /messages handler | Process | S T R I D E | - | - | login_required | entry point |
| POST /api/users handler | Process | S T R I D E | - | - | none | entry point |
| DELETE /api/tokens handler | Process | S T R I D E | - | - | token_auth.login_required | entry point |
| auth | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /search handler | Process | S T R I D E | - | - | login_required | entry point |
| forms | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/users/{id}/following handler | Process | S T R I D E | - | - | token_auth.login_required | entry point |
| POST /unfollow/{username} handler | Process | S T R I D E | - | - | login_required | entry point |
| tests | Process | S T R I D E | - | - | n/a (internal) |  |
| GET\|POST /auth/login handler | Process | S T R I D E | - | - | none | entry point |
| GET\|POST /send_message/{recipient} handler | Process | S T R I D E | - | - | login_required | entry point |
| GET /api/users/{id} handler | Process | S T R I D E | - | - | token_auth.login_required | entry point |
| GET /api/users/{id}/followers handler | Process | S T R I D E | - | - | token_auth.login_required | entry point |
| app | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /notifications handler | Process | S T R I D E | - | - | login_required | entry point |
| GET /api/users handler | Process | S T R I D E | - | - | token_auth.login_required | entry point |
| GET\|POST /edit_profile handler | Process | S T R I D E | - | - | login_required | entry point |
| GET / handler (+1 routes) | Process | S T R I D E | - | - | login_required | entry point |
| email | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /user/{username}/popup handler | Process | S T R I D E | - | - | login_required | entry point |
| GET\|POST /auth/reset_password/{token} handler | Process | S T R I D E | - | - | none | entry point |
| GET /user/{username} handler | Process | S T R I D E | - | - | login_required | entry point |
| POST /follow/{username} handler | Process | S T R I D E | - | - | login_required | entry point |
| GET\|POST /auth/register handler | Process | S T R I D E | - | - | none | entry point |
| GET /export_posts handler | Process | S T R I D E | - | - | login_required | entry point |
| no authentication control detected on GET /auth/reset_password_request | Weakness (info) | S E | - | - | ep:kwzfizkfor | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:55 |
| no authentication control detected on POST /auth/reset_password_request | Weakness (info) | S E | - | - | ep:jad5ukyk5q | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:55 |
| no authentication control detected on POST /auth/login | Weakness (info) | S E | - | - | ep:zyujxd7dfj | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:14 |
| no authentication control detected on GET /auth/logout | Weakness (info) | S E | - | - | ep:wgv2dghw3d | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:33 |
| no authentication control detected on POST /auth/register | Weakness (info) | S E | - | - | ep:zyidpb6z47 | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:39 |
| no authentication control detected on GET /auth/login | Weakness (info) | S E | - | - | ep:bst7ueny32 | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:14 |
| no authentication control detected on POST /api/users | Weakness (info) | S E | - | - | ep:2cxtkdmljh | CWE-306 Entry point without a detected authentication control (review) at app/api/users.py:45 |
| no authentication control detected on POST /auth/reset_password/{token} | Weakness (info) | S E | - | - | ep:2ayzga4pft | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:72 |
| no authentication control detected on GET /auth/register | Weakness (info) | S E | - | - | ep:3jucglazqj | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:39 |
| no authentication control detected on GET /auth/reset_password/{token} | Weakness (info) | S E | - | - | ep:4s66eqkeye | CWE-306 Entry point without a detected authentication control (review) at app/auth/routes.py:72 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | GET/POST /auth/reset_password_request handler, tasks, forms (d3aj), PUT /api/users/{id} handler, models, POST /api/users handler, auth (hde2), forms (ibuk) (+13) | Postgres: User | SMTP mail relay |
| credential | GET/POST /auth/reset_password_request handler, tasks, forms (d3aj), PUT /api/users/{id} handler, models, POST /api/users handler, auth (hde2), forms (ibuk) (+12) | Postgres: User | - |
