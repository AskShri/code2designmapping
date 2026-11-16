# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| POSTGRES_PASSWORD committed in .env | Weakness (high) | I E | - | - | fastapi-full-stack | CWE-798 Hard-coded or committed credentials at .env:17 |
| SECRET_KEY committed in .env | Weakness (high) | I E | - | - | fastapi-full-stack | CWE-798 Hard-coded or committed credentials at .env:6 |
| hard-coded token_type | Weakness (high) | I E | - | - | backend | CWE-798 Hard-coded or committed credentials at backend/app/models.py:116 |
| FIRST_SUPERUSER_PASSWORD committed in .env | Weakness (high) | I E | - | - | fastapi-full-stack | CWE-798 Hard-coded or committed credentials at .env:8 |
| Postgres: user | Data store | T R I D | credential | in container: db | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| PUT /api/v1/items/{id} handler -> Postgres: item | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/password-recovery/{email} handler | Data flow | T I D | internal | repository: fastapi-full-stack | CORSMiddleware | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres: user -> GET /api/v1/users/{user_id} handler | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/utils/test-email handler | Data flow | T I D | internal | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_active_superuser) | authentication=credentials, encryption=unknown: question for the team |
| PATCH /api/v1/users/me handler -> Postgres: user | Data flow | T I D | pii | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: user -> db | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> PATCH /api/v1/users/me handler | Data flow | T I D | pii | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_user) | authentication=credentials, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/users handler | Data flow | T I D | credential | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_active_superuser) | authentication=credentials, encryption=unknown: question for the team |
| Postgres: user -> PATCH /api/v1/users/{user_id} handler | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: item -> GET /api/v1/items/{id} handler | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/items handler | Data flow | T I D | internal | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_user) | authentication=credentials, encryption=unknown: question for the team |
| DELETE /api/v1/users/me handler -> Postgres: user | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: item -> GET /api/v1/items handler | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/private/users handler | Data flow | T I D | credential, pii | repository: fastapi-full-stack | CORSMiddleware | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres: user -> DELETE /api/v1/users/{user_id} handler | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| DELETE /api/v1/users/{user_id} handler -> Postgres: item | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/login/test-token handler | Data flow | T I D | internal | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_user) | authentication=credentials, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/reset-password handler | Data flow | T I D | credential, pii | repository: fastapi-full-stack | CORSMiddleware | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/login/access-token handler | Data flow | T I D | credential | repository: fastapi-full-stack | CORSMiddleware | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| DELETE /api/v1/users/{user_id} handler -> Postgres: user | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: item -> DELETE /api/v1/items/{id} handler | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> DELETE /api/v1/users/me handler | Data flow | T I D | internal | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_user) | authentication=credentials, encryption=unknown: question for the team |
| Internal HTTP client -> GET /api/v1/utils/health-check handler | Data flow | T I D | - | repository: fastapi-full-stack | CORSMiddleware | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| PATCH /api/v1/users/me/password handler -> Postgres: user | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: user -> crud | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: user -> GET /api/v1/users handler | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| POST /api/v1/items handler -> Postgres: item | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| crud -> Postgres: item | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: user -> deps | Data flow | T I D | credential | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/password-recovery-html-content/{email} handler | Data flow | T I D | - | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_active_superuser) | authentication=credentials, encryption=unknown: question for the team |
| POST /api/v1/private/users handler -> Postgres: user | Data flow | T I D | credential, pii | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/v1/users/signup handler | Data flow | T I D | credential, pii | repository: fastapi-full-stack | CORSMiddleware | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| DELETE /api/v1/items/{id} handler -> Postgres: item | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| app -> Sentry | Data flow | T I D | - | repository: fastapi-full-stack | none | authentication=unknown, encryption=tls: question for the team |
| Postgres: item -> PUT /api/v1/items/{id} handler | Data flow | T I D | - | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> GET /api/v1/users/me handler | Data flow | T I D | internal | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_user) | authentication=credentials, encryption=unknown: question for the team |
| crud -> Postgres: user | Data flow | T I D | credential, pii | container: db, repository: fastapi-full-stack | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> PATCH /api/v1/users/me/password handler | Data flow | T I D | credential | repository: fastapi-full-stack | CORSMiddleware, Depends(get_current_user) | authentication=credentials, encryption=unknown: question for the team |
| Internal HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Sentry | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Postgres: item | Data store | T R I D | - | in container: db | encryption at rest: unknown |  |
| POST /api/v1/password-recovery/{email} handler | Process | S T R I D E | - | - | CORSMiddleware | entry point |
| PATCH /api/v1/users/me handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| DELETE /api/v1/users/me handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| POST /api/v1/items handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| POST /api/v1/private/users handler | Process | S T R I D E | - | - | CORSMiddleware | entry point |
| POST /api/v1/utils/test-email handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_active_superuser) | entry point |
| POST /api/v1/login/access-token handler | Process | S T R I D E | - | - | CORSMiddleware | entry point |
| POST /api/v1/users handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_active_superuser) | entry point |
| DELETE /api/v1/users/{user_id} handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_active_superuser), Depends(get_current_user) | entry point |
| GET /api/v1/users/{user_id} handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| PATCH /api/v1/users/me/password handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| POST /api/v1/password-recovery-html-content/{email} handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_active_superuser) | entry point |
| GET /api/v1/items/{id} handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| POST /api/v1/reset-password handler | Process | S T R I D E | - | - | CORSMiddleware | entry point |
| app | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /api/v1/login/test-token handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| GET /api/v1/users handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_active_superuser) | entry point |
| db | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /api/v1/users/signup handler | Process | S T R I D E | - | - | CORSMiddleware | entry point |
| crud | Process | S T R I D E | - | - | n/a (internal) |  |
| DELETE /api/v1/items/{id} handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| PATCH /api/v1/users/{user_id} handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_active_superuser) | entry point |
| GET /api/v1/items handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| deps | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/v1/users/me handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |
| PUT /api/v1/items/{id} handler | Process | S T R I D E | - | - | CORSMiddleware, Depends(get_current_user) | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | PATCH /api/v1/users/me handler, POST /api/v1/private/users handler, POST /api/v1/reset-password handler, POST /api/v1/users/signup handler, crud | - | - |
| credential | DELETE /api/v1/users/me handler, POST /api/v1/private/users handler, POST /api/v1/login/access-token handler, POST /api/v1/users handler, DELETE /api/v1/users/{user_id} handler, GET /api/v1/users/{user_id} handler, PATCH /api/v1/users/me/password handler, POST /api/v1/reset-password handler (+6) | Postgres: user | - |
