# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| MYSQL_ROOT_PASSWORD_FILE set in compose service 'db' | Weakness | - | - | - | - | plaintext_credentials at compose.yaml:46 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at backend/src/server.js:22 |
| DATABASE_PASSWORD set in compose service 'backend' | Weakness | - | - | - | - | plaintext_credentials at compose.yaml:12 |
| no authn control detected on GET /healthz | Weakness | - | - | - | - | unauthenticated_entry_point at backend/src/server.js:29 |
| DATABASE_PASSWORD read at module import | Weakness | - | - | - | - | secret_in_env_at_import at backend/src/config.js:13 |
| DATABASE_PASSWORD read at module import | Weakness | - | - | - | - | secret_in_env_at_import at backend/src/config.js:12 |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| HTTP client -> GET / handler | Data flow | T I D | - | container: backend | morgan | authentication=none, encryption=unknown: question for the team |
| serviceWorker -> Unresolved HTTP target | Data flow | T I D | - | container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /healthz handler | Data flow | T I D | - | container: backend | morgan | authentication=none, encryption=unknown: question for the team |
| healthcheck -> Unresolved HTTP target | Data flow | T I D | - | container: backend | none | authentication=unknown, encryption=unknown: question for the team |
| MySQL | Data store | T R I D | - | in container: db | encryption at rest: unknown |  |
| healthcheck | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /healthz handler | Process | S T R I D E | - | - | morgan | entry point |
| serviceWorker | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | morgan | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
