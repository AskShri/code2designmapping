# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at backend/hello.py:36 |
| MYSQL_ROOT_PASSWORD_FILE set in compose service 'db' | Weakness | - | - | - | - | plaintext_credentials at compose.yaml:22 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| hello -> MySQL: IF | Data flow | T I D | - | container: backend, container: db | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: backend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| MySQL: blog -> hello | Data flow | T I D | - | container: backend, container: db | none | authentication=unknown, encryption=unknown: question for the team |
| hello -> MySQL (collection unresolved) | Data flow | T I D | - | container: backend, container: db | none | authentication=unknown, encryption=unknown: question for the team |
| hello -> MySQL: blog | Data flow | T I D | - | container: backend, container: db | none | authentication=unknown, encryption=unknown: question for the team |
| MySQL: blog | Data store | T R I D | - | in container: db | encryption at rest: unknown |  |
| MySQL (collection unresolved) | Data store | T R I D | - | in container: db | encryption at rest: unknown |  |
| MySQL: IF | Data store | T R I D | - | in container: db | encryption at rest: unknown |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| hello | Process | S T R I D E | - | - | n/a (internal) |  |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
