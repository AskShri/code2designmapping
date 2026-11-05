# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at app.py:7 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| Redis: hits:* -> GET / handler | Data flow | T I D | - | container: redis, container: web | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: web | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| GET / handler -> Redis: hits:* | Data flow | T I D | - | container: redis, container: web | none | authentication=unknown, encryption=unknown: question for the team |
| Redis: hits:* | Data store | T R I D | - | in container: redis | encryption at rest: unknown |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| app | Process | S T R I D E | - | - | n/a (internal) |  |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
