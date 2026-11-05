# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at flask/server.py:11 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| HTTP client -> GET / handler | Data flow | T I D | - | container: backend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| MongoDB | Data store | T R I D | - | in container: mongo | encryption at rest: unknown |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
