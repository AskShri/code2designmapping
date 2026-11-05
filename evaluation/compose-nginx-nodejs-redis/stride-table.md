# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at web/server.js:10 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| GET / handler -> Redis: numVisits:* | Data flow | T I D | - | container: web1, container: redis, container: web2 | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: web1, container: web2 | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| Redis: numVisits:* -> GET / handler | Data flow | T I D | - | container: web1, container: redis, container: web2 | none | authentication=unknown, encryption=unknown: question for the team |
| Redis: numVisits:* | Data store | T R I D | - | in container: redis | encryption at rest: unknown |  |
| web | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
