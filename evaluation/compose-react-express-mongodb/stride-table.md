# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET /api | Weakness | - | - | - | - | unauthenticated_entry_point at backend/routes/index.js:24 |
| no authn control detected on POST /api/todos | Weakness | - | - | - | - | unauthenticated_entry_point at backend/routes/index.js:9 |
| cors() with default or wildcard origin | Weakness | - | - | - | - | permissive_cors at backend/server.js:18 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| POST /api/todos handler -> MongoDB: Todo | Data flow | T I D | - | container: backend, container: mongo | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: Todo -> GET /api handler | Data flow | T I D | - | container: backend, container: mongo | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api handler | Data flow | T I D | - | container: backend | cors | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/todos handler | Data flow | T I D | internal | container: backend | cors | authentication=none, encryption=unknown: question for the team |
| MongoDB: Todo | Data store | T R I D | - | in container: mongo | encryption at rest: unknown |  |
| routes | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /api/todos handler | Process | S T R I D E | - | - | cors | entry point |
| GET /api handler | Process | S T R I D E | - | - | cors | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
