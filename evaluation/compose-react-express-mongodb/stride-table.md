# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at backend/routes/index.js:24 |
| cors() with default or wildcard origin | Weakness | - | - | - | - | permissive_cors at backend/server.js:18 |
| no authn control detected on POST /todos | Weakness | - | - | - | - | unauthenticated_entry_point at backend/routes/index.js:9 |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| App -> Unresolved HTTP target | Data flow | T I D | - | container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| POST /todos handler -> MongoDB | Data flow | T I D | - | container: backend, container: mongo | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /todos handler | Data flow | T I D | - | container: backend | cors | authentication=none, encryption=unknown: question for the team |
| MongoDB: Todo -> GET / handler | Data flow | T I D | - | container: backend, container: mongo | none | authentication=unknown, encryption=unknown: question for the team |
| serviceWorker -> Unresolved HTTP target | Data flow | T I D | - | container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: backend | cors | authentication=none, encryption=unknown: question for the team |
| MongoDB | Data store | T R I D | - | in container: mongo | encryption at rest: unknown |  |
| MongoDB: Todo | Data store | T R I D | - | in container: mongo | encryption at rest: unknown |  |
| routes | Process | S T R I D E | - | - | n/a (internal) |  |
| serviceWorker | Process | S T R I D E | - | - | n/a (internal) |  |
| App | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | cors | entry point |
| POST /todos handler | Process | S T R I D E | - | - | cors | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
