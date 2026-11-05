# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on POST / | Weakness | - | - | - | - | unauthenticated_entry_point at app/routes/turorial.routes.js:7 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at app/routes/turorial.routes.js:10 |
| no authn control detected on PUT /:id | Weakness | - | - | - | - | unauthenticated_entry_point at app/routes/turorial.routes.js:19 |
| no authn control detected on GET /:id | Weakness | - | - | - | - | unauthenticated_entry_point at app/routes/turorial.routes.js:16 |
| no authn control detected on GET /published | Weakness | - | - | - | - | unauthenticated_entry_point at app/routes/turorial.routes.js:13 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at server.js:33 |
| no authn control detected on DELETE / | Weakness | - | - | - | - | unauthenticated_entry_point at app/routes/turorial.routes.js:25 |
| no authn control detected on DELETE /:id | Weakness | - | - | - | - | unauthenticated_entry_point at app/routes/turorial.routes.js:22 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| PUT /:id handler -> MongoDB: tutorials | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| HTTP client -> PUT /:id handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST / handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /:id handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /published handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| POST / handler -> MongoDB: tutorials | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: tutorials -> GET /published handler | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: tutorials -> GET / handler | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE / handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| DELETE / handler -> MongoDB: tutorials | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: tutorials -> GET /:id handler | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE /:id handler | Data flow | T I D | - | repository: node-express-mongodb | cors | authentication=none, encryption=unknown: question for the team |
| MongoDB: tutorials | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| GET /:id handler | Process | S T R I D E | - | - | cors | entry point |
| GET / handler | Process | S T R I D E | - | - | cors | entry point |
| GET / handler | Process | S T R I D E | - | - | cors | entry point |
| PUT /:id handler | Process | S T R I D E | - | - | cors | entry point |
| GET /published handler | Process | S T R I D E | - | - | cors | entry point |
| POST / handler | Process | S T R I D E | - | - | cors | entry point |
| DELETE / handler | Process | S T R I D E | - | - | cors | entry point |
| DELETE /:id handler | Process | S T R I D E | - | - | cors | entry point |
| tutorial.controller | Process | S T R I D E | - | - | n/a (internal) |  |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
