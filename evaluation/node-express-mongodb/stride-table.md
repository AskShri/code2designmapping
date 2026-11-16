# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| PUT /api/tutorials/{id} handler -> MongoDB: tutorial | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/tutorials handler | Data flow | T I D | internal | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/tutorials/published handler | Data flow | T I D | - | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /api/tutorials handler -> MongoDB: tutorial | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: tutorial -> GET /api/tutorials/{id} handler | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/tutorials/{id} handler | Data flow | T I D | - | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/tutorials/{id} handler | Data flow | T I D | - | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: tutorial -> GET /api/tutorials/published handler | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| DELETE /api/tutorials handler -> MongoDB: tutorial | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: tutorial -> GET /api/tutorials handler | Data flow | T I D | - | repository: node-express-mongodb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/tutorials handler | Data flow | T I D | internal | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/tutorials handler | Data flow | T I D | - | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> PUT /api/tutorials/{id} handler | Data flow | T I D | - | repository: node-express-mongodb | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| MongoDB: tutorial | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| GET /api/tutorials/published handler | Process | S T R I D E | - | - | cors | entry point |
| GET / handler | Process | S T R I D E | - | - | cors | entry point |
| GET /api/tutorials handler | Process | S T R I D E | - | - | cors | entry point |
| DELETE /api/tutorials/{id} handler | Process | S T R I D E | - | - | cors | entry point |
| DELETE /api/tutorials handler | Process | S T R I D E | - | - | cors | entry point |
| PUT /api/tutorials/{id} handler | Process | S T R I D E | - | - | cors | entry point |
| POST /api/tutorials handler | Process | S T R I D E | - | - | cors | entry point |
| GET /api/tutorials/{id} handler | Process | S T R I D E | - | - | cors | entry point |
| no authentication control detected on DELETE /api/tutorials/{id} | Weakness (info) | S E | - | - | ep:a4hpo7ddb5 | CWE-306 Entry point without a detected authentication control (review) at app/routes/turorial.routes.js:22 |
| no authentication control detected on PUT /api/tutorials/{id} | Weakness (info) | S E | - | - | ep:x4qyectef6 | CWE-306 Entry point without a detected authentication control (review) at app/routes/turorial.routes.js:19 |
| no authentication control detected on GET /api/tutorials | Weakness (info) | S E | - | - | ep:27vyldmhnz | CWE-306 Entry point without a detected authentication control (review) at app/routes/turorial.routes.js:10 |
| no authentication control detected on DELETE /api/tutorials | Weakness (info) | S E | - | - | ep:ia3tbrm6wn | CWE-306 Entry point without a detected authentication control (review) at app/routes/turorial.routes.js:25 |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:xikdto6k2u | CWE-306 Entry point without a detected authentication control (review) at server.js:33 |
| no authentication control detected on GET /api/tutorials/published | Weakness (info) | S E | - | - | ep:mde7efirmd | CWE-306 Entry point without a detected authentication control (review) at app/routes/turorial.routes.js:13 |
| no authentication control detected on GET /api/tutorials/{id} | Weakness (info) | S E | - | - | ep:fl3av674hk | CWE-306 Entry point without a detected authentication control (review) at app/routes/turorial.routes.js:16 |
| no authentication control detected on POST /api/tutorials | Weakness (info) | S E | - | - | ep:vsbu34ogyq | CWE-306 Entry point without a detected authentication control (review) at app/routes/turorial.routes.js:7 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
