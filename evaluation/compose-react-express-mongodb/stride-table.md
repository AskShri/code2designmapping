# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| cors() with default or wildcard origin | Weakness (medium) | I | - | - | backend | CWE-942 Permissive cross-origin policy at backend/server.js:18 |
| MongoDB: Todo -> GET /api handler | Data flow | T I D | - | container: backend, container: mongo | none | authentication=unknown, encryption=unknown: question for the team |
| POST /api/todos handler -> MongoDB: Todo | Data flow | T I D | - | container: backend, container: mongo | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client -> POST /api/todos handler | Data flow | T I D | internal | container: backend | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Internal HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| MongoDB: Todo | Data store | T R I D | - | in container: mongo | encryption at rest: unknown |  |
| POST /api/todos handler | Process | S T R I D E | - | - | cors | entry point |
| GET /api handler | Process | S T R I D E | - | - | cors | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
