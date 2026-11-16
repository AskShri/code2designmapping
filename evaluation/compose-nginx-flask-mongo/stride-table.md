# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| debug=True on the application server | Weakness (medium) | I E | - | - | flask | CWE-489 Debug mode enabled on the application server at flask/server.py:21 |
| Internal HTTP client -> GET / handler | Data flow | T I D | - | container: backend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| flask -> MongoDB | Data flow (inferred) | T I D | - | container: backend, container: mongo | none | authentication=unknown, encryption=unknown: question for the team |
| Internal HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| MongoDB | Data store | T R I D | - | in container: mongo | encryption at rest: unknown |  |
| flask | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
