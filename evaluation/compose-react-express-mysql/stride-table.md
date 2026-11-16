# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| MYSQL_ROOT_PASSWORD_FILE set in compose service 'db' | Weakness (high) | I E | - | - | compose-react-express-mysql | CWE-798 Hard-coded or committed credentials at compose.yaml:46 |
| DATABASE_PASSWORD set in compose service 'backend' | Weakness (high) | I E | - | - | compose-react-express-mysql | CWE-798 Hard-coded or committed credentials at compose.yaml:12 |
| HTTP client -> GET /healthz handler | Data flow | T I D | - | container: backend | morgan | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| healthcheck -> Unresolved HTTP target | Data flow | T I D | - | container: backend | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: backend | morgan | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| backend -> MySQL | Data flow (inferred) | T I D | - | container: backend, container: db | none | authentication=unknown, encryption=unknown: question for the team |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| MySQL | Data store | T R I D | - | in container: db | encryption at rest: unknown |  |
| healthcheck | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | morgan | entry point |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:olb7e5a6fp | CWE-306 Entry point without a detected authentication control (review) at backend/src/server.js:22 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
