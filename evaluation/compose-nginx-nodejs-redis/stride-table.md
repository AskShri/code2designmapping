# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| Redis -> web | Data flow | T I D | - | container: web1 | none | authentication=unknown, encryption=unknown: question for the team |
| web -> Redis | Data flow | T I D | - | container: web1 | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: web1 | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Redis | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| web | Process | S T R I D E | - | - | n/a (internal) |  |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:6sxzmgwcz6 | CWE-306 Entry point without a detected authentication control (review) at web/server.js:10 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
