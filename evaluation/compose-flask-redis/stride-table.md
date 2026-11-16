# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| debug=True on the application server | Weakness (medium) | I E | - | - | web | CWE-489 Debug mode enabled on the application server at app.py:14 |
| Redis -> GET / handler | Data flow | T I D | - | container: web | none | authentication=unknown, encryption=unknown: question for the team |
| GET / handler -> Redis | Data flow | T I D | - | container: web | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: web | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Redis | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:ihu4cujw3c | CWE-306 Entry point without a detected authentication control (review) at app.py:7 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
