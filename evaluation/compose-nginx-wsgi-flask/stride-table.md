# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| HTTP client -> GET /cache-me handler | Data flow | T I D | - | container: flask-app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: flask-app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /info handler | Data flow | T I D | - | container: flask-app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /flask-health-check handler | Data flow | T I D | - | container: flask-app | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| GET /flask-health-check handler | Process | S T R I D E | - | - | none | entry point |
| GET /cache-me handler | Process | S T R I D E | - | - | none | entry point |
| GET /info handler | Process | S T R I D E | - | - | none | entry point |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:wzz3sesz2f | CWE-306 Entry point without a detected authentication control (review) at flask/app.py:5 |
| no authentication control detected on GET /cache-me | Weakness (info) | S E | - | - | ep:hni6dffb2p | CWE-306 Entry point without a detected authentication control (review) at flask/app.py:9 |
| no authentication control detected on GET /flask-health-check | Weakness (info) | S E | - | - | ep:jouwkhefz5 | CWE-306 Entry point without a detected authentication control (review) at flask/app.py:25 |
| no authentication control detected on GET /info | Weakness (info) | S E | - | - | ep:awepcnowam | CWE-306 Entry point without a detected authentication control (review) at flask/app.py:13 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
