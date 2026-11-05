# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET /flask-health-check | Weakness | - | - | - | - | unauthenticated_entry_point at flask/app.py:25 |
| no authn control detected on GET /info | Weakness | - | - | - | - | unauthenticated_entry_point at flask/app.py:13 |
| no authn control detected on GET /cache-me | Weakness | - | - | - | - | unauthenticated_entry_point at flask/app.py:9 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at flask/app.py:5 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| HTTP client -> GET /flask-health-check handler | Data flow | T I D | - | container: flask-app | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /info handler | Data flow | T I D | - | container: flask-app | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: flask-app | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /cache-me handler | Data flow | T I D | - | container: flask-app | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| GET /cache-me handler | Process | S T R I D E | - | - | none | entry point |
| GET /info handler | Process | S T R I D E | - | - | none | entry point |
| GET /flask-health-check handler | Process | S T R I D E | - | - | none | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
