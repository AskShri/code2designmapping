# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on ANY /^admin/ | Weakness | - | - | - | - | unauthenticated_entry_point at app/example/urls.py:20 |
| SECRET_KEY read at module import | Weakness | - | - | - | - | secret_in_env_at_import at app/example/settings.py:31 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| HTTP client -> ANY /^admin/ handler | Data flow | T I D | - | container: web | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| ANY /^admin/ handler | Process | S T R I D E | - | - | none | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
