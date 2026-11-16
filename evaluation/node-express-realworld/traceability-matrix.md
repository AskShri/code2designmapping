# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> POST /api/users/login handler -> auth.service -> Postgres: User | none | cors | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | User credentials | HTTP client -> POST /api/users/login handler -> auth.service -> Postgres: User | none | cors | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> POST /api/users/login handler -> auth.service -> Postgres: User | none | cors | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | User credentials | HTTP client -> POST /api/users/login handler -> auth.service -> Postgres: User | none | cors | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: app | Personal data (PII) | auth.service -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: app | User credentials | auth.service -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret JWT_SECRET | no path | - | - | unreachable from this agent over the modelled flows |
| Authenticated HTTP caller | Secret JWT_SECRET | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: app | Secret JWT_SECRET | no path | - | - | unreachable from this agent over the modelled flows |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; use functions beyond their role | inferred |
| Insider with access to container: app | insider | container: app | POST /api/articles handler, DELETE /api/articles/{slug} handler, POST /api/users/login handler, POST /api/profiles/{username}/follow handler, GET /api/articles/{slug}/comments handler (+19) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret JWT_SECRET | credential | secret | routes | routes |
| Personal data (PII) | data | pii | Postgres: User | auth.service, profile.service |
| User credentials | data | credential | Postgres: User | auth.service, profile.service |
