# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Compromised external service | Personal data (PII) | SMTP mail relay -> app (ntsz) -> tasks -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | User credentials | SMTP mail relay -> app (ntsz) -> tasks -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> GET/POST /auth/reset_password_request handler -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | User credentials | HTTP client -> GET/POST /auth/reset_password_request handler -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> GET/POST /auth/reset_password_request handler -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | User credentials | HTTP client -> GET/POST /auth/reset_password_request handler -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: app | Personal data (PII) | GET/POST /auth/reset_password_request handler -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: app | User credentials | GET/POST /auth/reset_password_request handler -> Postgres: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret MAIL_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret MAIL_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Authenticated HTTP caller | Secret MAIL_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Authenticated HTTP caller | Secret SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: app | Secret MAIL_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: app | Secret SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | api.cognitive.microsofttranslator.com, SMTP mail relay | - | return malicious responses; harvest data sent to it | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; use functions beyond their role | inferred |
| Insider with access to container: app | insider | container: app | POST /translate handler, GET /explore handler, search, GET/POST /auth/reset_password_request handler, GET /auth/logout handler (+20) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret MAIL_PASSWORD | credential | secret | app (5f4h) | app (5f4h) |
| Personal data (PII) | data | pii | Postgres: User | GET/POST /auth/reset_password_request handler, tasks, forms (d3aj), PUT /api/users/{id} handler, models, POST /api/users handler, auth (hde2), forms (ibuk) (+13) |
| User credentials | data | credential | Postgres: User | GET/POST /auth/reset_password_request handler, tasks, forms (d3aj), PUT /api/users/{id} handler, models, POST /api/users handler, auth (hde2), forms (ibuk) (+12) |
| Secret SECRET_KEY | credential | secret | app (5f4h) | app (5f4h) |
