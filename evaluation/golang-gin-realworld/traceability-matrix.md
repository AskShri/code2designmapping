# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> GET /api/articles/{slug} handler -> models (k4l4) -> SQLite: UserModel | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | User credentials | HTTP client -> GET /api/articles/{slug} handler -> models (k4l4) -> SQLite: UserModel | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: golang-gin-realworld | Personal data (PII) | models (3dfh) -> SQLite: UserModel | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: golang-gin-realworld | User credentials | models (3dfh) -> SQLite: UserModel | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> PUT /api/articles/{slug} handler -> models (k4l4) -> SQLite: UserModel | none | users.AuthMiddleware | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | User credentials | HTTP client -> PUT /api/articles/{slug} handler -> models (k4l4) -> SQLite: UserModel | none | users.AuthMiddleware | authentication only: no authorization control detected on the path (check object- and function-level access) |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to repository: golang-gin-realworld | insider | repository: golang-gin-realworld | PUT /api/articles/{slug} handler, PUT /api/user handler, models (3dfh), GET /api/articles/{slug} handler, POST /api/profiles/{username}/follow handler (+18) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; use functions beyond their role | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Personal data (PII) | data | pii | SQLite: UserModel | models (3dfh), middlewares, models (k4l4) |
| User credentials | data | credential | SQLite: UserModel | models (3dfh), middlewares, models (k4l4) |
