# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Compromised external service | Personal data (PII) | SMTP mail relay -> email.service -> POST /v1/auth/forgot-password handler -> user.service -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | User credentials | SMTP mail relay -> email.service -> POST /v1/auth/forgot-password handler -> user.service -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> POST /v1/auth/refresh-tokens handler -> user.service -> MongoDB: User | none | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | User credentials | HTTP client -> POST /v1/auth/refresh-tokens handler -> user.service -> MongoDB: User | none | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: node-app | Personal data (PII) | passport -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: node-app | User credentials | passport -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> POST /v1/users handler -> user.service -> MongoDB: User | none | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | User credentials | HTTP client -> POST /v1/users handler -> user.service -> MongoDB: User | none | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | authentication only: no authorization control detected on the path (check object- and function-level access) |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | SMTP mail relay | - | return malicious responses; harvest data sent to it | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: node-app | insider | container: node-app | auth.service, POST /v1/auth/logout handler, POST /v1/users handler, GET /v1/users handler, POST /v1/auth/refresh-tokens handler (+15) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; use functions beyond their role | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Personal data (PII) | data | pii | MongoDB: User, MongoDB: Token | auth.service, POST /v1/auth/login handler, passport, email.service, user.service, POST /v1/auth/forgot-password handler, POST /v1/auth/register handler, token.service |
| User credentials | data | credential | MongoDB: User, MongoDB: Token | auth.service, POST /v1/auth/logout handler, POST /v1/auth/refresh-tokens handler, POST /v1/auth/login handler, passport, POST /v1/auth/reset-password handler, user.service, POST /v1/auth/verify-email handler (+2) |
