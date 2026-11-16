# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Compromised external service | Secret STRIPE_SECRET_KEY | Stripe Payments API -> stripe | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Personal data (PII) | Stripe Payments API -> stripe -> service -> Postgres: orders | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Financial data | Stripe Payments API -> stripe -> service -> Postgres: orders | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: api | Secret STRIPE_SECRET_KEY | stripe (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to container: api | Personal data (PII) | service -> Postgres: orders | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: api | Financial data | service -> Postgres: orders | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Rogue merchant operator | Secret STRIPE_SECRET_KEY | POST /orders handler -> stripe | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Rogue merchant operator | Personal data (PII) | POST /orders handler -> service -> Postgres: orders | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Rogue merchant operator | Financial data | POST /orders handler -> service -> Postgres: orders | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret STRIPE_SECRET_KEY | HTTP client -> POST /orders handler -> stripe | none | requireJwt, rateLimit, CreateOrderRequest.parse | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> POST /orders handler -> service -> Postgres: orders | none | requireJwt, rateLimit, CreateOrderRequest.parse | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Financial data | HTTP client -> POST /orders handler -> service -> Postgres: orders | none | requireJwt, rateLimit, CreateOrderRequest.parse | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Anonymous HTTP caller | Secret STRIPE_SECRET_KEY | HTTP client -> POST /orders handler -> stripe | requireJwt | rateLimit, CreateOrderRequest.parse | blocked at entry; unanswered: HTTP client -> POST /orders handler encryption |
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> POST /orders handler -> service -> Postgres: orders | requireJwt | rateLimit, CreateOrderRequest.parse | blocked at entry; unanswered: HTTP client -> POST /orders handler encryption; Postgres: orders -> service authentication and encryption |
| Anonymous HTTP caller | Financial data | HTTP client -> POST /orders handler -> service -> Postgres: orders | requireJwt | rateLimit, CreateOrderRequest.parse | blocked at entry; unanswered: HTTP client -> POST /orders handler encryption; Postgres: orders -> service authentication and encryption |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | Stripe Payments API | - | return malicious responses; harvest data sent to it | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: api | insider | container: api | stripe, POST /orders handler, service, GET /orders/{id} handler | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Rogue merchant operator | insider | outside all boundaries | POST /orders handler | authn, rate_limit | create fraudulent orders | declared |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; use functions beyond their role | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret STRIPE_SECRET_KEY | credential | secret | stripe | stripe |
| Personal data (PII) | data | pii | Postgres: orders, Redis: order:* | stripe, POST /orders handler, service |
| Financial data | data | financial | Postgres: orders, Redis: order:* | stripe, POST /orders handler, service |
