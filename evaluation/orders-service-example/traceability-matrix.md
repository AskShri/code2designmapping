# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|
| Compromised third party: Stripe API | Secret STRIPE_SECRET_KEY | Stripe Payments API -> stripe | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Personal data (PII) | Stripe Payments API -> stripe -> service -> Postgres: orders | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Financial data | Stripe Payments API -> stripe -> service -> Postgres: orders | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: api | Secret STRIPE_SECRET_KEY | stripe (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to container: api | Personal data (PII) | service -> Postgres: orders | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: api | Financial data | service -> Postgres: orders | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Rogue merchant operator | Secret STRIPE_SECRET_KEY | POST /orders handler -> stripe | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Rogue merchant operator | Personal data (PII) | POST /orders handler -> service -> Postgres: orders | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Rogue merchant operator | Financial data | POST /orders handler -> service -> Postgres: orders | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Anonymous HTTP caller | Secret STRIPE_SECRET_KEY | HTTP client -> POST /orders handler -> stripe | requireJwt, rateLimit | requireJwt, rateLimit | controlled at entry; HTTP client -> POST /orders handler: unknown encryption |
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> GET /orders/:id handler -> service -> Postgres: orders | requireJwt, rateLimit | requireJwt, rateLimit | controlled at entry; HTTP client -> GET /orders/:id handler: unknown encryption; Postgres: orders -> service: unknown authentication and encryption |
| Anonymous HTTP caller | Financial data | HTTP client -> GET /orders/:id handler -> service -> Postgres: orders | requireJwt, rateLimit | requireJwt, rateLimit | controlled at entry; HTTP client -> GET /orders/:id handler: unknown encryption; Postgres: orders -> service: unknown authentication and encryption |
| Authenticated HTTP caller | Secret STRIPE_SECRET_KEY | HTTP client -> POST /orders handler -> stripe | requireJwt, rateLimit | rateLimit | controlled at entry; HTTP client -> POST /orders handler: unknown encryption |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> GET /orders/:id handler -> service -> Postgres: orders | requireJwt, rateLimit | rateLimit | controlled at entry; HTTP client -> GET /orders/:id handler: unknown encryption; Postgres: orders -> service: unknown authentication and encryption |
| Authenticated HTTP caller | Financial data | HTTP client -> GET /orders/:id handler -> service -> Postgres: orders | requireJwt, rateLimit | rateLimit | controlled at entry; HTTP client -> GET /orders/:id handler: unknown encryption; Postgres: orders -> service: unknown authentication and encryption |

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Compromised third party: Stripe API | third_party | outside all boundaries | Stripe Payments API | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: api | insider | container: api | GET /orders/:id handler, service, stripe, POST /orders handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Rogue merchant operator | insider | outside all boundaries | POST /orders handler | authn, rate_limit | create fraudulent orders | declared |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; abuse privileged functions | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret STRIPE_SECRET_KEY | credential | secret | stripe | stripe |
| Personal data (PII) | data | pii | Postgres: orders, Redis: order:* | service, stripe, POST /orders handler |
| Financial data | data | financial | Postgres: orders, Redis: order:* | service, stripe, POST /orders handler |
