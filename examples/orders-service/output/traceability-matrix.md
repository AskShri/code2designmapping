# Control-path traceability matrix: orders-service

One row per (threat agent, asset) pair. The path is the shortest route over the data flows from where the agent starts to an element that holds or processes the asset. 'Effective controls' excludes controls the agent legitimately passes (an authenticated client passes authn). Rows are ordered worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|
| Insider or attacker with api container access | Stripe secret key | charge card (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider or attacker with api container access | Customer PII (email, shipping address) | get order -> Redis: order:* | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider or attacker with api container access | Payment data (card token, amounts, charge ids) | get order -> Redis: order:* | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised or malicious third party (Stripe API) | Stripe secret key | Stripe API -> charge card | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised or malicious third party (Stripe API) | Customer PII (email, shipping address) | Stripe API -> charge card -> create order -> Redis: order:* | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised or malicious third party (Stripe API) | Payment data (card token, amounts, charge ids) | Stripe API -> charge card -> create order -> Redis: order:* | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Anonymous internet user | Customer PII (email, shipping address) | API client (JWT bearer) -> POST /orders handler -> create order -> Redis: order:* | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | controlled at entry; create order -> Redis: order:* link has unknown authentication/encryption |
| Anonymous internet user | Payment data (card token, amounts, charge ids) | API client (JWT bearer) -> POST /orders handler -> create order -> Redis: order:* | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | controlled at entry; create order -> Redis: order:* link has unknown authentication/encryption |
| Authenticated API client (valid JWT) | Customer PII (email, shipping address) | API client (JWT bearer) -> POST /orders handler -> create order -> Redis: order:* | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | rate limit 100/min, zod CreateOrderRequest | controlled at entry; create order -> Redis: order:* link has unknown authentication/encryption |
| Authenticated API client (valid JWT) | Payment data (card token, amounts, charge ids) | API client (JWT bearer) -> POST /orders handler -> create order -> Redis: order:* | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | rate limit 100/min, zod CreateOrderRequest | controlled at entry; create order -> Redis: order:* link has unknown authentication/encryption |
| Anonymous internet user | Stripe secret key | API client (JWT bearer) -> POST /orders handler -> create order -> charge card | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | controlled |
| Authenticated API client (valid JWT) | Stripe secret key | API client (JWT bearer) -> POST /orders handler -> create order -> charge card | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | rate limit 100/min, zod CreateOrderRequest | controlled |

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Anonymous internet user | anonymous | outside all boundaries | API client (JWT bearer) | - | read or alter other customers' orders; charge cards without authorization | inferred |
| Authenticated API client (valid JWT) | authenticated | outside all boundaries | API client (JWT bearer) | authn | access orders belonging to other users; abuse the charge path | inferred |
| Insider or attacker with api container access | insider | container: api | create order, get order, charge card | authn, rate_limit, input_validation | read the database directly; exfiltrate the Stripe key | inferred |
| Compromised or malicious third party (Stripe API) | third_party | outside all boundaries | Stripe API | - | return forged charge results; harvest card tokens | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Stripe secret key | credential | secret | charge card | charge card |
| Customer PII (email, shipping address) | data | pii | Postgres: orders, Redis: order:* | POST /orders handler, create order, get order |
| Payment data (card token, amounts, charge ids) | data | financial | Postgres: orders, Redis: order:* | POST /orders handler, create order, charge card, get order |
