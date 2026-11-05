# code2design report: orders-service-example

Commit `05fad9d339c8`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| typescript | 8 |
| (test files skipped) | 0 |

Detectors that ran: config@0.3, js@0.3

Facts: app_entry 1, boundary_hint 4, config_value 1, control 2, dependencies 1, entry_point 2, listener 1, module 1, outbound_call 2, router_mount 1, schema 3, store_access 8

## Model

| Collection | Count |
|---|---|
| processes | 9 |
| entities | 2 |
| stores | 2 |
| boundaries | 3 |
| flows | 10 |
| entry_points | 2 |
| controls | 2 |
| weaknesses | 1 |
| schemas | 3 |
| assets | 3 |
| threat_agents | 4 |
| gaps | 3 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 2 entry points, 0 without a detected authn control
- **listeners**: src/index.ts port 8080
- **exit points carrying sensitive data**: Stripe API
- **third-party dependencies**: 7 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| GET /orders/:id | requireJwt, rateLimit |
| POST /orders | requireJwt, rateLimit |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |
| Stripe API | system | api.stripe.com |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| Postgres: orders | postgres | financial, pii | container: db |
| Redis: order:* | redis | financial, pii | container: cache |

## Lint

- **warning** `unknown-link-attributes` Postgres: orders -> service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Redis: order:* -> service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` service -> Postgres: orders: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` service -> Redis: order:*: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- Anonymous HTTP caller (confidence 0.9): 2 http entry points, 0 without a detected authn control
- Compromised third party: Stripe API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: api (confidence 0.8): one insider agent per trust boundary, placed inside it
- Authenticated HTTP caller (confidence 0.9): authn controls exist on some entry points; a valid credential holder is a distinct agent

## Gaps and questions

- `unknown_attribute` src/index.ts: Question for the team: is TLS terminated in front of the HTTP listener on port 8080? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/orders/service.ts:13: Question for the team: how is the link to Postgres: orders authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/orders/service.ts:17: Question for the team: how is the link to Redis: order:* authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
