# code2design report: orders-service

Commit `24d7ae35ccec`, code2design 0.5.2, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| typescript | 8 |
| (test files, not modelled) | 0 |

Detectors: config@0.5, js@0.5, synth@0.5.2

Facts: app 1, boundary_hint 4, config_value 1, control 3, declared_link 2, dependencies 1, entry_point 2, listener 1, module 1, outbound_call 2, router 2, router_mount 1, schema 3, store_access 8

## Model

| Collection | Count |
|---|---|
| processes | 9 |
| entities | 2 |
| stores | 2 |
| boundaries | 3 |
| flows | 11 |
| entry_points | 2 |
| controls | 3 |
| weaknesses | 0 |
| schemas | 3 |
| assets | 3 |
| threat_agents | 5 |
| gaps | 5 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 2 entry points, 0 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: src/index.ts port 8080
- **exit points carrying sensitive data**: Stripe Payments API
- **third-party dependencies**: 7 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /orders/{id} | public | requireJwt, rateLimit | Postgres: orders, Redis: order:* |
| POST /orders | public | requireJwt, rateLimit, CreateOrderRequest.parse | Stripe Payments API, Postgres: orders, Redis: order:* |

### Weaknesses

None detected.

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |
| Stripe Payments API | system | api.stripe.com |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| Postgres: orders | postgres | financial, pii | yes | container: db |
| Redis: order:* | redis | financial, pii | unknown | container: cache |

## Lint

- **info** `unknown-link-attributes` service -> Redis: order:*: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: orders -> service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` service -> Postgres: orders: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Redis: order:* -> service: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- Compromised external service (confidence 0.7): each of the 1 outbound dependencies is a potentially hostile responder
- Anonymous HTTP caller (confidence 0.9): 2 entry points are reachable from outside, 0 of them without a detected authentication control
- Insider with access to container: api (confidence 0.8): one insider agent per trust boundary, placed inside it
- Authenticated HTTP caller (confidence 0.9): 2 entry points require authentication; a holder of valid credentials is a distinct agent

## Gaps and questions

- `unknown_attribute` src/index.ts: Question: is TLS terminated in front of the HTTP listener of api? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/orders/service.ts:17: Question: what is the authentication and encryption of the link to Redis: order:*?
- `unknown_attribute` src/orders/service.ts:24: Question: what is the authentication and encryption of the link to Postgres: orders?
- `unknown_attribute` src/orders/service.ts:17: Question: is Redis: order:* encrypted at rest? It holds financial, pii.
- `override_target_missing` .code2design/overrides.yaml: set_attribute override targets 'service -> Postgres: orders' which does not exist in the model
