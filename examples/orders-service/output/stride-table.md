# STRIDE per element: orders-service

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| Stripe API | External entity | S R | - | - | - | outbound dependency; API key STRIPE_SECRET_KEY read from env (src/payments/stripe.ts:3); confirm secret storage and timeouts |
| API client (JWT bearer) | External entity | S R | - | - | - | inbound caller; verify JWT issuer, audience and expiry in requireJwt |
| Redis: order:* | Data store | T R I D | pii, financial | in container: cache | none detected (encryption at rest unknown) | holds pii+financial; confirm encryption at rest and retention |
| Postgres: orders | Data store | T R I D | pii, financial | in container: db | none detected (encryption at rest unknown) | holds pii+financial; confirm encryption at rest and retention |
| STRIPE_SECRET_KEY read at module import | Weakness | - | - | - | - | secret_in_env_at_import at src/payments/stripe.ts:3; applies to Stripe API |
| charge card -> Stripe API | Data flow | T I D | financial | container: api | none | EXIT POINT: sensitive data leaves the system; crosses boundary without a control |
| Redis: order:* -> get order | Data flow | T I D | pii, financial | container: cache, container: api | none | crosses boundary without a control; authentication=unknown, encryption=unknown: question for the team |
| create order -> Redis: order:* | Data flow | T I D | pii, financial | container: api, container: cache | none | crosses boundary without a control; authentication=unknown, encryption=unknown: question for the team |
| Postgres: orders -> get order | Data flow | T I D | pii, financial | container: db, container: api | none | crosses boundary without a control; authentication=unknown, encryption=unknown: question for the team |
| create order -> Postgres: orders | Data flow | T I D | pii, financial | container: api, container: db | none | crosses boundary without a control; authentication=unknown, encryption=unknown: question for the team |
| POST /orders handler | Process | S T R I D E | - | - | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | entry point |
| get order | Process | S T R I D E | - | - | n/a (internal) |  |
| create order | Process | S T R I D E | - | - | n/a (internal) |  |
| charge card | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /orders/:id handler | Process | S T R I D E | - | - | JWT bearer (requireJwt), rate limit 100/min | entry point |
| API client (JWT bearer) -> POST /orders handler | Data flow | T I D | pii, financial | container: api | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest |  |
| API client (JWT bearer) -> GET /orders/:id handler | Data flow | T I D | internal | container: api | JWT bearer (requireJwt), rate limit 100/min |  |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | POST /orders handler, create order, get order | Postgres: orders, Redis: order:* | - |
| financial | POST /orders handler, charge card, create order, get order | Postgres: orders, Redis: order:* | Stripe API |
