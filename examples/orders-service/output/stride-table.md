# STRIDE per element: orders-service

Rows are ordered by priority hint (flagged items first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| Stripe API | External entity | S R | - | - | - | outbound dependency; API key STRIPE_SECRET_KEY read from env (src/payments/stripe.ts:3); confirm secret storage and timeouts |
| API client (JWT bearer) | External entity | S R | - | - | - | inbound caller; verify JWT issuer, audience and expiry in requireJwt |
| Redis: order:* | Data store | T R I D | pii, financial | in container: cache | none detected (encryption at rest unknown) | holds pii+financial; confirm encryption at rest and retention |
| Postgres: orders | Data store | T R I D | pii, financial | in container: db | none detected (encryption at rest unknown) | holds pii+financial; confirm encryption at rest and retention |
| charge card -> Stripe API | Data flow | T I D | financial | container: api | none | crosses boundary without a control |
| Redis: order:* -> get order | Data flow | T I D | pii, financial | container: cache, container: api | none | crosses boundary without a control; sensitive data over redis; confirm TLS on the link |
| create order -> Redis: order:* | Data flow | T I D | pii, financial | container: api, container: cache | none | crosses boundary without a control; sensitive data over redis; confirm TLS on the link |
| Postgres: orders -> get order | Data flow | T I D | pii, financial | container: db, container: api | none | crosses boundary without a control; sensitive data over sql; confirm TLS on the link |
| create order -> Postgres: orders | Data flow | T I D | pii, financial | container: api, container: db | none | crosses boundary without a control; sensitive data over sql; confirm TLS on the link |
| POST /orders handler | Process | S T R I D E | - | - | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest | entry point |
| get order | Process | S T R I D E | - | - | n/a (internal) |  |
| create order | Process | S T R I D E | - | - | n/a (internal) |  |
| charge card | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /orders/:id handler | Process | S T R I D E | - | - | JWT bearer (requireJwt), rate limit 100/min | entry point |
| API client (JWT bearer) -> POST /orders handler | Data flow | T I D | pii, financial | container: api | JWT bearer (requireJwt), rate limit 100/min, zod CreateOrderRequest |  |
| API client (JWT bearer) -> GET /orders/:id handler | Data flow | T I D | internal | container: api | JWT bearer (requireJwt), rate limit 100/min |  |
