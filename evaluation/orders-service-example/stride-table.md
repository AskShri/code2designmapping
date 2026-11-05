# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| STRIPE_SECRET_KEY read at module import | Weakness | - | - | - | - | secret_in_env_at_import at src/payments/stripe.ts:3 |
| stripe -> Stripe Payments API | Data flow | T I D | financial, pii | container: api | none | EXIT POINT: sensitive data leaves the system |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| Stripe Payments API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Postgres: orders | Data store | T R I D | financial, pii | in container: db | encryption at rest: yes | holds sensitive data; confirm encryption at rest, access control and retention |
| Redis: order:* | Data store | T R I D | financial, pii | in container: cache | encryption at rest: unknown | holds sensitive data; confirm encryption at rest, access control and retention |
| HTTP client -> GET /orders/:id handler | Data flow | T I D | - | container: api | requireJwt, rateLimit | authentication=token, encryption=unknown: question for the team |
| Postgres: orders -> service | Data flow | T I D | financial, pii | container: db, container: api | none | authentication=unknown, encryption=unknown: question for the team |
| Redis: order:* -> service | Data flow | T I D | financial, pii | container: cache, container: api | none | authentication=unknown, encryption=unknown: question for the team |
| service -> Postgres: orders | Data flow | T I D | financial, pii | container: db, container: api | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /orders handler | Data flow | T I D | financial, pii | container: api | requireJwt, rateLimit | authentication=token, encryption=unknown: question for the team |
| service -> Redis: order:* | Data flow | T I D | financial, pii | container: cache, container: api | none | authentication=unknown, encryption=unknown: question for the team |
| GET /orders/:id handler | Process | S T R I D E | - | - | requireJwt, rateLimit | entry point |
| service | Process | S T R I D E | - | - | n/a (internal) |  |
| stripe | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /orders handler | Process | S T R I D E | - | - | requireJwt, rateLimit | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | service, stripe, POST /orders handler | Postgres: orders, Redis: order:* | Stripe Payments API |
| financial | service, stripe, POST /orders handler | Postgres: orders, Redis: order:* | Stripe Payments API |
