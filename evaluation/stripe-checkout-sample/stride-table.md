# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on POST /webhook | Weakness | - | - | - | - | unauthenticated_entry_point at server/python/server.py:88 |
| STRIPE_SECRET_KEY read at module import | Weakness | - | - | - | - | secret_in_env_at_import at server/nextjs/lib/stripe.ts:8 |
| no authn control detected on ANY / | Weakness | - | - | - | - | unauthenticated_entry_point at server/go/server.go:42 |
| no authn control detected on GET /config | Weakness | - | - | - | - | unauthenticated_entry_point at server/python/server.py:41 |
| no authn control detected on GET /checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/dotnet/Program.cs:61 |
| no authn control detected on POST /webhook | Weakness | - | - | - | - | unauthenticated_entry_point at server/node/server.js:89 |
| no authn control detected on GET /checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/python/server.py:51 |
| no authn control detected on POST /create-checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/dotnet/Program.cs:68 |
| no authn control detected on ANY /webhook | Weakness | - | - | - | - | unauthenticated_entry_point at server/go/server.go:46 |
| STRIPE_SECRET_KEY read at module import | Weakness | - | - | - | - | secret_in_env_at_import at server/node/server.js:15 |
| no authn control detected on POST webhook | Weakness | - | - | - | - | unauthenticated_entry_point at server/dotnet/Program.cs:90 |
| no authn control detected on GET /config | Weakness | - | - | - | - | unauthenticated_entry_point at server/node/server.js:43 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at server/python/server.py:36 |
| no authn control detected on ANY /checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/go/server.go:44 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at server/node/server.js:38 |
| no authn control detected on ANY /create-checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/go/server.go:45 |
| no authn control detected on ANY /config | Weakness | - | - | - | - | unauthenticated_entry_point at server/go/server.go:43 |
| no authn control detected on GET /config | Weakness | - | - | - | - | unauthenticated_entry_point at server/dotnet/Program.cs:48 |
| no authn control detected on POST /create-checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/node/server.js:60 |
| no authn control detected on GET /checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/node/server.js:54 |
| STRIPE_SECRET_KEY read at module import | Weakness | - | - | - | - | secret_in_env_at_import at server/python/server.py:28 |
| no authn control detected on POST /create-checkout-session | Weakness | - | - | - | - | unauthenticated_entry_point at server/python/server.py:58 |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| Stripe API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| HTTP client -> GET /config handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /create-checkout-session handler | Data flow | T I D | internal | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST webhook handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY /create-checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY / handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /config handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /checkout-session handler | Data flow | T I D | internal | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| Server -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none | authentication=unknown, encryption=tls: question for the team |
| success -> Unresolved HTTP target | Data flow | T I D | - | repository: stripe-checkout-sample | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> ANY /checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY /config handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| Success -> Unresolved HTTP target | Data flow | T I D | - | repository: stripe-checkout-sample | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /webhook handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /create-checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /config handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /webhook handler | Data flow | T I D | internal | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY /webhook handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /create-checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| GET /checkout-session handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| POST /create-checkout-session handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| GET /config handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| GET /config handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| stripe -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| GET /checkout-session handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| route -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| Program -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| POST /webhook handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| POST /webhook handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| POST /create-checkout-session handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| python -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| go -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| POST /create-checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| Program | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /create-checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| ANY /webhook handler | Process | S T R I D E | - | - | none | entry point |
| go | Process | S T R I D E | - | - | n/a (internal) |  |
| node | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| POST /webhook handler | Process | S T R I D E | - | - | none | entry point |
| POST webhook handler | Process | S T R I D E | - | - | none | entry point |
| route | Process | S T R I D E | - | - | n/a (internal) |  |
| python | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /create-checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| Success | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| ANY /config handler | Process | S T R I D E | - | - | none | entry point |
| success | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| GET /checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| ANY /create-checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| POST /webhook handler | Process | S T R I D E | - | - | none | entry point |
| GET /config handler | Process | S T R I D E | - | - | none | entry point |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| GET /config handler | Process | S T R I D E | - | - | none | entry point |
| Server | Process | S T R I D E | - | - | n/a (internal) |  |
| ANY / handler | Process | S T R I D E | - | - | none | entry point |
| GET /config handler | Process | S T R I D E | - | - | none | entry point |
| stripe | Process | S T R I D E | - | - | n/a (internal) |  |
| ANY /checkout-session handler | Process | S T R I D E | - | - | none | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
