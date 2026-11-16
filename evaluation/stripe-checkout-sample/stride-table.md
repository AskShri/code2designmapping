# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| debug=True on the application server | Weakness (medium) | I E | - | - | python (zyjt) | CWE-489 Debug mode enabled on the application server at server/python/server.py:119 |
| HTTP client -> ANY /webhook handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /config handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY /config handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY / handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Success -> Unresolved HTTP target | Data flow | T I D | - | repository: stripe-checkout-sample | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /create-checkout-session handler | Data flow | T I D | internal | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY /create-checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /checkout-session handler | Data flow | T I D | internal | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| success -> Unresolved HTTP target | Data flow | T I D | - | repository: stripe-checkout-sample | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /webhook handler | Data flow | T I D | internal | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> ANY /checkout-session handler | Data flow | T I D | - | repository: stripe-checkout-sample | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Stripe API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| GET /config handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| GET /checkout-session handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| POST /create-checkout-session handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| POST /webhook handler -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| python (zyjt) -> Stripe API | Data flow | T I D | - | repository: stripe-checkout-sample | none |  |
| GET /checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| ANY / handler | Process | S T R I D E | - | - | none | entry point |
| ANY /create-checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| ANY /config handler | Process | S T R I D E | - | - | none | entry point |
| POST /create-checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| GET /config handler | Process | S T R I D E | - | - | none | entry point |
| Success | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| success | Process | S T R I D E | - | - | n/a (internal) |  |
| ANY /webhook handler | Process | S T R I D E | - | - | none | entry point |
| ANY /checkout-session handler | Process | S T R I D E | - | - | none | entry point |
| POST /webhook handler | Process | S T R I D E | - | - | none | entry point |
| python | Process | S T R I D E | - | - | n/a (internal) |  |
| no authentication control detected on POST /create-checkout-session | Weakness (info) | S E | - | - | ep:5rzlb7yz4i | CWE-306 Entry point without a detected authentication control (review) at server/node/server.js:60 |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:bbk22lbk2b | CWE-306 Entry point without a detected authentication control (review) at server/node/server.js:38 |
| no authentication control detected on GET /checkout-session | Weakness (info) | S E | - | - | ep:irrtw4xj3x | CWE-306 Entry point without a detected authentication control (review) at server/node/server.js:54 |
| no authentication control detected on ANY /checkout-session | Weakness (info) | S E | - | - | ep:s4haugkxfl | CWE-306 Entry point without a detected authentication control (review) at server/go/server.go:44 |
| no authentication control detected on POST /webhook | Weakness (info) | S E | - | - | ep:wrsx7evara | CWE-306 Entry point without a detected authentication control (review) at server/node/server.js:89 |
| no authentication control detected on ANY / | Weakness (info) | S E | - | - | ep:qwm3k5h7ze | CWE-306 Entry point without a detected authentication control (review) at server/go/server.go:42 |
| no authentication control detected on GET /config | Weakness (info) | S E | - | - | ep:4oobveqi2u | CWE-306 Entry point without a detected authentication control (review) at server/node/server.js:43 |
| no authentication control detected on ANY /create-checkout-session | Weakness (info) | S E | - | - | ep:2t2seq4rhy | CWE-306 Entry point without a detected authentication control (review) at server/go/server.go:45 |
| no authentication control detected on ANY /config | Weakness (info) | S E | - | - | ep:fp4upbmx3t | CWE-306 Entry point without a detected authentication control (review) at server/go/server.go:43 |
| no authentication control detected on ANY /webhook | Weakness (info) | S E | - | - | ep:7nwykl3h2f | CWE-306 Entry point without a detected authentication control (review) at server/go/server.go:46 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
