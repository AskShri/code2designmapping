# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|
| Anonymous HTTP caller | Secret STRIPE_SECRET_KEY | HTTP client -> POST /create-checkout-session handler -> Stripe API -> python | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Anonymous HTTP caller | Secret STRIPE_WEBHOOK_SECRET | HTTP client -> POST /create-checkout-session handler -> Stripe API -> route | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret STRIPE_SECRET_KEY | Stripe API -> python | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret STRIPE_WEBHOOK_SECRET | Stripe API -> route | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: stripe-checkout-sample | Secret STRIPE_SECRET_KEY | node (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to repository: stripe-checkout-sample | Secret STRIPE_WEBHOOK_SECRET | node (inside) | none | none | agent starts at the asset holder: no control can apply |
| Compromised third party: Unresolved HTTP target | Secret STRIPE_SECRET_KEY | no path | - | - | unreachable from this agent |
| Compromised third party: Unresolved HTTP target | Secret STRIPE_WEBHOOK_SECRET | no path | - | - | unreachable from this agent |

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Compromised third party: Unresolved HTTP target | third_party | outside all boundaries | Unresolved HTTP target | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Stripe API | third_party | outside all boundaries | Stripe API | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to repository: stripe-checkout-sample | insider | repository: stripe-checkout-sample | POST /create-checkout-session handler, POST /create-checkout-session handler, node, GET / handler, POST /webhook handler ... | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret STRIPE_SECRET_KEY | credential | secret | stripe, node, python | stripe, node, python |
| Secret STRIPE_WEBHOOK_SECRET | credential | secret | route, node, python | route, node, python |
