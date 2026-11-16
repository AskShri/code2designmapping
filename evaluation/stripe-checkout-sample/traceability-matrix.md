# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Compromised external service | Secret STRIPE_SECRET_KEY | Stripe API -> python (zyjt) | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret STRIPE_WEBHOOK_SECRET | Stripe API -> python (zyjt) | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: stripe-checkout-sample | Secret STRIPE_SECRET_KEY | python (zyjt) (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to repository: stripe-checkout-sample | Secret STRIPE_WEBHOOK_SECRET | python (zyjt) (inside) | none | none | agent starts at the asset holder: no control can apply |
| Anonymous HTTP caller | Secret STRIPE_SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret STRIPE_WEBHOOK_SECRET | no path | - | - | unreachable from this agent over the modelled flows |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | Unresolved HTTP target, Stripe API | - | return malicious responses; harvest data sent to it | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to repository: stripe-checkout-sample | insider | repository: stripe-checkout-sample | GET /checkout-session handler, ANY / handler, ANY /create-checkout-session handler, ANY /config handler, POST /create-checkout-session handler (+8) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret STRIPE_SECRET_KEY | credential | secret | go, dotnet, nextjs, node, python (zyjt) | go, dotnet, nextjs, node, python (zyjt) |
| Secret STRIPE_WEBHOOK_SECRET | credential | secret | go, dotnet, nextjs, node, python (zyjt) | go, dotnet, nextjs, node, python (zyjt) |
