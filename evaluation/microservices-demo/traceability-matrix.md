# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Compromised external service | Secret ALLOYDB_SECRET_NAME | Google Gemini API -> POST / handler -> Postgres -> catalog_loader | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: shoppingassistantservice | Secret ALLOYDB_SECRET_NAME | shoppingassistantservice (nbwu) -> Postgres -> catalog_loader | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: productcatalogservice | Secret ALLOYDB_SECRET_NAME | catalog_loader (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to container: currencyservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: currencyservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: loadgenerator | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: loadgenerator | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: shippingservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: shippingservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: microservices-demo | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: microservices-demo | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: adservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: adservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: checkoutservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: checkoutservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: shoppingassistantservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: emailservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: emailservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: productcatalogservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: cartservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: cartservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling gRPC client endpoints | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling gRPC client endpoints | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: frontend | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: frontend | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: paymentservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: paymentservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: recommendationservice | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: recommendationservice | Secret SPANNER_CONNECTION_STRING | no path | - | - | unreachable from this agent over the modelled flows |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Insider with access to container: currencyservice | insider | container: currencyservice | grpc gRPC CurrencyService handler (+1 routes) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Compromised external service | third_party | outside all boundaries | OTLP collector, Google Gemini API, Google Cloud APIs, Google Cloud Profiler, Unresolved grpc target | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: loadgenerator | insider | container: loadgenerator | loadgenerator | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to container: shippingservice | insider | container: shippingservice | shippingservice (txxh), grpc gRPC Health handler (+1 routes) (xrau) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to repository: microservices-demo | insider | repository: microservices-demo | kustomize | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Workload inside the deployment calling HTTP client endpoints | insider | outside all boundaries | Internal HTTP client | - | call internal services directly | inferred |
| Insider with access to container: adservice | insider | container: adservice | gRPC Health handler (a67s), gRPC AdService handler, AdServiceClient | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to container: checkoutservice | insider | container: checkoutservice | checkoutservice (3a2t), grpc gRPC CheckoutService handler (+1 routes) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: shoppingassistantservice | insider | container: shoppingassistantservice | shoppingassistantservice (nbwu), POST / handler | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to container: emailservice | insider | container: emailservice | grpc gRPC EmailService handler (+1 routes), email_server | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to container: productcatalogservice | insider | container: productcatalogservice | productcatalogservice (bd4e), catalog_loader, grpc gRPC Health handler (+1 routes) (q4dl) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to container: cartservice | insider | container: cartservice | gRPC CartService handler, RedisCartStore, GET / handler (myck), gRPC Health handler (qidx) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Workload inside the deployment calling gRPC client endpoints | insider | outside all boundaries | Internal gRPC client | - | call internal services directly | inferred |
| Insider with access to container: frontend | insider | container: frontend | GET /assistant handler, POST /cart/checkout handler, POST /cart handler, GET /product/{id} handler, GET /product-meta/{ids} handler (+10) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to container: paymentservice | insider | container: paymentservice | grpc gRPC Health handler (+1 routes) (iw3v) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Insider with access to container: recommendationservice | insider | container: recommendationservice | client, grpc gRPC Health handler (+1 routes) (jhqd), recommendation_server | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret ALLOYDB_SECRET_NAME | credential | secret | catalog_loader | catalog_loader |
| Secret SPANNER_CONNECTION_STRING | credential | secret | cartservice | cartservice |
