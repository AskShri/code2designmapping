# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|
| Insider with access to container: currencyservice | Secret ALLOYDB_SECRET_NAME | gRPC Health handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: OTLP collector | Secret ALLOYDB_SECRET_NAME | OTLP collector -> productcatalogservice -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: shippingservice | Secret ALLOYDB_SECRET_NAME | gRPC Health handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: adservice | Secret ALLOYDB_SECRET_NAME | gRPC AdService handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Anonymous GRPC caller | Secret ALLOYDB_SECRET_NAME | gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: checkoutservice | Secret ALLOYDB_SECRET_NAME | gRPC Health handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Anonymous HTTP caller | Secret ALLOYDB_SECRET_NAME | HTTP client -> POST / handler -> Postgres -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: shoppingassistantservice | Secret ALLOYDB_SECRET_NAME | shoppingassistantservice -> Postgres -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Cloud APIs | Secret ALLOYDB_SECRET_NAME | Google Cloud APIs -> shoppingassistantservice -> Postgres -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Gemini API | Secret ALLOYDB_SECRET_NAME | Google Gemini API -> POST / handler -> Postgres -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: emailservice | Secret ALLOYDB_SECRET_NAME | gRPC EmailService handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: productcatalogservice | Secret ALLOYDB_SECRET_NAME | catalog_loader (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to container: cartservice | Secret ALLOYDB_SECRET_NAME | gRPC CartService handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Cloud Profiler | Secret ALLOYDB_SECRET_NAME | Google Cloud Profiler -> productcatalogservice -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: frontend | Secret ALLOYDB_SECRET_NAME | GET /assistant handler -> HTTP client -> POST / handler -> Postgres -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: paymentservice | Secret ALLOYDB_SECRET_NAME | gRPC Health handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: recommendationservice | Secret ALLOYDB_SECRET_NAME | gRPC RecommendationService handler -> gRPC client -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved grpc target | Secret ALLOYDB_SECRET_NAME | Unresolved grpc target -> productcatalogservice -> gRPC ProductCatalogService handler -> catalog_loader | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to container: loadgenerator | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent |
| Insider with access to repository: microservices-demo | Secret ALLOYDB_SECRET_NAME | no path | - | - | unreachable from this agent |

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Insider with access to container: currencyservice | insider | container: currencyservice | gRPC Health handler, gRPC CurrencyService handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: OTLP collector | third_party | outside all boundaries | OTLP collector | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: loadgenerator | insider | container: loadgenerator | loadgenerator | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to container: shippingservice | insider | container: shippingservice | shippingservice, gRPC Health handler, gRPC ShippingService handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to repository: microservices-demo | insider | repository: microservices-demo | kustomize | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to container: adservice | insider | container: adservice | gRPC AdService handler, AdServiceClient | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Anonymous GRPC caller | anonymous | outside all boundaries | gRPC client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: checkoutservice | insider | container: checkoutservice | gRPC Health handler, checkoutservice, gRPC CheckoutService handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: shoppingassistantservice | insider | container: shoppingassistantservice | shoppingassistantservice, POST / handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: Google Cloud APIs | third_party | outside all boundaries | Google Cloud APIs | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Google Gemini API | third_party | outside all boundaries | Google Gemini API | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: emailservice | insider | container: emailservice | gRPC EmailService handler, gRPC Health handler, email_server | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to container: productcatalogservice | insider | container: productcatalogservice | catalog_loader, productcatalogservice, gRPC ProductCatalogService handler, gRPC Health handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to container: cartservice | insider | container: cartservice | gRPC CartService handler, GET / handler, RedisCartStore | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: Google Cloud Profiler | third_party | outside all boundaries | Google Cloud Profiler | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: frontend | insider | container: frontend | GET /assistant handler, POST /cart/checkout handler, POST /cart handler, GET /cart handler, POST /bot handler ... | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to container: paymentservice | insider | container: paymentservice | gRPC Health handler, gRPC PaymentService handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to container: recommendationservice | insider | container: recommendationservice | gRPC RecommendationService handler, client, recommendation_server, gRPC Health handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: Unresolved grpc target | third_party | outside all boundaries | Unresolved grpc target | - | return malicious responses; harvest data sent to it | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret ALLOYDB_SECRET_NAME | credential | secret | catalog_loader | catalog_loader |
