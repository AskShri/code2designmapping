# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on POST /cart | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:153 |
| gRPC channel usePlaintext() | Weakness | - | - | - | - | unencrypted_transport at src/adservice/src/main/java/hipstershop/AdServiceClient.java:45 |
| no authn control detected on POST /bot | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:163 |
| no authn control detected on POST /cart/empty | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:154 |
| grpc.insecure_channel | Weakness | - | - | - | - | unencrypted_transport at src/recommendationservice/recommendation_server.py:135 |
| grpc.insecure_channel | Weakness | - | - | - | - | unencrypted_transport at src/recommendationservice/client.py:33 |
| no authn control detected on POST /cart/checkout | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:157 |
| gRPC client with insecure credentials | Weakness | - | - | - | - | unencrypted_transport at src/productcatalogservice/server.go:212 |
| no authn control detected on GET /logout | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:156 |
| no authn control detected on GET /assistant | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:158 |
| no authn control detected on GET /cart | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:152 |
| no authn control detected on POST /setCurrency | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:155 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:150 |
| ALLOYDB_SECRET_NAME literal in Deployment shoppingassistants | Weakness | - | - | - | - | plaintext_credentials at kustomize/components/shopping-assistant/shoppingassistantservice.yaml:18 |
| gRPC client with insecure credentials | Weakness | - | - | - | - | unencrypted_transport at src/frontend/main.go:230 |
| gRPC client with insecure credentials | Weakness | - | - | - | - | unencrypted_transport at src/checkoutservice/main.go:215 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at src/cartservice/src/Startup.cs:77 |
| no authn control detected on GET /product-meta/{ids} | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:162 |
| no authn control detected on POST / | Weakness | - | - | - | - | unauthenticated_entry_point at src/shoppingassistantservice/shoppingassistantservice.py:65 |
| no authn control detected on GET /product/{id} | Weakness | - | - | - | - | unauthenticated_entry_point at src/frontend/main.go:151 |
| OTLP collector | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Google Gemini API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts (LLM API: check what data is sent) |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| gRPC client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| Google Cloud APIs | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Google Cloud Profiler | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Unresolved grpc target | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| rpc -> currencyservice | Data flow | T I D | - | container: currencyservice, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| checkoutservice -> cartservice | Data flow | T I D | - | container: cartservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| gRPC client -> gRPC EmailService handler | Data flow | T I D | - | container: emailservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| checkoutservice -> productcatalogservice | Data flow | T I D | - | container: productcatalogservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| gRPC client -> gRPC RecommendationService handler | Data flow | T I D | - | container: recommendationservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| POST / handler -> Google Gemini API | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /cart handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| productcatalogservice -> OTLP collector | Data flow | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| frontend -> OTLP collector | Data flow | T I D | - | container: frontend | none | authentication=unknown, encryption=tls: question for the team |
| checkoutservice -> paymentservice | Data flow | T I D | - | container: paymentservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| checkoutservice -> currencyservice | Data flow | T I D | - | container: checkoutservice, container: currencyservice | none | authentication=unknown, encryption=none: question for the team |
| gRPC client -> gRPC Health handler | Data flow | T I D | - | container: recommendationservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| frontend -> Google Cloud Profiler | Data flow | T I D | - | container: frontend | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: cartservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC AdService handler | Data flow | T I D | - | container: adservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| productcatalogservice -> Google Cloud Profiler | Data flow | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=tls: question for the team |
| rpc -> cartservice | Data flow | T I D | - | container: cartservice, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| gRPC client -> gRPC CurrencyService handler | Data flow | T I D | - | container: currencyservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| Redis -> RedisCartStore | Data flow | T I D | - | container: cartservice | none | authentication=unknown, encryption=unknown: question for the team |
| gRPC client -> gRPC Health handler | Data flow | T I D | - | container: shippingservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC Health handler | Data flow | T I D | - | container: currencyservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| recommendation_server -> OTLP collector | Data flow | T I D | - | container: recommendationservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> ANY /_healthz handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| rpc -> recommendationservice | Data flow | T I D | - | container: recommendationservice, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| gRPC client -> gRPC PaymentService handler | Data flow | T I D | - | container: paymentservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /cart/checkout handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| POST /cart/checkout handler -> checkoutservice | Data flow | T I D | - | container: checkoutservice, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| gRPC client -> gRPC ShippingService handler | Data flow | T I D | - | container: shippingservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /cart handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| checkoutservice -> Google Cloud Profiler | Data flow | T I D | - | container: checkoutservice | none | authentication=unknown, encryption=tls: question for the team |
| gRPC client -> gRPC Health handler | Data flow | T I D | - | container: checkoutservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| AdServiceClient -> Unresolved grpc target | Data flow | T I D | - | container: adservice | none | authentication=unknown, encryption=none: question for the team |
| checkoutservice -> OTLP collector | Data flow | T I D | - | container: checkoutservice | none | authentication=unknown, encryption=tls: question for the team |
| gRPC client -> gRPC CartService handler | Data flow | T I D | - | container: cartservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| rpc -> adservice | Data flow | T I D | - | container: adservice, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /bot handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| productcatalogservice -> Unresolved grpc target | Data flow | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=none: question for the team |
| shippingservice -> Google Cloud Profiler | Data flow | T I D | - | container: shippingservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /logout handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /product-meta/{ids} handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| Postgres -> catalog_loader | Data flow | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=unknown: question for the team |
| gRPC client -> gRPC ProductCatalogService handler | Data flow | T I D | - | container: productcatalogservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| checkoutservice -> emailservice | Data flow | T I D | - | container: checkoutservice, container: emailservice | none | authentication=unknown, encryption=none: question for the team |
| client -> Unresolved grpc target | Data flow | T I D | - | container: recommendationservice | none | authentication=unknown, encryption=none: question for the team |
| checkoutservice -> shippingservice | Data flow | T I D | - | container: shippingservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| rpc -> shippingservice | Data flow | T I D | - | container: shippingservice, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> ANY /robots.txt handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| Postgres -> POST / handler | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=unknown: question for the team |
| shoppingassistantservice -> Google Cloud APIs | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=tls: question for the team |
| gRPC client -> gRPC CheckoutService handler | Data flow | T I D | - | container: checkoutservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /setCurrency handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| Postgres -> shoppingassistantservice | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=unknown: question for the team |
| recommendation_server -> productcatalogservice | Data flow | T I D | - | container: productcatalogservice, container: recommendationservice | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> POST / handler | Data flow | T I D | - | container: shoppingassistantservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /cart/empty handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /assistant handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC Health handler | Data flow | T I D | - | container: paymentservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| RedisCartStore -> Redis | Data flow | T I D | - | container: cartservice | none | authentication=unknown, encryption=unknown: question for the team |
| email_server -> OTLP collector | Data flow | T I D | - | container: emailservice | none | authentication=unknown, encryption=tls: question for the team |
| rpc -> productcatalogservice | Data flow | T I D | - | container: productcatalogservice, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| gRPC client -> gRPC Health handler | Data flow | T I D | - | container: productcatalogservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /product/{id} handler | Data flow | T I D | - | container: frontend | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC Health handler | Data flow | T I D | - | container: emailservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| POST /bot handler -> shoppingassistantservice | Data flow | T I D | - | container: shoppingassistantservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| Postgres | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Redis | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| gRPC CartService handler | Process | S T R I D E | - | - | none | entry point |
| catalog_loader | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /assistant handler | Process | S T R I D E | - | - | none | entry point |
| shippingservice | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC RecommendationService handler | Process | S T R I D E | - | - | none | entry point |
| gRPC Health handler | Process | S T R I D E | - | - | none | entry point |
| POST /cart/checkout handler | Process | S T R I D E | - | - | none | entry point |
| gRPC Health handler | Process | S T R I D E | - | - | none | entry point |
| POST /cart handler | Process | S T R I D E | - | - | none | entry point |
| shoppingassistantservice | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC EmailService handler | Process | S T R I D E | - | - | none | entry point |
| GET /cart handler | Process | S T R I D E | - | - | none | entry point |
| POST /bot handler | Process | S T R I D E | - | - | none | entry point |
| productcatalogservice | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| ANY /_healthz handler | Process | S T R I D E | - | - | none | entry point |
| gRPC Health handler | Process | S T R I D E | - | - | none | entry point |
| RedisCartStore | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /logout handler | Process | S T R I D E | - | - | none | entry point |
| frontend | Process | S T R I D E | - | - | n/a (internal) |  |
| ANY /robots.txt handler | Process | S T R I D E | - | - | none | entry point |
| POST /setCurrency handler | Process | S T R I D E | - | - | none | entry point |
| client | Process | S T R I D E | - | - | n/a (internal) |  |
| checkoutservice | Process | S T R I D E | - | - | n/a (internal) |  |
| recommendation_server | Process | S T R I D E | - | - | n/a (internal) |  |
| rpc | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC CheckoutService handler | Process | S T R I D E | - | - | none | entry point |
| gRPC PaymentService handler | Process | S T R I D E | - | - | none | entry point |
| gRPC Health handler | Process | S T R I D E | - | - | none | entry point |
| gRPC AdService handler | Process | S T R I D E | - | - | none | entry point |
| GET /product/{id} handler | Process | S T R I D E | - | - | none | entry point |
| POST /cart/empty handler | Process | S T R I D E | - | - | none | entry point |
| handlers | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /product-meta/{ids} handler | Process | S T R I D E | - | - | none | entry point |
| POST / handler | Process | S T R I D E | - | - | none | entry point |
| gRPC Health handler | Process | S T R I D E | - | - | none | entry point |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| gRPC ProductCatalogService handler | Process | S T R I D E | - | - | none | entry point |
| gRPC ShippingService handler | Process | S T R I D E | - | - | none | entry point |
| gRPC Health handler | Process | S T R I D E | - | - | none | entry point |
| gRPC CurrencyService handler | Process | S T R I D E | - | - | none | entry point |
| AdServiceClient | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC Health handler | Process | S T R I D E | - | - | none | entry point |
| email_server | Process | S T R I D E | - | - | n/a (internal) |  |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
