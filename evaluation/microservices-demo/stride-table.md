# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| ALLOYDB_SECRET_NAME literal in Deployment shoppingassistantservice | Weakness (high) | I E | - | - | microservices-demo | CWE-798 Hard-coded or committed credentials at kustomize/components/shopping-assistant/shoppingassistantservice.yaml:61 |
| GOOGLE_API_KEY literal in Deployment shoppingassistantservice | Weakness (high) | I E | - | - | microservices-demo | CWE-798 Hard-coded or committed credentials at kustomize/components/shopping-assistant/shoppingassistantservice.yaml:51 |
| grpc.insecure_channel | Weakness (medium) | T I | - | - | recommendation_server | CWE-319 Cleartext transport to a non-local host at src/recommendationservice/recommendation_server.py:135 |
| gRPC client with insecure credentials | Weakness (medium) | T I | - | - | frontend (s53a) | CWE-319 Cleartext transport to a non-local host at src/frontend/main.go:230 |
| gRPC client with insecure credentials | Weakness (medium) | T I | - | - | checkoutservice (3a2t) | CWE-319 Cleartext transport to a non-local host at src/checkoutservice/main.go:215 |
| gRPC client with insecure credentials | Weakness (medium) | T I | - | - | productcatalogservice (bd4e) | CWE-319 Cleartext transport to a non-local host at src/productcatalogservice/server.go:212 |
| grpc.insecure_channel | Weakness (medium) | T I | - | - | client | CWE-319 Cleartext transport to a non-local host at src/recommendationservice/client.py:33 |
| gRPC channel usePlaintext() | Weakness (medium) | T I | - | - | AdServiceClient | CWE-319 Cleartext transport to a non-local host at src/adservice/src/main/java/hipstershop/AdServiceClient.java:45 |
| rpc -> gRPC CartService handler | Data flow | T I D | - | container: cartservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| checkoutservice (3a2t) -> grpc gRPC Health handler (+1 routes) (q4dl) | Data flow | T I D | - | container: productcatalogservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> POST /cart/empty handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| frontend (s53a) -> Google Cloud Profiler | Data flow (inferred) | T I D | - | container: frontend | none | authentication=unknown, encryption=tls: question for the team |
| Internal HTTP client -> GET / handler (myck) | Data flow | T I D | - | container: cartservice | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| productcatalogservice (bd4e) -> Unresolved grpc target | Data flow | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> GET /product/{id} handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| checkoutservice (3a2t) -> grpc gRPC Health handler (+1 routes) (iw3v) | Data flow | T I D | - | container: paymentservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> ANY /_healthz handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| frontend (s53a) -> OTLP collector | Data flow (inferred) | T I D | - | container: frontend | none | authentication=unknown, encryption=tls: question for the team |
| rpc -> grpc gRPC CurrencyService handler (+1 routes) | Data flow | T I D | - | container: currencyservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> GET /logout handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| recommendation_server -> productcatalogservice (66kd) | Data flow | T I D | - | container: productcatalogservice, container: recommendationservice | none | authentication=unknown, encryption=none: question for the team |
| Internal gRPC client -> gRPC Health handler (a67s) | Data flow | T I D | - | container: adservice | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| checkoutservice (3a2t) -> gRPC CartService handler | Data flow | T I D | - | container: cartservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| RedisCartStore -> Redis | Data flow | T I D | - | container: redis-cart, container: cartservice | none | authentication=unknown, encryption=unknown: question for the team |
| checkoutservice (3a2t) -> grpc gRPC CurrencyService handler (+1 routes) | Data flow | T I D | - | container: checkoutservice, container: currencyservice | none | authentication=unknown, encryption=none: question for the team |
| loadgenerator -> frontend (sehz) | Data flow (inferred) | T I D | - | container: loadgenerator, container: frontend | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /cart handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /product-meta/{ids} handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| shoppingassistantservice (nbwu) -> Google Cloud APIs | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=tls: question for the team |
| productcatalogservice (bd4e) -> Google Cloud Profiler | Data flow (inferred) | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /cart/checkout handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| client -> Unresolved grpc target | Data flow | T I D | - | container: recommendationservice | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> GET / handler (zlml) | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| checkoutservice (3a2t) -> Google Cloud Profiler | Data flow (inferred) | T I D | - | container: checkoutservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> ANY /robots.txt handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres -> shoppingassistantservice (nbwu) | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=unknown: question for the team |
| Redis -> RedisCartStore | Data flow | T I D | - | container: redis-cart, container: cartservice | none | authentication=unknown, encryption=unknown: question for the team |
| POST /cart/checkout handler -> grpc gRPC CheckoutService handler (+1 routes) | Data flow | T I D | - | container: checkoutservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| email_server -> OTLP collector | Data flow (inferred) | T I D | - | container: emailservice | none | authentication=unknown, encryption=tls: question for the team |
| Internal gRPC client -> gRPC Health handler (qidx) | Data flow | T I D | - | container: cartservice | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres -> catalog_loader | Data flow | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /bot handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres -> POST / handler | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=unknown: question for the team |
| checkoutservice (3a2t) -> OTLP collector | Data flow (inferred) | T I D | - | container: checkoutservice | none | authentication=unknown, encryption=tls: question for the team |
| recommendation_server -> OTLP collector | Data flow (inferred) | T I D | - | container: recommendationservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /setCurrency handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| checkoutservice (3a2t) -> grpc gRPC Health handler (+1 routes) (xrau) | Data flow | T I D | - | container: shippingservice, container: checkoutservice | none | authentication=unknown, encryption=none: question for the team |
| rpc -> grpc gRPC Health handler (+1 routes) (xrau) | Data flow | T I D | - | container: shippingservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| rpc -> grpc gRPC Health handler (+1 routes) (jhqd) | Data flow | T I D | - | container: recommendationservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| checkoutservice (3a2t) -> grpc gRPC EmailService handler (+1 routes) | Data flow | T I D | - | container: checkoutservice, container: emailservice | none | authentication=unknown, encryption=none: question for the team |
| productcatalogservice (bd4e) -> OTLP collector | Data flow (inferred) | T I D | - | container: productcatalogservice | none | authentication=unknown, encryption=tls: question for the team |
| rpc -> gRPC AdService handler | Data flow | T I D | - | container: adservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| shippingservice (txxh) -> Google Cloud Profiler | Data flow (inferred) | T I D | - | container: shippingservice | none | authentication=unknown, encryption=tls: question for the team |
| POST /bot handler -> shoppingassistantservice (ivcw) | Data flow | T I D | - | container: shoppingassistantservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> GET /assistant handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| AdServiceClient -> Unresolved grpc target | Data flow | T I D | - | container: adservice | none | authentication=unknown, encryption=none: question for the team |
| rpc -> grpc gRPC Health handler (+1 routes) (q4dl) | Data flow | T I D | - | container: productcatalogservice, container: frontend | none | authentication=unknown, encryption=none: question for the team |
| POST / handler -> Google Gemini API | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /cart handler | Data flow | T I D | - | container: frontend | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Internal HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| OTLP collector | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Google Gemini API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts (LLM API: check what data is sent) |
| Internal gRPC client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Google Cloud APIs | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Google Cloud Profiler | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Unresolved grpc target | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Postgres | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Redis | Data store | T R I D | - | in container: redis-cart | encryption at rest: unknown |  |
| grpc gRPC CurrencyService handler (+1 routes) | Process | S T R I D E | - | - | none | entry point |
| GET /assistant handler | Process | S T R I D E | - | - | none | entry point |
| checkoutservice | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /cart/checkout handler | Process | S T R I D E | - | - | none | entry point |
| POST /cart handler | Process | S T R I D E | - | - | none | entry point |
| gRPC CartService handler | Process | S T R I D E | - | - | none | entry point |
| grpc gRPC EmailService handler (+1 routes) | Process | S T R I D E | - | - | none | entry point |
| GET /product/{id} handler | Process | S T R I D E | - | - | none | entry point |
| GET /product-meta/{ids} handler | Process | S T R I D E | - | - | none | entry point |
| GET /cart handler | Process | S T R I D E | - | - | none | entry point |
| RedisCartStore | Process | S T R I D E | - | - | n/a (internal) |  |
| productcatalogservice | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC AdService handler | Process | S T R I D E | - | - | none | entry point |
| client | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /setCurrency handler | Process | S T R I D E | - | - | none | entry point |
| GET /logout handler | Process | S T R I D E | - | - | none | entry point |
| grpc gRPC Health handler (+1 routes) | Process | S T R I D E | - | - | none | entry point |
| grpc gRPC Health handler (+1 routes) | Process | S T R I D E | - | - | none | entry point |
| POST /bot handler | Process | S T R I D E | - | - | none | entry point |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| shoppingassistantservice | Process | S T R I D E | - | - | n/a (internal) |  |
| recommendation_server | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /cart/empty handler | Process | S T R I D E | - | - | none | entry point |
| catalog_loader | Process | S T R I D E | - | - | n/a (internal) |  |
| grpc gRPC Health handler (+1 routes) | Process | S T R I D E | - | - | none | entry point |
| POST / handler | Process | S T R I D E | - | - | none | entry point |
| rpc | Process | S T R I D E | - | - | n/a (internal) |  |
| frontend | Process | S T R I D E | - | - | n/a (internal) |  |
| AdServiceClient | Process | S T R I D E | - | - | n/a (internal) |  |
| shippingservice | Process | S T R I D E | - | - | n/a (internal) |  |
| email_server | Process | S T R I D E | - | - | n/a (internal) |  |
| grpc gRPC Health handler (+1 routes) | Process | S T R I D E | - | - | none | entry point |
| grpc gRPC CheckoutService handler (+1 routes) | Process | S T R I D E | - | - | none | entry point |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| no authentication control detected on POST /cart | Weakness (info) | S E | - | - | ep:rw6goxikuq | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:153 |
| no authentication control detected on POST /cart/empty | Weakness (info) | S E | - | - | ep:urc6dkbttb | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:154 |
| no authentication control detected on POST /setCurrency | Weakness (info) | S E | - | - | ep:ryap4rulgf | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:155 |
| no authentication control detected on GET /product/{id} | Weakness (info) | S E | - | - | ep:yghqd2zcbd | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:151 |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:og4t6eu76k | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:150 |
| no authentication control detected on GET /cart | Weakness (info) | S E | - | - | ep:crrbzqtump | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:152 |
| no authentication control detected on GET /logout | Weakness (info) | S E | - | - | ep:23qm52ldvy | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:156 |
| no authentication control detected on POST /cart/checkout | Weakness (info) | S E | - | - | ep:4slvynctty | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:157 |
| no authentication control detected on POST /bot | Weakness (info) | S E | - | - | ep:mb2lhpjan7 | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:163 |
| no authentication control detected on GET /assistant | Weakness (info) | S E | - | - | ep:xqbb2s74nb | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:158 |
| no authentication control detected on GET /product-meta/{ids} | Weakness (info) | S E | - | - | ep:a5cbu2bfoc | CWE-306 Entry point without a detected authentication control (review) at src/frontend/main.go:162 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
