# code2design report: microservices-demo

Commit `c7cb6d5bfd6e`, code2design 0.5.1, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| c_sharp | 9 |
| go | 29 |
| java | 2 |
| javascript | 6 |
| python | 13 |
| (test files, not modelled) | 18 |

Detectors: config@0.5, csharp@0.5, go@0.5, java@0.5, js@0.5, py@0.5, synth@0.5.1

Facts: app 5, boundary_hint 52, config_value 2, declared_link 18, dependencies 10, entry_point 33, listener 11, module 6, outbound_call 42, router 3, schema 2, service_host 39, store_access 17, weakness 8

## Model

| Collection | Count |
|---|---|
| processes | 52 |
| entities | 8 |
| stores | 2 |
| boundaries | 14 |
| flows | 59 |
| entry_points | 33 |
| controls | 0 |
| weaknesses | 19 |
| schemas | 1 |
| assets | 2 |
| threat_agents | 17 |
| gaps | 11 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **grpc**: 9 entry points, 9 without a detected authentication control (0 of them published outside the deployment); 9 infrastructure entry points (health, preflight, docs) not counted
- **http**: 13 entry points, 13 without a detected authentication control (11 of them published outside the deployment); 2 infrastructure entry points (health, preflight, docs) not counted
- **listeners**: src/adservice/src/main/java/hipstershop/AdService.java port port, src/cartservice/src/Program.cs port ?, src/cartservice/src/Startup.cs port ?, src/checkoutservice/main.go port fmt.Sprintf(":%s", port, src/emailservice/email_server.py port '[::]:'+port, src/frontend/main.go port addr+":"+srvPort, src/frontend/main.go port profiler.Config{, src/productcatalogservice/server.go port fmt.Sprintf(":%s", port, src/recommendationservice/recommendation_server.py port '[::]:'+port, src/shippingservice/main.go port port, src/shoppingassistantservice/shoppingassistantservice.py port 8080
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 390 declared in src/checkoutservice/go.mod, src/currencyservice/package.json, src/emailservice/requirements.txt, src/frontend/go.mod, src/loadgenerator/requirements.txt, src/paymentservice/package.json, src/productcatalogservice/go.mod, src/recommendationservice/requirements.txt, src/shippingservice/go.mod, src/shoppingassistantservice/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 2 high, 6 medium, 11 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /logout | public | none | - |
| ANY /_healthz (infrastructure) | public | none | - |
| grpc Health (infrastructure) | internal | none | - |
| POST /cart/checkout | public | none | - |
| grpc Health (infrastructure) | internal | none | - |
| grpc RecommendationService | internal | none | - |
| grpc Health (infrastructure) | internal | none | - |
| GET /product-meta/{ids} | public | none | - |
| grpc Health (infrastructure) | internal | none | Unresolved grpc target |
| grpc Health (infrastructure) | internal | none | - |
| GET /cart | public | none | - |
| grpc Health (infrastructure) | internal | none | Postgres |
| grpc Health (infrastructure) | internal | none | - |
| ANY /robots.txt (infrastructure) | public | none | - |
| grpc PaymentService | internal | none | - |
| grpc CheckoutService | internal | none | - |
| grpc Health (infrastructure) | internal | none | - |
| grpc CurrencyService | internal | none | - |
| POST /bot | public | none | - |
| grpc CartService | internal | none | Redis |
| GET / | public | none | - |
| grpc Health (infrastructure) | internal | none | - |
| POST /cart | public | none | - |
| POST /setCurrency | public | none | - |
| grpc ProductCatalogService | internal | none | Postgres |
| POST /cart/empty | public | none | - |
| grpc AdService | internal | none | - |
| grpc ShippingService | internal | none | - |
| grpc EmailService | internal | none | - |
| POST / | internal | none | Google Gemini API, Postgres |
| GET /assistant | public | none | - |
| GET /product/{id} | public | none | - |
| GET / | internal | none | - |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| high | CWE-798 | ALLOYDB_SECRET_NAME literal in Deployment shoppingassistantservice | kustomize/components/shopping-assistant/shoppingassistantservice.yaml:61 |
| high | CWE-798 | GOOGLE_API_KEY literal in Deployment shoppingassistantservice | kustomize/components/shopping-assistant/shoppingassistantservice.yaml:51 |
| medium | CWE-319 | grpc.insecure_channel | src/recommendationservice/recommendation_server.py:135 |
| medium | CWE-319 | gRPC client with insecure credentials | src/frontend/main.go:230 |
| medium | CWE-319 | gRPC client with insecure credentials | src/checkoutservice/main.go:215 |
| medium | CWE-319 | gRPC client with insecure credentials | src/productcatalogservice/server.go:212 |
| medium | CWE-319 | grpc.insecure_channel | src/recommendationservice/client.py:33 |
| medium | CWE-319 | gRPC channel usePlaintext() | src/adservice/src/main/java/hipstershop/AdServiceClient.java:45 |
| info | CWE-306 | no authentication control detected on POST /cart | src/frontend/main.go:153 |
| info | CWE-306 | no authentication control detected on POST /cart/empty | src/frontend/main.go:154 |
| info | CWE-306 | no authentication control detected on POST /setCurrency | src/frontend/main.go:155 |
| info | CWE-306 | no authentication control detected on GET /product/{id} | src/frontend/main.go:151 |
| info | CWE-306 | no authentication control detected on GET / | src/frontend/main.go:150 |
| info | CWE-306 | no authentication control detected on GET /cart | src/frontend/main.go:152 |
| info | CWE-306 | no authentication control detected on GET /logout | src/frontend/main.go:156 |
| info | CWE-306 | no authentication control detected on POST /cart/checkout | src/frontend/main.go:157 |
| info | CWE-306 | no authentication control detected on POST /bot | src/frontend/main.go:163 |
| info | CWE-306 | no authentication control detected on GET /assistant | src/frontend/main.go:158 |
| info | CWE-306 | no authentication control detected on GET /product-meta/{ids} | src/frontend/main.go:162 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Internal HTTP client | system | - |
| OTLP collector | system | - |
| Google Gemini API | llm_api | generativelanguage.googleapis.com |
| Internal gRPC client | system | - |
| HTTP client | system | - |
| Google Cloud APIs | system | - |
| Google Cloud Profiler | system | - |
| Unresolved grpc target | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| Postgres | postgres | - | unknown | - |
| Redis | redis | - | unknown | container: redis-cart |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /cart/empty handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /product/{id} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> ANY /_healthz handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /logout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal gRPC client -> gRPC Health handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /cart handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /product-meta/{ids} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /cart/checkout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> ANY /robots.txt handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: Internal gRPC client -> gRPC Health handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /bot handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /setCurrency handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /assistant handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /cart handler
- **warning** `weakness-plaintext-credentials` CWE-798 ALLOYDB_SECRET_NAME literal in Deployment shoppingassistantservice (kustomize/components/shopping-assistant/shoppingassistantservice.yaml:61)
- **warning** `weakness-plaintext-credentials` CWE-798 GOOGLE_API_KEY literal in Deployment shoppingassistantservice (kustomize/components/shopping-assistant/shoppingassistantservice.yaml:51)
- **warning** `weakness-unencrypted-transport` CWE-319 grpc.insecure_channel (src/recommendationservice/recommendation_server.py:135)
- **warning** `weakness-unencrypted-transport` CWE-319 gRPC client with insecure credentials (src/frontend/main.go:230)
- **warning** `weakness-unencrypted-transport` CWE-319 gRPC client with insecure credentials (src/checkoutservice/main.go:215)
- **warning** `weakness-unencrypted-transport` CWE-319 gRPC client with insecure credentials (src/productcatalogservice/server.go:212)
- **warning** `weakness-unencrypted-transport` CWE-319 grpc.insecure_channel (src/recommendationservice/client.py:33)
- **warning** `weakness-unencrypted-transport` CWE-319 gRPC channel usePlaintext() (src/adservice/src/main/java/hipstershop/AdServiceClient.java:45)
- **info** `black-hole-or-miracle` process grpc gRPC CurrencyService handler (+1 routes) has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process checkoutservice has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC CartService handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process grpc gRPC EmailService handler (+1 routes) has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC Health handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process productcatalogservice has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC AdService handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process client has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /setCurrency handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /logout handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process grpc gRPC Health handler (+1 routes) has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process grpc gRPC Health handler (+1 routes) has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process recommendation_server has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process catalog_loader has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process grpc gRPC Health handler (+1 routes) has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC Health handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /robots.txt handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /_healthz handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process frontend has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process AdServiceClient has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process shippingservice has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process email_server has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process grpc gRPC Health handler (+1 routes) has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process grpc gRPC CheckoutService handler (+1 routes) has only inputs; a detector may be missing
- **info** `unknown-link-attributes` rpc -> gRPC CartService handler: authentication=unknown, encryption=none
- **info** `unknown-link-attributes` checkoutservice -> grpc gRPC Health handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` frontend -> Google Cloud Profiler: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` productcatalogservice -> Unresolved grpc target: authentication=unknown, encryption=none
- **info** `unknown-link-attributes` checkoutservice -> grpc gRPC Health handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` frontend -> OTLP collector: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` rpc -> grpc gRPC CurrencyService handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` recommendation_server -> productcatalogservice: authentication=unknown, encryption=none
- **info** `unknown-link-attributes` checkoutservice -> gRPC CartService handler: authentication=unknown, encryption=none
- **info** `unknown-link-attributes` RedisCartStore -> Redis: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` checkoutservice -> grpc gRPC CurrencyService handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` loadgenerator -> frontend: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` shoppingassistantservice -> Google Cloud APIs: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` productcatalogservice -> Google Cloud Profiler: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` client -> Unresolved grpc target: authentication=unknown, encryption=none
- **info** `unknown-link-attributes` checkoutservice -> Google Cloud Profiler: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` Postgres -> shoppingassistantservice: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Redis -> RedisCartStore: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /cart/checkout handler -> grpc gRPC CheckoutService handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` email_server -> OTLP collector: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` Postgres -> catalog_loader: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres -> POST / handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` checkoutservice -> OTLP collector: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` recommendation_server -> OTLP collector: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` checkoutservice -> grpc gRPC Health handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` rpc -> grpc gRPC Health handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` rpc -> grpc gRPC Health handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` checkoutservice -> grpc gRPC EmailService handler (+1 routes): authentication=unknown, encryption=none
- **info** `unknown-link-attributes` productcatalogservice -> OTLP collector: authentication=unknown, encryption=tls
- **info** `unknown-link-attributes` rpc -> gRPC AdService handler: authentication=unknown, encryption=none
- **info** `unknown-link-attributes` shippingservice -> Google Cloud Profiler: authentication=unknown, encryption=tls
- ... 4 more

## Inferred elements (dashed in diagrams)

- repository: microservices-demo (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- frontend (s53a) -> Google Cloud Profiler (confidence 0.6): the Google Cloud Profiler SDK is imported in src/frontend/main.go but no call site could be resolved
- frontend (s53a) -> OTLP collector (confidence 0.6): the OTLP collector SDK is imported in src/frontend/main.go but no call site could be resolved
- loadgenerator -> frontend (sehz) (confidence 0.7): FRONTEND_ADDR of service 'loadgenerator' names host 'frontend' in release/kubernetes-manifests.yaml; no call site was resolved in code
- productcatalogservice (bd4e) -> Google Cloud Profiler (confidence 0.6): the Google Cloud Profiler SDK is imported in src/productcatalogservice/server.go but no call site could be resolved
- checkoutservice (3a2t) -> Google Cloud Profiler (confidence 0.6): the Google Cloud Profiler SDK is imported in src/checkoutservice/main.go but no call site could be resolved
- email_server -> OTLP collector (confidence 0.6): the OTLP collector SDK is imported in src/emailservice/email_server.py but no call site could be resolved
- checkoutservice (3a2t) -> OTLP collector (confidence 0.6): the OTLP collector SDK is imported in src/checkoutservice/main.go but no call site could be resolved
- recommendation_server -> OTLP collector (confidence 0.6): the OTLP collector SDK is imported in src/recommendationservice/recommendation_server.py but no call site could be resolved
- productcatalogservice (bd4e) -> OTLP collector (confidence 0.6): the OTLP collector SDK is imported in src/productcatalogservice/server.go but no call site could be resolved
- shippingservice (txxh) -> Google Cloud Profiler (confidence 0.6): the Google Cloud Profiler SDK is imported in src/shippingservice/main.go but no call site could be resolved
- Insider with access to container: currencyservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised external service (confidence 0.7): each of the 5 outbound dependencies is a potentially hostile responder
- Insider with access to container: loadgenerator (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: shippingservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to repository: microservices-demo (confidence 0.8): one insider agent per trust boundary, placed inside it
- Workload inside the deployment calling HTTP client endpoints (confidence 0.7): these entry points are not published outside the deployment; a caller must already be inside it
- Insider with access to container: adservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: checkoutservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 11 entry points are reachable from outside, 11 of them without a detected authentication control
- Insider with access to container: shoppingassistantservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: emailservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: productcatalogservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: cartservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Workload inside the deployment calling gRPC client endpoints (confidence 0.7): these entry points are not published outside the deployment; a caller must already be inside it
- Insider with access to container: frontend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: paymentservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: recommendationservice (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` src/recommendationservice/client.py:33: the target of an outbound call is built from a variable; the host is not resolvable statically
- `unknown_attribute` src/cartservice/src/Program.cs: Question: is TLS terminated in front of the HTTP listener of cartservice? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/frontend/main.go: Question: is TLS terminated in front of the HTTP listener of frontend? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py: Question: is TLS terminated in front of the HTTP listener of shoppingassistantservice? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/frontend/main.go:24: Question: what is the authentication of the link to Google Cloud Profiler?
- `unknown_attribute` src/productcatalogservice/server.go:211: Question: what is the authentication of the link to Unresolved grpc target?
- `unknown_attribute` src/frontend/main.go:31: Question: what is the authentication of the link to OTLP collector?
- `unknown_attribute` src/cartservice/src/cartstore/RedisCartStore.cs:60: Question: what is the authentication and encryption of the link to Redis?
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:35: Question: what is the authentication of the link to Google Cloud APIs?
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:41: Question: what is the authentication and encryption of the link to Postgres?
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:82: Question: what is the authentication of the link to Google Gemini API?
