# code2design report: microservices-demo

Commit `c7cb6d5bfd6e`, tool 0.3.0-prototype, 1.0s.

## Coverage

| Language | Files parsed |
|---|---|
| c_sharp | 9 |
| go | 29 |
| java | 2 |
| javascript | 6 |
| python | 13 |
| (test files skipped) | 18 |

Detectors that ran: config@0.3, csharp@0.1, go@0.1, java@0.1, js@0.3, py@0.3

Facts: app_entry 8, boundary_hint 51, config_value 1, dependencies 6, entry_point 31, listener 10, module 2, outbound_call 44, schema 2, service_host 39, store_access 17, weakness 8

## Model

| Collection | Count |
|---|---|
| processes | 58 |
| entities | 7 |
| stores | 2 |
| boundaries | 13 |
| flows | 83 |
| entry_points | 31 |
| controls | 0 |
| weaknesses | 20 |
| schemas | 1 |
| assets | 1 |
| threat_agents | 20 |
| gaps | 11 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **grpc**: 9 entry points, 9 without a detected authn control; 7 infrastructure entry points (health, preflight, docs) not counted
- **http**: 13 entry points, 13 without a detected authn control; 2 infrastructure entry points (health, preflight, docs) not counted
- **listeners**: src/adservice/src/main/java/hipstershop/AdService.java port port, src/cartservice/src/Program.cs port ?, src/checkoutservice/main.go port fmt.Sprintf(":%s", port, src/emailservice/email_server.py port '[::]:'+port, src/frontend/main.go port addr+":"+srvPort, src/paymentservice/index.js port ?, src/productcatalogservice/server.go port fmt.Sprintf(":%s", port, src/recommendationservice/recommendation_server.py port '[::]:'+port, src/shippingservice/main.go port port, src/shoppingassistantservice/shoppingassistantservice.py port (host='0.0.0.0', port=8080)
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 212 declared in src/currencyservice/package.json, src/emailservice/requirements.txt, src/loadgenerator/requirements.txt, src/paymentservice/package.json, src/recommendationservice/requirements.txt, src/shoppingassistantservice/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| grpc CartService | none |
| POST /bot | none |
| grpc CurrencyService | none |
| grpc ProductCatalogService | none |
| POST /cart/empty | none |
| grpc RecommendationService | none |
| grpc EmailService | none |
| GET / | none |
| grpc Health (infrastructure) | none |
| grpc ShippingService | none |
| grpc CheckoutService | none |
| grpc Health (infrastructure) | none |
| grpc Health (infrastructure) | none |
| GET /assistant | none |
| GET /product/{id} | none |
| grpc Health (infrastructure) | none |
| grpc Health (infrastructure) | none |
| ANY /_healthz (infrastructure) | none |
| POST /cart/checkout | none |
| GET /logout | none |
| ANY /robots.txt (infrastructure) | none |
| grpc PaymentService | none |
| GET / | none |
| grpc AdService | none |
| grpc Health (infrastructure) | none |
| GET /cart | none |
| POST / | none |
| POST /setCurrency | none |
| GET /product-meta/{ids} | none |
| POST /cart | none |
| grpc Health (infrastructure) | none |

### External entities

| Entity | Kind | Host |
|---|---|---|
| OTLP collector | system | - |
| Google Gemini API | llm_api | generativelanguage.googleapis.com |
| HTTP client | system | - |
| gRPC client | system | - |
| Google Cloud APIs | system | - |
| Google Cloud Profiler | system | - |
| Unresolved grpc target | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| Postgres | postgres | - | - |
| Redis | redis | - | - |

## Lint

- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC EmailService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC RecommendationService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /cart handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC AdService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC CurrencyService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> ANY /_healthz handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC PaymentService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /cart/checkout handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC ShippingService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /cart handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC CartService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /bot handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /logout handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /product-meta/{ids} handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC ProductCatalogService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> ANY /robots.txt handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC CheckoutService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /setCurrency handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST / handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /cart/empty handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /assistant handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /product/{id} handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC Health handler
- **warning** `unknown-link-attributes` rpc -> currencyservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` checkoutservice -> cartservice: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` checkoutservice -> productcatalogservice: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` POST / handler -> Google Gemini API: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` productcatalogservice -> OTLP collector: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` frontend -> OTLP collector: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` checkoutservice -> paymentservice: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` checkoutservice -> currencyservice: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` frontend -> Google Cloud Profiler: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` productcatalogservice -> Google Cloud Profiler: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` rpc -> cartservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Redis -> RedisCartStore: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` recommendation_server -> OTLP collector: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` rpc -> recommendationservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` POST /cart/checkout handler -> checkoutservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` checkoutservice -> Google Cloud Profiler: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` AdServiceClient -> Unresolved grpc target: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` checkoutservice -> OTLP collector: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` rpc -> adservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` productcatalogservice -> Unresolved grpc target: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` shippingservice -> Google Cloud Profiler: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` Postgres -> catalog_loader: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` checkoutservice -> emailservice: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` client -> Unresolved grpc target: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` checkoutservice -> shippingservice: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` rpc -> shippingservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Postgres -> POST / handler: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` shoppingassistantservice -> Google Cloud APIs: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` Postgres -> shoppingassistantservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` recommendation_server -> productcatalogservice: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` RedisCartStore -> Redis: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` email_server -> OTLP collector: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` rpc -> productcatalogservice: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` POST /bot handler -> shoppingassistantservice: authentication=unknown, encryption=none
- **warning** `weakness` plaintext_credentials: ALLOYDB_SECRET_NAME literal in Deployment shoppingassistantservice (kustomize/components/shopping-assistant/shoppingassistantservice.yaml:18)
- **info** `black-hole-or-miracle` process catalog_loader has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process shippingservice has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC Health handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC EmailService handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /_healthz handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC Health handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /logout handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process frontend has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /robots.txt handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /setCurrency handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process client has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC PaymentService handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC Health handler has only inputs; a detector may be missing
- ... 4 more

## Inferred elements (dashed in diagrams)

- repository: microservices-demo (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: currencyservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: OTLP collector (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: loadgenerator (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: shippingservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to repository: microservices-demo (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: adservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous GRPC caller (confidence 0.9): 16 grpc entry points, 16 without a detected authn control
- Insider with access to container: checkoutservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 15 http entry points, 15 without a detected authn control
- Insider with access to container: shoppingassistantservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: Google Cloud APIs (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Google Gemini API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: emailservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: productcatalogservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: cartservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: Google Cloud Profiler (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: frontend (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: paymentservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: recommendationservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: Unresolved grpc target (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder

## Gaps and questions

- `unresolved` src/cartservice/src/Startup.cs:77: router for GET / is not mounted from a detected app entry; path shown without prefix
- `unresolved` src/adservice/src/main/java/hipstershop/AdServiceClient.java:42: outbound call target is a variable:host expression; host not resolvable statically
- `unresolved` src/productcatalogservice/server.go:211: outbound call target is a variable:addr expression; host not resolvable statically
- `unknown_attribute` src/paymentservice/index.js: Question for the team: is TLS terminated in front of the HTTP listener on port '[::]:'+port, (host='0.0.0.0', port=8080), ?, addr+":"+srvPort, fmt.Sprintf(":%s", port, port? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:41: Question for the team: how is the link to Postgres authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/cartservice/src/cartstore/RedisCartStore.cs:40: Question for the team: how is the link to Redis authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/emailservice/email_server.py:37: Question for the team: how is the link to OTLP collector authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` src/recommendationservice/client.py:33: Question for the team: how is the link to Unresolved grpc target authenticated and is it encrypted in transit? (authentication=unknown, encryption=none)
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:35: Question for the team: how is the link to Google Cloud APIs authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:82: Question for the team: how is the link to Google Gemini API authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` src/checkoutservice/main.go:24: Question for the team: how is the link to Google Cloud Profiler authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
