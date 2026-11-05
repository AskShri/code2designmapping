# code2design report: microservices-demo

Commit `c7cb6d5bfd6e`, tool 0.3.0-prototype, 0.3s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 6 |
| python | 13 |
| (test files skipped) | 0 |
| no recognizer for .cs | 9 (not analyzed) |
| no recognizer for .go | 29 (not analyzed) |
| no recognizer for .java | 2 (not analyzed) |

Detectors that ran: config@0.3, js@0.3, py@0.3

Facts: app_entry 2, boundary_hint 51, dependencies 6, entry_point 9, listener 4, module 2, outbound_call 14, service_host 39, store_access 4, weakness 4

## Model

| Collection | Count |
|---|---|
| processes | 21 |
| entities | 7 |
| stores | 1 |
| boundaries | 7 |
| flows | 15 |
| entry_points | 9 |
| controls | 0 |
| weaknesses | 4 |
| schemas | 0 |
| assets | 0 |
| threat_agents | 14 |
| gaps | 10 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **grpc**: 8 entry points, 8 without a detected authn control
- **http**: 1 entry points, 1 without a detected authn control
- **listeners**: src/emailservice/email_server.py port '[::]:'+port, src/paymentservice/index.js port ?, src/recommendationservice/recommendation_server.py port '[::]:'+port, src/shoppingassistantservice/shoppingassistantservice.py port (host='0.0.0.0', port=8080)
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 212 declared in src/currencyservice/package.json, src/emailservice/requirements.txt, src/loadgenerator/requirements.txt, src/paymentservice/package.json, src/recommendationservice/requirements.txt, src/shoppingassistantservice/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| grpc RecommendationServiceServicer | none |
| grpc hipsterShopPackage.PaymentService | none |
| grpc healthProto.Health | none |
| grpc EmailServiceServicer | none |
| grpc shopProto.CurrencyService | none |
| grpc HealthServicer | none |
| grpc healthPackage.Health | none |
| POST / | none |
| grpc HealthServicer | none |

### External entities

| Entity | Kind | Host |
|---|---|---|
| OTLP collector | system | - |
| Google Gemini API | llm_api | generativelanguage.googleapis.com |
| HTTP client | system | - |
| gRPC client | system | - |
| Google Cloud APIs | system | - |
| productcatalogservice service | system | productcatalogservice |
| Unresolved grpc target | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| Redis: redis-cart | redis | - | - |

## Lint

- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC shopProto.CurrencyService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC HealthServicer handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC healthProto.Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC EmailServiceServicer handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC RecommendationServiceServicer handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC hipsterShopPackage.PaymentService handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC HealthServicer handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: gRPC client -> gRPC healthPackage.Health handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST / handler
- **warning** `unknown-link-attributes` POST / handler -> Google Gemini API: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` recommendation_server -> OTLP collector: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` client -> Unresolved grpc target: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` shoppingassistantservice -> Google Cloud APIs: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` recommendation_server -> productcatalogservice service: authentication=unknown, encryption=none
- **warning** `unknown-link-attributes` email_server -> OTLP collector: authentication=unknown, encryption=tls
- **warning** `weakness` plaintext_credentials: ALLOYDB_SECRET_NAME literal in Deployment shoppingassistantservice (kustomize/components/shopping-assistant/shoppingassistantservice.yaml:18)
- **info** `black-hole-or-miracle` process gRPC hipsterShopPackage.PaymentService handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC HealthServicer handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process shoppingassistantservice has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC healthProto.Health handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process client has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC EmailServiceServicer handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC RecommendationServiceServicer handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process recommendation_server has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC shopProto.CurrencyService handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC HealthServicer handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process email_server has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process gRPC healthPackage.Health handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: microservices-demo (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: currencyservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: OTLP collector (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: loadgenerator (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to repository: microservices-demo (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous GRPC caller (confidence 0.9): 8 grpc entry points, 8 without a detected authn control
- Anonymous HTTP caller (confidence 0.9): 1 http entry points, 1 without a detected authn control
- Insider with access to container: shoppingassistantservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: Google Cloud APIs (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Google Gemini API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: emailservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: productcatalogservice service (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to container: paymentservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Insider with access to container: recommendationservice (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: Unresolved grpc target (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder

## Gaps and questions

- `unresolved` kubernetes-manifests/cartservice.yaml:92: Redis: redis-cart is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unsupported_file` src/cartservice/src/Program.cs: no recognizer for .cs: 9 file(s), e.g. src/cartservice/src/Program.cs, src/cartservice/src/Startup.cs, src/cartservice/src/cartstore/AlloyDBCartStore.cs
- `unsupported_file` src/checkoutservice/main.go: no recognizer for .go: 29 file(s), e.g. src/checkoutservice/main.go, src/checkoutservice/genproto/demo.pb.go, src/checkoutservice/genproto/demo_grpc.pb.go
- `unsupported_file` src/adservice/src/main/java/hipstershop/AdService.java: no recognizer for .java: 2 file(s), e.g. src/adservice/src/main/java/hipstershop/AdService.java, src/adservice/src/main/java/hipstershop/AdServiceClient.java
- `unknown_attribute` src/paymentservice/index.js: Question for the team: is TLS terminated in front of the HTTP listener on port '[::]:'+port, (host='0.0.0.0', port=8080), ?? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/emailservice/email_server.py:37: Question for the team: how is the link to OTLP collector authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` src/recommendationservice/client.py:33: Question for the team: how is the link to Unresolved grpc target authenticated and is it encrypted in transit? (authentication=unknown, encryption=none)
- `unknown_attribute` src/recommendationservice/recommendation_server.py:135: Question for the team: how is the link to productcatalogservice service authenticated and is it encrypted in transit? (authentication=unknown, encryption=none)
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:35: Question for the team: how is the link to Google Cloud APIs authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` src/shoppingassistantservice/shoppingassistantservice.py:82: Question for the team: how is the link to Google Gemini API authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
