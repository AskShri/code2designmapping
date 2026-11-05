# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| grpc.insecure_channel | Weakness | - | - | - | - | unencrypted_transport at src/recommendationservice/recommendation_server.py:135 |
| grpc.insecure_channel | Weakness | - | - | - | - | unencrypted_transport at src/recommendationservice/client.py:33 |
| ALLOYDB_SECRET_NAME literal in Deployment shoppingassistants | Weakness | - | - | - | - | plaintext_credentials at kustomize/components/shopping-assistant/shoppingassistantservice.yaml:18 |
| no authn control detected on POST / | Weakness | - | - | - | - | unauthenticated_entry_point at src/shoppingassistantservice/shoppingassistantservice.py:65 |
| OTLP collector | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Google Gemini API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts (LLM API: check what data is sent) |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| gRPC client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| Google Cloud APIs | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| productcatalogservice service | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Unresolved grpc target | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| POST / handler -> Google Gemini API | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=tls: question for the team |
| gRPC client -> gRPC shopProto.CurrencyService handler | Data flow | T I D | - | container: currencyservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| recommendation_server -> OTLP collector | Data flow | T I D | - | container: recommendationservice | none | authentication=unknown, encryption=tls: question for the team |
| gRPC client -> gRPC HealthServicer handler | Data flow | T I D | - | container: emailservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC healthProto.Health handler | Data flow | T I D | - | container: currencyservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC EmailServiceServicer handler | Data flow | T I D | - | container: emailservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC RecommendationServiceServicer handler | Data flow | T I D | - | container: recommendationservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC hipsterShopPackage.PaymentService handler | Data flow | T I D | - | container: paymentservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| gRPC client -> gRPC HealthServicer handler | Data flow | T I D | - | container: recommendationservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| client -> Unresolved grpc target | Data flow | T I D | - | container: recommendationservice | none | authentication=unknown, encryption=none: question for the team |
| shoppingassistantservice -> Google Cloud APIs | Data flow | T I D | - | container: shoppingassistantservice | none | authentication=unknown, encryption=tls: question for the team |
| gRPC client -> gRPC healthPackage.Health handler | Data flow | T I D | - | container: paymentservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST / handler | Data flow | T I D | - | container: shoppingassistantservice | none | inbound crossing with no control; authentication=none, encryption=unknown: question for the team |
| recommendation_server -> productcatalogservice service | Data flow | T I D | - | container: recommendationservice | none | authentication=unknown, encryption=none: question for the team |
| email_server -> OTLP collector | Data flow | T I D | - | container: emailservice | none | authentication=unknown, encryption=tls: question for the team |
| Redis: redis-cart | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| gRPC hipsterShopPackage.PaymentService handler | Process | S T R I D E | - | - | none | entry point |
| gRPC HealthServicer handler | Process | S T R I D E | - | - | none | entry point |
| shoppingassistantservice | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC healthProto.Health handler | Process | S T R I D E | - | - | none | entry point |
| client | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC EmailServiceServicer handler | Process | S T R I D E | - | - | none | entry point |
| gRPC RecommendationServiceServicer handler | Process | S T R I D E | - | - | none | entry point |
| recommendation_server | Process | S T R I D E | - | - | n/a (internal) |  |
| POST / handler | Process | S T R I D E | - | - | none | entry point |
| gRPC shopProto.CurrencyService handler | Process | S T R I D E | - | - | none | entry point |
| gRPC HealthServicer handler | Process | S T R I D E | - | - | none | entry point |
| email_server | Process | S T R I D E | - | - | n/a (internal) |  |
| gRPC healthPackage.Health handler | Process | S T R I D E | - | - | none | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
