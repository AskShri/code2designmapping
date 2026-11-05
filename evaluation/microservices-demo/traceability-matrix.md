# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Insider with access to container: currencyservice | insider | container: currencyservice | gRPC healthProto.Health handler, gRPC shopProto.CurrencyService handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: OTLP collector | third_party | outside all boundaries | OTLP collector | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: loadgenerator | insider | container: loadgenerator | loadgenerator | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to repository: microservices-demo | insider | repository: microservices-demo | kustomize | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Anonymous GRPC caller | anonymous | outside all boundaries | gRPC client | - | reach data or functions without authenticating | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: shoppingassistantservice | insider | container: shoppingassistantservice | shoppingassistantservice, POST / handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: Google Cloud APIs | third_party | outside all boundaries | Google Cloud APIs | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Google Gemini API | third_party | outside all boundaries | Google Gemini API | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: emailservice | insider | container: emailservice | gRPC HealthServicer handler, gRPC EmailServiceServicer handler, email_server | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: productcatalogservice service | third_party | outside all boundaries | productcatalogservice service | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: paymentservice | insider | container: paymentservice | gRPC hipsterShopPackage.PaymentService handler, gRPC healthPackage.Health handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Insider with access to container: recommendationservice | insider | container: recommendationservice | client, gRPC RecommendationServiceServicer handler, recommendation_server, gRPC HealthServicer handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: Unresolved grpc target | third_party | outside all boundaries | Unresolved grpc target | - | return malicious responses; harvest data sent to it | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
