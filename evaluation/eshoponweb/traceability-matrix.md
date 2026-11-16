# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> POST /Basket handler -> SQL Server: CatalogItem -> OrderService -> SQL Server: Order | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Financial data | HTTP client -> POST /Basket handler -> SQL Server: CatalogItem | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: eshoponweb | Personal data (PII) | DeleteCatalogItemEndpoint -> SQL Server: CatalogItem -> OrderService -> SQL Server: Order | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: eshoponweb | Financial data | DeleteCatalogItemEndpoint -> SQL Server: CatalogItem | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Financial data | HTTP client -> POST /Basket handler -> SQL Server: CatalogItem | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: eshoppublicapi | Personal data (PII) | OrderService -> SQL Server: Order | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to container: eshoppublicapi | Financial data | OrderService -> SQL Server: CatalogItem | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> POST /Basket/Checkout handler -> OrderService -> SQL Server: Order | none | [Authorize] | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Compromised external service | Secret CatalogConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret AZURE_SQL_CATALOG_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Personal data (PII) | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Financial data | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret IdentityConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret AZURE_SQL_IDENTITY_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret CatalogConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret AZURE_SQL_CATALOG_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret IdentityConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret AZURE_SQL_IDENTITY_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: eshoponweb | Secret CatalogConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: eshoponweb | Secret AZURE_SQL_CATALOG_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: eshoponweb | Secret IdentityConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: eshoponweb | Secret AZURE_SQL_IDENTITY_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Authenticated HTTP caller | Secret CatalogConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Authenticated HTTP caller | Secret AZURE_SQL_CATALOG_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Authenticated HTTP caller | Secret IdentityConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Authenticated HTTP caller | Secret AZURE_SQL_IDENTITY_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: eshoppublicapi | Secret CatalogConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: eshoppublicapi | Secret AZURE_SQL_CATALOG_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: eshoppublicapi | Secret IdentityConnection | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: eshoppublicapi | Secret AZURE_SQL_IDENTITY_CONNECTION_STRING_KEY | no path | - | - | unreachable from this agent over the modelled flows |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | Unresolved HTTP target | - | return malicious responses; harvest data sent to it | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to repository: eshoponweb | insider | repository: eshoponweb | GET / handler, POST /Manage/ResetAuthenticator handler, GET/POST /Manage/SetPassword handler, GET /Privacy handler, POST /Manage/Disable2fa handler (+20) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; use functions beyond their role | inferred |
| Insider with access to container: eshoppublicapi | insider | container: eshoppublicapi | OrderService, BasketService, CustomAuthStateProvider, CatalogContextSeed, CatalogLookupDataService (+1) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret CatalogConnection | credential | secret | eshoppublicapi | eshoppublicapi |
| Secret AZURE_SQL_CATALOG_CONNECTION_STRING_KEY | credential | secret | Web | Web |
| Personal data (PII) | data | pii | SQL Server: Order | OrderService, GetMyOrdersHandler, GetOrderDetailsHandler |
| Financial data | data | financial | SQL Server: BasketItem, SQL Server: CatalogItem, SQL Server: OrderItem | DeleteCatalogItemEndpoint, UpdateCatalogItemEndpoint, CatalogItemGetByIdEndpoint, CatalogItemViewModelService, OrderService, CreateCatalogItemEndpoint, CatalogItemListPagedEndpoint, CatalogContextSeed (+3) |
| Secret IdentityConnection | credential | secret | eshoppublicapi | eshoppublicapi |
| Secret AZURE_SQL_IDENTITY_CONNECTION_STRING_KEY | credential | secret | Web | Web |
