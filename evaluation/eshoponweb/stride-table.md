# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| hard-coded DEFAULT_PASSWORD | Weakness (high) | I E | - | - | eshoppublicapi | CWE-798 Hard-coded or committed credentials at src/ApplicationCore/Constants/AuthorizationConstants.cs:8 |
| SA_PASSWORD set in compose service 'sqlserver' | Weakness (high) | I E | - | - | eshoponweb | CWE-798 Hard-coded or committed credentials at docker-compose.yml:23 |
| hard-coded JWT_SECRET_KEY | Weakness (high) | I E | - | - | eshoppublicapi | CWE-798 Hard-coded or committed credentials at src/ApplicationCore/Constants/AuthorizationConstants.cs:11 |
| SQL Server: BasketItem | Data store | T R I D | financial | in container: sqlserver | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| SQL Server: CatalogItem | Data store | T R I D | financial | in container: sqlserver | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| SQL Server: Order | Data store | T R I D | pii | in container: sqlserver | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| SQL Server: OrderItem | Data store | T R I D | financial | in container: sqlserver | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| SQL Server: CatalogType -> CatalogContextSeed | Data flow | T I D | - | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: Basket -> BasketViewModelService | Data flow | T I D | - | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| CustomAuthStateProvider -> Unresolved HTTP target | Data flow | T I D | - | container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogItem -> UpdateCatalogItemEndpoint | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogType -> CatalogTypeListEndpoint | Data flow | T I D | - | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogBrand -> CatalogBrandListEndpoint | Data flow | T I D | - | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: Order -> GetMyOrdersHandler | Data flow | T I D | pii | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /Error handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| HttpService -> Unresolved HTTP target | Data flow | T I D | - | container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /Account/Login handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| HTTP client -> POST /User/Logout handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| SQL Server: CatalogItem -> CatalogItemViewModelService | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogBrand -> CatalogContextSeed | Data flow | T I D | - | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: Basket -> BasketService | Data flow | T I D | - | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogItem -> CreateCatalogItemEndpoint | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| CatalogContextSeed -> SQL Server: CatalogBrand | Data flow | T I D | - | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogType -> CatalogViewModelService | Data flow | T I D | - | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /Account/Register handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| SQL Server: CatalogBrand -> CatalogViewModelService | Data flow | T I D | - | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| OrderService -> SQL Server: Order | Data flow | T I D | pii | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/catalog-items handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| HTTP client -> GET /api/catalog-items/{catalogItemId} handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| HTTP client -> GET /Account/Logout handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| CreateCatalogItemEndpoint -> SQL Server: CatalogItem | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /Basket handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| SQL Server: CatalogItem -> CatalogItemGetByIdEndpoint | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: Basket -> OrderService | Data flow | T I D | - | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogItem -> OrderService | Data flow | T I D | financial | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /Account/Login handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| HTTP client -> GET /api/catalog-brands handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| UpdateCatalogItemEndpoint -> SQL Server: CatalogItem | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| BasketViewModelService -> SQL Server: Basket | Data flow | T I D | - | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /User handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| HTTP client -> GET /api/catalog-types handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| CatalogContextSeed -> SQL Server: CatalogItem | Data flow | T I D | financial | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: Order -> GetOrderDetailsHandler | Data flow | T I D | pii | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogItem -> CatalogItemListPagedEndpoint | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| CatalogContextSeed -> SQL Server: CatalogType | Data flow | T I D | - | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogItem -> CatalogViewModelService | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /Basket handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| SQL Server: CatalogItem -> DeleteCatalogItemEndpoint | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /Privacy handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| BasketService -> SQL Server: Basket | Data flow | T I D | - | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogItem -> POST /Basket handler | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| CatalogLookupDataService -> Unresolved HTTP target | Data flow | T I D | - | container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| SQL Server: CatalogItem -> CatalogContextSeed | Data flow | T I D | financial | container: sqlserver, container: eshoppublicapi | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /Account/Register handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| CatalogItemViewModelService -> SQL Server: CatalogItem | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /Account/Logout handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| SQL Server: CatalogItem -> BasketViewModelService | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /Account/ConfirmEmail handler | Data flow | T I D | - | repository: eshoponweb | none | inbound crossing without authentication |
| DeleteCatalogItemEndpoint -> SQL Server: CatalogItem | Data flow | T I D | financial | container: sqlserver, repository: eshoponweb | none | authentication=unknown, encryption=unknown: question for the team |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| SQL Server: Basket | Data store | T R I D | - | in container: sqlserver | encryption at rest: unknown |  |
| SQL Server: CatalogType | Data store | T R I D | - | in container: sqlserver | encryption at rest: unknown |  |
| SQL Server: CatalogBrand | Data store | T R I D | - | in container: sqlserver | encryption at rest: unknown |  |
| HTTP client -> POST /Manage/GenerateRecoveryCodes handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> POST /Admin/EditCatalogItem handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET /Manage/TwoFactorAuthentication handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> POST /Manage/ResetAuthenticator handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> GET /Order/MyOrders handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> POST /api/catalog-items handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET/POST /Manage/ChangePassword handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> GET /Manage/ResetAuthenticatorWarning handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET /Manage/ExternalLogins handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> PUT /api/catalog-items handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET/POST /Manage/MyAccount handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> GET /Order/Detail/{orderId} handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> POST /Basket/Checkout handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET /Manage/LinkLoginCallback handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET /Manage/ShowRecoveryCodes handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> POST /Manage/SendVerificationEmail handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> GET /Basket/Success handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> POST /Manage/RemoveLogin handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> GET /Admin/EditCatalogItem handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET/POST /Manage/SetPassword handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> GET /Basket/Checkout handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> DELETE /api/catalog-items/{catalogItemId} handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET /Manage/Disable2faWarning handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> GET /Manage/GenerateRecoveryCodesWarning handler | Data flow | T I D | - | repository: eshoponweb | [Authorize] |  |
| HTTP client -> POST /Manage/Disable2fa handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> POST /Manage/LinkLogin handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| HTTP client -> GET/POST /Manage/EnableAuthenticator handler | Data flow | T I D | - | repository: eshoponweb | [Authorize], [ValidateAntiForgeryToken] |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| POST /Manage/ResetAuthenticator handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| GET\|POST /Manage/SetPassword handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| GET /Privacy handler | Process | S T R I D E | - | - | none | entry point |
| POST /Manage/Disable2fa handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| POST /Manage/LinkLogin handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| POST /User/Logout handler | Process | S T R I D E | - | - | none | entry point |
| DeleteCatalogItemEndpoint | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /Admin/EditCatalogItem handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| GET /Basket/Success handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| GET /Manage/Disable2faWarning handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| POST /Account/Register handler | Process | S T R I D E | - | - | none | entry point |
| GET /api/catalog-brands handler | Process | S T R I D E | - | - | none | entry point |
| UpdateCatalogItemEndpoint | Process | S T R I D E | - | - | n/a (internal) |  |
| CatalogBrandListEndpoint | Process | S T R I D E | - | - | n/a (internal) |  |
| GET\|POST /Manage/MyAccount handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| GET /Account/ConfirmEmail handler | Process | S T R I D E | - | - | none | entry point |
| GET /Account/Logout handler | Process | S T R I D E | - | - | none | entry point |
| CatalogItemGetByIdEndpoint | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /Manage/ExternalLogins handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| CatalogItemViewModelService | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/catalog-items/{catalogItemId} handler | Process | S T R I D E | - | - | none | entry point |
| GET /Basket handler | Process | S T R I D E | - | - | none | entry point |
| OrderService | Process | S T R I D E | - | - | n/a (internal) |  |
| GET\|POST /Manage/ChangePassword handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| GET /Manage/TwoFactorAuthentication handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| POST /Manage/SendVerificationEmail handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| POST /Account/Login handler | Process | S T R I D E | - | - | none | entry point |
| POST /Basket/Checkout handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| CreateCatalogItemEndpoint | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /Manage/GenerateRecoveryCodesWarning handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| GetMyOrdersHandler | Process | S T R I D E | - | - | n/a (internal) |  |
| GET\|POST /Manage/EnableAuthenticator handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| BasketService | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /Manage/GenerateRecoveryCodes handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| CustomAuthStateProvider | Process | S T R I D E | - | - | n/a (internal) |  |
| CatalogItemListPagedEndpoint | Process | S T R I D E | - | - | n/a (internal) |  |
| GetOrderDetailsHandler | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /Manage/RemoveLogin handler | Process | S T R I D E | - | - | [Authorize], [ValidateAntiForgeryToken] | entry point |
| GET /Order/Detail/{orderId} handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| CatalogContextSeed | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /Account/Logout handler | Process | S T R I D E | - | - | none | entry point |
| GET /Basket/Checkout handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| PUT /api/catalog-items handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| GET /api/catalog-types handler | Process | S T R I D E | - | - | none | entry point |
| GET /Error handler | Process | S T R I D E | - | - | none | entry point |
| GET /Account/Login handler | Process | S T R I D E | - | - | none | entry point |
| POST /api/catalog-items handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| POST /Admin/EditCatalogItem handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| CatalogLookupDataService | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /Basket handler | Process | S T R I D E | - | - | none | entry point |
| GET /Account/Register handler | Process | S T R I D E | - | - | none | entry point |
| GET /Manage/ResetAuthenticatorWarning handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| BasketViewModelService | Process | S T R I D E | - | - | n/a (internal) |  |
| HttpService | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/catalog-items handler | Process | S T R I D E | - | - | none | entry point |
| CatalogViewModelService | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /User handler | Process | S T R I D E | - | - | none | entry point |
| GET /Order/MyOrders handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| GET /Manage/LinkLoginCallback handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| CatalogTypeListEndpoint | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /Manage/ShowRecoveryCodes handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| DELETE /api/catalog-items/{catalogItemId} handler | Process | S T R I D E | - | - | [Authorize] | entry point |
| no authentication control detected on GET /User | Weakness (info) | S E | - | - | ep:us7znizi7a | CWE-306 Entry point without a detected authentication control (review) at src/Web/Controllers/UserController.cs:35 |
| no authentication control detected on GET /api/catalog-items/{catalogItemId} | Weakness (info) | S E | - | - | ep:xaxqjzclrv | CWE-306 Entry point without a detected authentication control (review) at src/PublicApi/CatalogItemEndpoints/CatalogItemGetByIdEndpoint.cs:25 |
| no authentication control detected on GET /Privacy | Weakness (info) | S E | - | - | ep:z4t75suyvk | CWE-306 Entry point without a detected authentication control (review) at src/Web/Pages/Privacy.cshtml.cs:7 |
| no authentication control detected on GET /api/catalog-items | Weakness (info) | S E | - | - | ep:iqekol6spt | CWE-306 Entry point without a detected authentication control (review) at src/PublicApi/CatalogItemEndpoints/CatalogItemListPagedEndpoint.cs:31 |
| no authentication control detected on POST /Basket | Weakness (info) | S E | - | - | ep:qoeh2hmj2r | CWE-306 Entry point without a detected authentication control (review) at src/Web/Pages/Basket/Index.cshtml.cs:33 |
| no authentication control detected on GET /api/catalog-types | Weakness (info) | S E | - | - | ep:y3agugev4g | CWE-306 Entry point without a detected authentication control (review) at src/PublicApi/CatalogTypeEndpoints/CatalogTypeListEndpoint.cs:27 |
| no authentication control detected on GET /Account/Logout | Weakness (info) | S E | - | - | ep:gy22xxuukt | CWE-306 Entry point without a detected authentication control (review) at src/Web/Areas/Identity/Pages/Account/Logout.cshtml.cs:27 |
| no authentication control detected on GET /Basket | Weakness (info) | S E | - | - | ep:g7pwwz7lkd | CWE-306 Entry point without a detected authentication control (review) at src/Web/Pages/Basket/Index.cshtml.cs:28 |
| no authentication control detected on GET /Error | Weakness (info) | S E | - | - | ep:fhdletxi3a | CWE-306 Entry point without a detected authentication control (review) at src/Web/Pages/Error.cshtml.cs:14 |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:jijfgmeirg | CWE-306 Entry point without a detected authentication control (review) at src/Web/Pages/Index.cshtml.cs:18 |
| no authentication control detected on GET /Account/Register | Weakness (info) | S E | - | - | ep:j2vt6oh2cs | CWE-306 Entry point without a detected authentication control (review) at src/Web/Areas/Identity/Pages/Account/Register.cshtml.cs:61 |
| no authentication control detected on POST /Account/Login | Weakness (info) | S E | - | - | ep:aeggl6b5bg | CWE-306 Entry point without a detected authentication control (review) at src/Web/Areas/Identity/Pages/Account/Login.cshtml.cs:68 |
| no authentication control detected on POST /User/Logout | Weakness (info) | S E | - | - | ep:uogo7jtztz | CWE-306 Entry point without a detected authentication control (review) at src/Web/Controllers/UserController.cs:41 |
| no authentication control detected on GET /Account/ConfirmEmail | Weakness (info) | S E | - | - | ep:efsc5py3da | CWE-306 Entry point without a detected authentication control (review) at src/Web/Areas/Identity/Pages/Account/ConfirmEmail.cshtml.cs:23 |
| no authentication control detected on GET /api/catalog-brands | Weakness (info) | S E | - | - | ep:22fe3qzbc4 | CWE-306 Entry point without a detected authentication control (review) at src/PublicApi/CatalogBrandEndpoints/CatalogBrandListEndpoint.cs:27 |
| no authentication control detected on POST /Account/Logout | Weakness (info) | S E | - | - | ep:2jhjnagajw | CWE-306 Entry point without a detected authentication control (review) at src/Web/Areas/Identity/Pages/Account/Logout.cshtml.cs:31 |
| no authentication control detected on POST /Account/Register | Weakness (info) | S E | - | - | ep:yumgwikcub | CWE-306 Entry point without a detected authentication control (review) at src/Web/Areas/Identity/Pages/Account/Register.cshtml.cs:66 |
| no authentication control detected on GET /Account/Login | Weakness (info) | S E | - | - | ep:zbr3wvmfqd | CWE-306 Entry point without a detected authentication control (review) at src/Web/Areas/Identity/Pages/Account/Login.cshtml.cs:51 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | OrderService, GetMyOrdersHandler, GetOrderDetailsHandler | SQL Server: Order | - |
| financial | DeleteCatalogItemEndpoint, UpdateCatalogItemEndpoint, CatalogItemGetByIdEndpoint, CatalogItemViewModelService, OrderService, CreateCatalogItemEndpoint, CatalogItemListPagedEndpoint, CatalogContextSeed (+3) | SQL Server: BasketItem, SQL Server: CatalogItem, SQL Server: OrderItem | - |
