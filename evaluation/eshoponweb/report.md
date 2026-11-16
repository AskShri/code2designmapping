# code2design report: eshoponweb

Commit `4da8212117e8`, code2design 0.5.2, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| c_sharp | 244 |
| (test files, not modelled) | 45 |

Detectors: config@0.5, csharp@0.5, synth@0.5.2

Facts: app 2, boundary_hint 7, config_value 4, control 21, entry_point 50, listener 2, outbound_call 6, router 23, schema 7, store_access 53, weakness 3

## Model

| Collection | Count |
|---|---|
| processes | 67 |
| entities | 2 |
| stores | 7 |
| boundaries | 3 |
| flows | 95 |
| entry_points | 49 |
| controls | 9 |
| weaknesses | 21 |
| schemas | 7 |
| assets | 6 |
| threat_agents | 5 |
| gaps | 13 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 49 entry points, 18 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: src/PublicApi/Program.cs port ? (TLS), src/Web/Program.cs port ? (TLS)
- **exit points carrying sensitive data**: none detected
- **weaknesses**: 3 high, 18 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /api/catalog-brands | unknown | none | SQL Server: CatalogBrand |
| POST /Manage/Disable2fa | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| POST /Manage/RemoveLogin | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| POST /Account/Logout | unknown | none | - |
| GET /Manage/ResetAuthenticatorWarning | unknown | [Authorize] | - |
| POST /Manage/ChangePassword | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| GET /Manage/MyAccount | unknown | [Authorize] | - |
| DELETE /api/catalog-items/{catalogItemId} | unknown | [Authorize] | SQL Server: CatalogItem |
| POST /Account/Login | unknown | none | - |
| POST /Manage/ResetAuthenticator | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| GET /Order/MyOrders | unknown | [Authorize] | - |
| GET /Order/Detail/{orderId} | unknown | [Authorize] | - |
| GET /Manage/ExternalLogins | unknown | [Authorize] | - |
| GET /Basket/Checkout | unknown | [Authorize] | SQL Server: Basket, SQL Server: CatalogItem |
| GET /Account/ConfirmEmail | unknown | none | - |
| GET /Error | unknown | none | - |
| POST /Manage/MyAccount | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| GET /Basket | unknown | none | SQL Server: Basket, SQL Server: CatalogItem |
| GET /Account/Logout | unknown | none | - |
| GET /Manage/LinkLoginCallback | unknown | [Authorize] | - |
| GET /Basket/Success | unknown | [Authorize] | - |
| GET /Manage/ChangePassword | unknown | [Authorize] | - |
| GET /api/catalog-items | unknown | none | SQL Server: CatalogItem |
| GET /Account/Register | unknown | none | - |
| GET / | unknown | none | SQL Server: CatalogType, SQL Server: CatalogItem, SQL Server: CatalogBrand |
| POST /api/catalog-items | unknown | [Authorize] | SQL Server: CatalogItem |
| POST /Admin/EditCatalogItem | unknown | [Authorize] | - |
| GET /Manage/SetPassword | unknown | [Authorize] | - |
| GET /Admin/EditCatalogItem | unknown | [Authorize] | - |
| GET /Manage/Disable2faWarning | unknown | [Authorize] | - |
| GET /Manage/TwoFactorAuthentication | unknown | [Authorize] | - |
| POST /Manage/GenerateRecoveryCodes | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| POST /Manage/LinkLogin | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| POST /Basket | unknown | none | SQL Server: Basket, SQL Server: CatalogItem |
| POST /Manage/EnableAuthenticator | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| GET /Manage/EnableAuthenticator | unknown | [Authorize] | - |
| POST /Manage/SetPassword | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| GET /Manage/ShowRecoveryCodes | unknown | [Authorize] | - |
| GET /Manage/GenerateRecoveryCodesWarning | unknown | [Authorize] | - |
| POST /User/Logout | unknown | none | - |
| GET /User | unknown | none | - |
| POST /Manage/SendVerificationEmail | unknown | [Authorize], [ValidateAntiForgeryToken] | - |
| GET /api/catalog-items/{catalogItemId} | unknown | none | SQL Server: CatalogItem |
| GET /api/catalog-types | unknown | none | SQL Server: CatalogType |
| PUT /api/catalog-items | unknown | [Authorize] | SQL Server: CatalogItem |
| POST /Account/Register | unknown | none | - |
| GET /Privacy | unknown | none | - |
| GET /Account/Login | unknown | none | - |
| POST /Basket/Checkout | unknown | [Authorize] | SQL Server: Basket, SQL Server: CatalogItem, SQL Server: Order |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| high | CWE-798 | hard-coded DEFAULT_PASSWORD | src/ApplicationCore/Constants/AuthorizationConstants.cs:8 |
| high | CWE-798 | SA_PASSWORD set in compose service 'sqlserver' | docker-compose.yml:23 |
| high | CWE-798 | hard-coded JWT_SECRET_KEY | src/ApplicationCore/Constants/AuthorizationConstants.cs:11 |
| info | CWE-306 | no authentication control detected on GET /User | src/Web/Controllers/UserController.cs:35 |
| info | CWE-306 | no authentication control detected on GET /api/catalog-items/{catalogItemId} | src/PublicApi/CatalogItemEndpoints/CatalogItemGetByIdEndpoint.cs:25 |
| info | CWE-306 | no authentication control detected on GET /Privacy | src/Web/Pages/Privacy.cshtml.cs:7 |
| info | CWE-306 | no authentication control detected on GET /api/catalog-items | src/PublicApi/CatalogItemEndpoints/CatalogItemListPagedEndpoint.cs:31 |
| info | CWE-306 | no authentication control detected on POST /Basket | src/Web/Pages/Basket/Index.cshtml.cs:33 |
| info | CWE-306 | no authentication control detected on GET /api/catalog-types | src/PublicApi/CatalogTypeEndpoints/CatalogTypeListEndpoint.cs:27 |
| info | CWE-306 | no authentication control detected on GET /Account/Logout | src/Web/Areas/Identity/Pages/Account/Logout.cshtml.cs:27 |
| info | CWE-306 | no authentication control detected on GET /Basket | src/Web/Pages/Basket/Index.cshtml.cs:28 |
| info | CWE-306 | no authentication control detected on GET /Error | src/Web/Pages/Error.cshtml.cs:14 |
| info | CWE-306 | no authentication control detected on GET / | src/Web/Pages/Index.cshtml.cs:18 |
| info | CWE-306 | no authentication control detected on GET /Account/Register | src/Web/Areas/Identity/Pages/Account/Register.cshtml.cs:61 |
| info | CWE-306 | no authentication control detected on POST /Account/Login | src/Web/Areas/Identity/Pages/Account/Login.cshtml.cs:68 |
| info | CWE-306 | no authentication control detected on POST /User/Logout | src/Web/Controllers/UserController.cs:41 |
| info | CWE-306 | no authentication control detected on GET /Account/ConfirmEmail | src/Web/Areas/Identity/Pages/Account/ConfirmEmail.cshtml.cs:23 |
| info | CWE-306 | no authentication control detected on GET /api/catalog-brands | src/PublicApi/CatalogBrandEndpoints/CatalogBrandListEndpoint.cs:27 |
| info | CWE-306 | no authentication control detected on POST /Account/Logout | src/Web/Areas/Identity/Pages/Account/Logout.cshtml.cs:31 |
| info | CWE-306 | no authentication control detected on POST /Account/Register | src/Web/Areas/Identity/Pages/Account/Register.cshtml.cs:66 |
| info | CWE-306 | no authentication control detected on GET /Account/Login | src/Web/Areas/Identity/Pages/Account/Login.cshtml.cs:51 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Unresolved HTTP target | system | - |
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| SQL Server: Basket | mssql | - | unknown | container: sqlserver |
| SQL Server: BasketItem | mssql | financial | unknown | container: sqlserver |
| SQL Server: CatalogType | mssql | - | unknown | container: sqlserver |
| SQL Server: CatalogItem | mssql | financial | unknown | container: sqlserver |
| SQL Server: CatalogBrand | mssql | - | unknown | container: sqlserver |
| SQL Server: Order | mssql | pii | unknown | container: sqlserver |
| SQL Server: OrderItem | mssql | financial | unknown | container: sqlserver |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /Error handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /Account/Login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /User/Logout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /Account/Register handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/catalog-items handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/catalog-items/{catalogItemId} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /Account/Logout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /Basket handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /Account/Login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/catalog-brands handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /User handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/catalog-types handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /Basket handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /Privacy handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /Account/Register handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /Account/Logout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /Account/ConfirmEmail handler
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded DEFAULT_PASSWORD (src/ApplicationCore/Constants/AuthorizationConstants.cs:8)
- **warning** `weakness-plaintext-credentials` CWE-798 SA_PASSWORD set in compose service 'sqlserver' (docker-compose.yml:23)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded JWT_SECRET_KEY (src/ApplicationCore/Constants/AuthorizationConstants.cs:11)
- **info** `black-hole-or-miracle` process POST /Manage/ResetAuthenticator handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET|POST /Manage/SetPassword handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Privacy handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Manage/Disable2fa handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Manage/LinkLogin handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /User/Logout handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Admin/EditCatalogItem handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Basket/Success handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Manage/Disable2faWarning handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Account/Register handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process CatalogBrandListEndpoint has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET|POST /Manage/MyAccount handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Account/ConfirmEmail handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Account/Logout handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process CatalogItemGetByIdEndpoint has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Manage/ExternalLogins handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET|POST /Manage/ChangePassword handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Manage/TwoFactorAuthentication handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Manage/SendVerificationEmail handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Account/Login handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Manage/GenerateRecoveryCodesWarning handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GetMyOrdersHandler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET|POST /Manage/EnableAuthenticator handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Manage/GenerateRecoveryCodes handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process CustomAuthStateProvider has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process CatalogItemListPagedEndpoint has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GetOrderDetailsHandler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Manage/RemoveLogin handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Order/Detail/{orderId} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Account/Logout handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Error handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Account/Login handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /Admin/EditCatalogItem handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process CatalogLookupDataService has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Account/Register handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Manage/ResetAuthenticatorWarning handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process HttpService has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process CatalogViewModelService has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /User handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Order/MyOrders handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Manage/LinkLoginCallback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process CatalogTypeListEndpoint has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /Manage/ShowRecoveryCodes handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` SQL Server: CatalogType -> CatalogContextSeed: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: Basket -> BasketViewModelService: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` CustomAuthStateProvider -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogItem -> UpdateCatalogItemEndpoint: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogType -> CatalogTypeListEndpoint: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogBrand -> CatalogBrandListEndpoint: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: Order -> GetMyOrdersHandler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` HttpService -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogItem -> CatalogItemViewModelService: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogBrand -> CatalogContextSeed: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: Basket -> BasketService: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogItem -> CreateCatalogItemEndpoint: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` CatalogContextSeed -> SQL Server: CatalogBrand: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogType -> CatalogViewModelService: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL Server: CatalogBrand -> CatalogViewModelService: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` OrderService -> SQL Server: Order: authentication=unknown, encryption=unknown
- ... 19 more

## Inferred elements (dashed in diagrams)

- repository: eshoponweb (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Compromised external service (confidence 0.7): each of the 1 outbound dependencies is a potentially hostile responder
- Anonymous HTTP caller (confidence 0.9): 49 entry points are reachable from outside, 18 of them without a detected authentication control
- Insider with access to repository: eshoponweb (confidence 0.8): one insider agent per trust boundary, placed inside it
- Authenticated HTTP caller (confidence 0.9): 31 entry points require authentication; a holder of valid credentials is a distinct agent
- Insider with access to container: eshoppublicapi (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` src/BlazorAdmin/CustomAuthStateProvider.cs:57: the target of an outbound call is built from a variable; the host is not resolvable statically
- `unresolved` src/Infrastructure/Data/CatalogContext.cs:20: SQL Server: BasketItem is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unresolved` src/Infrastructure/Data/CatalogContext.cs:19: SQL Server: OrderItem is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unknown_attribute` src/Infrastructure/Data/CatalogContextSeed.cs:32: Question: what is the authentication and encryption of the link to SQL Server: CatalogType?
- `unknown_attribute` src/Web/Services/BasketViewModelService.cs:31: Question: what is the authentication and encryption of the link to SQL Server: Basket?
- `unknown_attribute` src/BlazorAdmin/CustomAuthStateProvider.cs:57: Question: what is the authentication and encryption of the link to Unresolved HTTP target?
- `unknown_attribute` src/PublicApi/CatalogItemEndpoints/UpdateCatalogItemEndpoint.cs:41: Question: what is the authentication and encryption of the link to SQL Server: CatalogItem?
- `unknown_attribute` src/PublicApi/CatalogBrandEndpoints/CatalogBrandListEndpoint.cs:40: Question: what is the authentication and encryption of the link to SQL Server: CatalogBrand?
- `unknown_attribute` src/Web/Features/MyOrders/GetMyOrdersHandler.cs:22: Question: what is the authentication and encryption of the link to SQL Server: Order?
- `unknown_attribute` src/Infrastructure/Data/CatalogContext.cs:20: Question: is SQL Server: BasketItem encrypted at rest? It holds financial.
- `unknown_attribute` src/Infrastructure/Data/CatalogContext.cs:15: Question: is SQL Server: CatalogItem encrypted at rest? It holds financial.
- `unknown_attribute` src/Infrastructure/Data/CatalogContext.cs:18: Question: is SQL Server: Order encrypted at rest? It holds pii.
- `unknown_attribute` src/Infrastructure/Data/CatalogContext.cs:19: Question: is SQL Server: OrderItem encrypted at rest? It holds financial.
