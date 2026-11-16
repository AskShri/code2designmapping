# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Insider with access to repository: spring-petclinic | Personal data (PII) | VisitController -> SQL database: owners | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> POST /owners/new handler -> SQL database: owners | none | @Valid | NO BLOCKING CONTROL on the weakest path: potential attack path |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Insider with access to repository: spring-petclinic | insider | repository: spring-petclinic | GET /oups handler, GET /owners/{ownerId}/pets/{petId}/visits/new handler, GET /owners/{ownerId}/pets/new handler, GET /owners/new handler, GET /owners/{ownerId}/edit handler (+17) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Personal data (PII) | data | pii | SQL database: pets, SQL database: owners | VisitController, POST /owners/new handler, OwnerController, POST /owners/{ownerId}/edit handler, POST /owners/{ownerId}/pets/{petId}/visits/new handler, POST /owners/{ownerId}/pets/new handler, POST /owners/{ownerId}/pets/{petId}/edit handler, PetController (+1) |
