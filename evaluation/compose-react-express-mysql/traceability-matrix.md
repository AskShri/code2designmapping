# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Compromised external service | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: backend | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Anonymous HTTP caller | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to container: frontend | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | Unresolved HTTP target | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: backend | insider | container: backend | healthcheck, GET /healthz handler, GET / handler | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: frontend | insider | container: frontend | frontend | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret DATABASE_PASSWORD | credential | secret | backend | backend |
