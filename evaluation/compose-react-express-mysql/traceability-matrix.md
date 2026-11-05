# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|
| Insider with access to container: backend | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent |
| Anonymous HTTP caller | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent |
| Compromised third party: Unresolved HTTP target | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent |
| Insider with access to container: frontend | Secret DATABASE_PASSWORD | no path | - | - | unreachable from this agent |

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Insider with access to container: backend | insider | container: backend | healthcheck, GET /healthz handler, GET / handler | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Compromised third party: Unresolved HTTP target | third_party | outside all boundaries | Unresolved HTTP target | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to container: frontend | insider | container: frontend | frontend | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret DATABASE_PASSWORD | credential | secret | backend | backend |
