# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Insider with access to container: node-app | insider | container: node-app | OPTIONS * handler, POST /v1/auth/login handler, POST /v1/auth/send-verification-email handler, POST /v1/auth/forgot-password handler, POST /v1/auth/verify-email handler ... | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; abuse privileged functions | inferred |
| Compromised third party: SMTP mail relay | third_party | outside all boundaries | SMTP mail relay | - | return malicious responses; harvest data sent to it | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
