# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Insider with access to container: web | insider | container: web | GET / handler, app | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
