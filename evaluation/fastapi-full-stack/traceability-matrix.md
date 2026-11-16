# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Insider with access to repository: fastapi-full-stack | Personal data (PII) | PATCH /api/v1/users/me handler (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to repository: fastapi-full-stack | User credentials | PATCH /api/v1/users/me handler -> Postgres: user | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Workload inside the deployment calling HTTP client endpoints | Personal data (PII) | Internal HTTP client -> POST /api/v1/private/users handler | none | CORSMiddleware | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Workload inside the deployment calling HTTP client endpoints | User credentials | Internal HTTP client -> POST /api/v1/private/users handler -> Postgres: user | none | CORSMiddleware | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret EMAIL_RESET_TOKEN_EXPIRE_HOURS | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret FIRST_SUPERUSER_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret ACCESS_TOKEN_EXPIRE_MINUTES | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Personal data (PII) | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | User credentials | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret SENTRY_DSN | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret SMTP_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Compromised external service | Secret SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: fastapi-full-stack | Secret EMAIL_RESET_TOKEN_EXPIRE_HOURS | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: fastapi-full-stack | Secret FIRST_SUPERUSER_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: fastapi-full-stack | Secret ACCESS_TOKEN_EXPIRE_MINUTES | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: fastapi-full-stack | Secret SENTRY_DSN | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: fastapi-full-stack | Secret SMTP_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Insider with access to repository: fastapi-full-stack | Secret SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret EMAIL_RESET_TOKEN_EXPIRE_HOURS | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret FIRST_SUPERUSER_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret ACCESS_TOKEN_EXPIRE_MINUTES | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret SENTRY_DSN | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret SMTP_PASSWORD | no path | - | - | unreachable from this agent over the modelled flows |
| Workload inside the deployment calling HTTP client endpoints | Secret SECRET_KEY | no path | - | - | unreachable from this agent over the modelled flows |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | Sentry | - | return malicious responses; harvest data sent to it | inferred |
| Insider with access to repository: fastapi-full-stack | insider | repository: fastapi-full-stack | POST /api/v1/password-recovery/{email} handler, PATCH /api/v1/users/me handler, DELETE /api/v1/users/me handler, POST /api/v1/items handler, POST /api/v1/private/users handler (+20) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |
| Workload inside the deployment calling HTTP client endpoints | insider | outside all boundaries | Internal HTTP client | - | call internal services directly | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret EMAIL_RESET_TOKEN_EXPIRE_HOURS | credential | secret | backend | backend |
| Secret FIRST_SUPERUSER_PASSWORD | credential | secret | backend | backend |
| Secret ACCESS_TOKEN_EXPIRE_MINUTES | credential | secret | backend | backend |
| Personal data (PII) | data | pii | - | PATCH /api/v1/users/me handler, POST /api/v1/private/users handler, POST /api/v1/reset-password handler, POST /api/v1/users/signup handler, crud |
| User credentials | data | credential | Postgres: user | DELETE /api/v1/users/me handler, POST /api/v1/private/users handler, POST /api/v1/login/access-token handler, POST /api/v1/users handler, DELETE /api/v1/users/{user_id} handler, GET /api/v1/users/{user_id} handler, PATCH /api/v1/users/me/password handler, POST /api/v1/reset-password handler (+6) |
| Secret SENTRY_DSN | credential | secret | backend | backend |
| Secret SMTP_PASSWORD | credential | secret | backend | backend |
| Secret SECRET_KEY | credential | secret | backend | backend |
