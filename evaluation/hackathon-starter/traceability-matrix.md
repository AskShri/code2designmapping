# Control-path traceability matrix

One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.

| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |
|---|---|---|---|---|---|
| Compromised external service | Secret TWITCH_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret PAYPAL_SECRET | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret MICROSOFT_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret FOURSQUARE_APIKEY | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret GROQ_API_KEY | Groq API -> ai | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret TUMBLR_SECRET | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Personal data (PII) | api.linkedin.com -> passport -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret QUICKBOOKS_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | User credentials | api.linkedin.com -> passport -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret GITHUB_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret HERE_API_KEY | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret SMTP_PASSWORD | SMTP mail relay -> nodemailer | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret FACEBOOK_SECRET | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret X_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret GOOGLE_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret GOOGLE_MAP_API_KEY | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret TWILIO_TOKEN | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret SESSION_SECRET | Google Sheets API -> api -> app | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret LINKEDIN_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret LASTFM_SECRET | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret GOOGLE_API_KEY | SMTP mail relay -> contact | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret GIPHY_API_KEY | Google Sheets API -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Compromised external service | Secret DISCORD_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret TWITCH_CLIENT_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret PAYPAL_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret MICROSOFT_CLIENT_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret FOURSQUARE_APIKEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret GROQ_API_KEY | HTTP client -> POST /ai/llm-camera handler -> ai | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret TUMBLR_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Personal data (PII) | HTTP client -> POST /signup handler -> MongoDB: User | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret QUICKBOOKS_CLIENT_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | User credentials | HTTP client -> POST /signup handler -> MongoDB: User | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret GITHUB_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret HERE_API_KEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret SMTP_PASSWORD | HTTP client -> POST /signup handler -> nodemailer | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret FACEBOOK_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret X_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret GOOGLE_CLIENT_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret GOOGLE_MAP_API_KEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret TWILIO_TOKEN | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret SESSION_SECRET | HTTP client -> POST /ai/llm-camera handler -> ai -> app | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret LINKEDIN_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret LASTFM_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret GOOGLE_API_KEY | HTTP client -> POST /contact handler -> contact | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret GIPHY_API_KEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Anonymous HTTP caller | Secret DISCORD_CLIENT_SECRET | HTTP client -> POST /signup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret PAYPAL_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret FOURSQUARE_APIKEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret GROQ_API_KEY | HTTP client -> POST /ai/llm-camera handler -> ai | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret TUMBLR_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret HERE_API_KEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret SMTP_PASSWORD | HTTP client -> POST /signup handler -> nodemailer | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret FACEBOOK_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret GOOGLE_MAP_API_KEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret TWILIO_TOKEN | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret SESSION_SECRET | HTTP client -> POST /ai/llm-camera handler -> ai -> app | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret LASTFM_SECRET | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret GOOGLE_API_KEY | HTTP client -> POST /contact handler -> contact | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret GIPHY_API_KEY | HTTP client -> GET /api/wikipedia handler -> api | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret TWITCH_CLIENT_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret PAYPAL_SECRET | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret MICROSOFT_CLIENT_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret FOURSQUARE_APIKEY | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GROQ_API_KEY | POST /ai/llm-camera handler -> ai | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret TUMBLR_SECRET | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Personal data (PII) | POST /account/2fa/totp/setup handler -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret QUICKBOOKS_CLIENT_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | User credentials | POST /account/2fa/totp/setup handler -> MongoDB: User | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GITHUB_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret HERE_API_KEY | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret SMTP_PASSWORD | POST /signup handler -> nodemailer | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret FACEBOOK_SECRET | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret X_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GOOGLE_CLIENT_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GOOGLE_MAP_API_KEY | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret TWILIO_TOKEN | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret SESSION_SECRET | app (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to repository: hackathon-starter | Secret LINKEDIN_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret LASTFM_SECRET | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GOOGLE_API_KEY | app -> contact | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GIPHY_API_KEY | GET /api/wikipedia handler -> api | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret DISCORD_CLIENT_SECRET | app -> passport | none | none | NO BLOCKING CONTROL on the weakest path: potential attack path |
| Authenticated HTTP caller | Secret TWITCH_CLIENT_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Secret MICROSOFT_CLIENT_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Personal data (PII) | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Secret QUICKBOOKS_CLIENT_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | User credentials | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Secret GITHUB_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Secret X_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Secret GOOGLE_CLIENT_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Secret LINKEDIN_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |
| Authenticated HTTP caller | Secret DISCORD_CLIENT_SECRET | HTTP client -> POST /account/2fa/totp/setup handler -> MongoDB: User -> passport | none | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication only: no authorization control detected on the path (check object- and function-level access) |

## Threat agent profiles

| Agent | Access | Location | Starts at | Holds | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised external service | third_party | outside all boundaries | Google Sheets API, Lob API, news.ycombinator.com, api.linkedin.com, graph.facebook.com (+21) | - | return malicious responses; harvest data sent to it | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; use functions beyond their role | inferred |
| Insider with access to repository: hackathon-starter | insider | repository: hackathon-starter | GET /api/google-maps handler, GET /api/google/sheets handler, GET /api/lob handler, POST /ai/llm-camera handler, POST /account/2fa/totp/setup handler (+20) | authn, authz, rate_limit, input_validation, csrf, cors, security_headers, audit_log | read data stores directly; exfiltrate secrets | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret TWITCH_CLIENT_SECRET | credential | secret | passport | passport |
| Secret PAYPAL_SECRET | credential | secret | api | api |
| Secret MICROSOFT_CLIENT_SECRET | credential | secret | passport | passport |
| Secret FOURSQUARE_APIKEY | credential | secret | api | api |
| Secret GROQ_API_KEY | credential | secret | ai, ai-agent | ai, ai-agent |
| Secret TUMBLR_SECRET | credential | secret | api, passport | api, passport |
| Personal data (PII) | data | pii | MongoDB: User | POST /account/2fa/totp/setup handler, POST /signup handler, POST /login handler, POST /login/2fa/totp handler, POST /forgot handler, POST /account/2fa/totp/remove handler, POST /login/webauthn-start handler, POST /reset/{token} handler (+19) |
| Secret QUICKBOOKS_CLIENT_SECRET | credential | secret | passport | passport |
| User credentials | data | credential | MongoDB: User | POST /account/2fa/totp/setup handler, POST /signup handler, POST /login handler, POST /login/2fa/totp handler, POST /forgot handler, POST /account/2fa/totp/remove handler, POST /reset/{token} handler, GET /reset/{token} handler (+17) |
| Secret GITHUB_SECRET | credential | secret | passport | passport |
| Secret HERE_API_KEY | credential | secret | api | api |
| Secret SMTP_PASSWORD | credential | secret | nodemailer | nodemailer |
| Secret FACEBOOK_SECRET | credential | secret | api, passport | api, passport |
| Secret X_SECRET | credential | secret | passport | passport |
| Secret GOOGLE_CLIENT_SECRET | credential | secret | passport | passport |
| Secret GOOGLE_MAP_API_KEY | credential | secret | api | api |
| Secret TWILIO_TOKEN | credential | secret | api | api |
| Secret SESSION_SECRET | credential | secret | app | app |
| Secret LINKEDIN_SECRET | credential | secret | passport | passport |
| Secret LASTFM_SECRET | credential | secret | api | api |
| Secret GOOGLE_API_KEY | credential | secret | contact | contact |
| Secret GIPHY_API_KEY | credential | secret | api | api |
| Secret DISCORD_CLIENT_SECRET | credential | secret | passport | passport |
