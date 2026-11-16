# code2design report: hackathon-starter

Commit `fb53b17c28c9`, code2design 0.5.2, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 56 |
| (test files, not modelled) | 36 |

Detectors: config@0.5, js@0.5, synth@0.5.2

Facts: app 1, config_value 24, control 63, dependencies 1, entry_point 90, listener 1, module 1, outbound_call 84, router 1, schema 65, store_access 70, weakness 7

## Model

| Collection | Count |
|---|---|
| processes | 107 |
| entities | 27 |
| stores | 3 |
| boundaries | 1 |
| flows | 213 |
| entry_points | 90 |
| controls | 12 |
| weaknesses | 63 |
| schemas | 28 |
| assets | 23 |
| threat_agents | 4 |
| gaps | 21 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 90 entry points, 56 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: app.js port app.get('port')
- **exit points carrying sensitive data**: SMTP mail relay, Stripe API, Unresolved HTTP target
- **third-party dependencies**: 62 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 6 high, 1 medium, 56 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| POST /login | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | SMTP mail relay, MongoDB: User |
| GET /api/nyt | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | www.alphavantage.co |
| POST /account/2fa/email/enable | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | MongoDB: User |
| POST /ai/rag/ingest | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /ai/ai-agent/reset | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /auth/discord/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | - |
| POST /login/2fa/totp | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | MongoDB: User |
| POST /account/profile | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | MongoDB: User |
| POST /forgot | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | SMTP mail relay, MongoDB: User |
| GET /api/wikipedia | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | www.alphavantage.co |
| GET /auth/twitch/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | - |
| GET /ai/llm-classifier | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /account/password | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | MongoDB: User |
| GET /forgot | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /ai/llm-classifier | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | Groq API |
| GET /auth/github/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | - |
| GET /logout | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /account/webauthn/register | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /signup | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | SMTP mail relay, MongoDB: User |
| GET /api/paypal/success | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | api.sandbox.paypal.com |
| GET /api/quickbooks | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | www.alphavantage.co |
| GET /auth/x/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | - |
| POST /reset/{token} | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | SMTP mail relay, MongoDB: User |
| GET /api/facebook | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | graph.facebook.com |
| GET /api/chart | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | www.alphavantage.co |
| POST /api/upload | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | - |
| POST /account/2fa/totp/setup | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | MongoDB: User |
| POST /account/2fa/email/remove | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | MongoDB: User |
| POST /account/logout-everywhere | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | - |
| GET /api/paypal/cancel | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /auth/tumblr/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | - |
| POST /login/2fa | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | MongoDB: User |
| GET /api/foursquare | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | www.alphavantage.co |
| POST /login/webauthn-verify | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | MongoDB: User |
| GET /auth/microsoft/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | - |
| GET /contact | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | - |
| GET /api/tumblr | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | api.tumblr.com, Unresolved HTTP target |
| GET /api/twilio | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /api/pubchem | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | pubchem.ncbi.nlm.nih.gov |
| GET /api/scraping | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | news.ycombinator.com |
| GET / | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /account/webauthn/verify | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | - |
| GET /api/upload | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, lusca | - |
| GET /ai | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /auth/linkedin/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | - |
| GET /api/google/sheets | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | Google Sheets API, Google Drive API |
| GET /login/verify/{token} | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | MongoDB: User |
| GET /api/twitch | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | api.twitch.tv |
| GET /signup | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /account | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | - |
| GET /account/2fa/totp/setup | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | MongoDB: User |
| GET /ai/llm-camera | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, lusca | - |
| GET /auth/failure | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /account/verify/{token} | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | - |
| POST /contact | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | SMTP mail relay, Unresolved HTTP target |
| GET /ai/ai-agent | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /ai/llm-camera | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | Groq API |
| GET /api/steam | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | www.alphavantage.co, Unresolved HTTP target |
| GET /login/2fa | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | SMTP mail relay, MongoDB: User |
| POST /account/webauthn/remove | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | - |
| GET /api/google-maps | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /api/stripe | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | Stripe API |
| POST /login/2fa/resend | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | SMTP mail relay, MongoDB: User |
| GET /api/lastfm | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /api/lob | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | Lob API, Unresolved HTTP target |
| GET /api/google/drive | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | Google Drive API |
| GET /login/webauthn-start | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| POST /ai/ai-agent/chat | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /api/paypal | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | api.sandbox.paypal.com |
| GET /auth/steam/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | - |
| GET /reset/{token} | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | MongoDB: User |
| GET /api | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /api/giphy | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | www.alphavantage.co |
| GET /auth/facebook/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | - |
| POST /ai/rag/ask | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | Groq API, MongoDB (collection unresolved) |
| GET /api/stripe | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /account/unlink/{provider} | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | Unresolved HTTP target, MongoDB: User |
| GET /api/here-maps | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection | - |
| GET /auth/quickbooks/callback | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | - |
| GET /login/2fa/totp | unknown | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | MongoDB: User |
| ... 10 more | | | |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| high | CWE-798 | hard-coded tokenURL literal | config/passport.js:703 |
| high | CWE-798 | hard-coded tokenURL literal | config/passport.js:730 |
| high | CWE-798 | hard-coded accessTokenURL literal | config/passport.js:582 |
| high | CWE-798 | hard-coded requestTokenURL literal | config/passport.js:581 |
| high | CWE-798 | hard-coded tokenURL literal | config/passport.js:487 |
| high | CWE-798 | hard-coded tokenURL literal | config/passport.js:434 |
| medium | CWE-319 | plain http:// to api.steampowered.com | config/passport.js:663 |
| info | CWE-306 | no authentication control detected on GET /auth/failure | app.js:345 |
| info | CWE-306 | no authentication control detected on POST /forgot | app.js:265 |
| info | CWE-306 | no authentication control detected on GET /login | app.js:252 |
| info | CWE-306 | no authentication control detected on GET /forgot | app.js:264 |
| info | CWE-306 | no authentication control detected on POST /ai/llm-classifier | app.js:328 |
| info | CWE-306 | no authentication control detected on GET /api/nyt | app.js:295 |
| info | CWE-306 | no authentication control detected on GET /api/lastfm | app.js:294 |
| info | CWE-306 | no authentication control detected on GET /login/webauthn-start | app.js:261 |
| info | CWE-306 | no authentication control detected on GET /signup | app.js:268 |
| info | CWE-306 | no authentication control detected on POST /reset/{token} | app.js:267 |
| info | CWE-306 | no authentication control detected on GET /api/lob | app.js:310 |
| info | CWE-306 | no authentication control detected on POST /login/2fa/totp | app.js:259 |
| info | CWE-306 | no authentication control detected on POST /contact | app.js:271 |
| info | CWE-306 | no authentication control detected on POST /ai/rag/ingest | app.js:332 |
| info | CWE-306 | no authentication control detected on GET /ai | app.js:326 |
| info | CWE-306 | no authentication control detected on GET /ai/llm-classifier | app.js:327 |
| info | CWE-306 | no authentication control detected on GET /api/google-maps | app.js:314 |
| info | CWE-306 | no authentication control detected on GET /api/paypal/cancel | app.js:309 |
| info | CWE-306 | no authentication control detected on GET /contact | app.js:270 |
| info | CWE-306 | no authentication control detected on GET /api/twilio | app.js:300 |
| info | CWE-306 | no authentication control detected on GET /login/2fa | app.js:255 |
| info | CWE-306 | no authentication control detected on GET /api/paypal | app.js:307 |
| info | CWE-306 | no authentication control detected on POST /api/upload | app.js:312 |
| info | CWE-306 | no authentication control detected on GET / | app.js:251 |
| info | CWE-306 | no authentication control detected on GET /api/giphy | app.js:321 |
| info | CWE-306 | no authentication control detected on POST /login/webauthn-verify | app.js:262 |
| info | CWE-306 | no authentication control detected on GET /api | app.js:293 |
| info | CWE-306 | no authentication control detected on GET /logout | app.js:263 |
| info | CWE-306 | no authentication control detected on GET /ai/ai-agent | app.js:334 |
| info | CWE-306 | no authentication control detected on POST /signup | app.js:269 |
| info | CWE-306 | no authentication control detected on GET /ai/llm-camera | app.js:329 |
| info | CWE-306 | no authentication control detected on GET /api/pubchem | app.js:319 |
| info | CWE-306 | no authentication control detected on GET /api/foursquare | app.js:302 |
| info | CWE-306 | no authentication control detected on POST /login | app.js:253 |
| info | CWE-306 | no authentication control detected on POST /ai/llm-camera | app.js:330 |
| info | CWE-306 | no authentication control detected on GET /api/scraping | app.js:299 |
| info | CWE-306 | no authentication control detected on GET /reset/{token} | app.js:266 |
| info | CWE-306 | no authentication control detected on POST /api/stripe | app.js:298 |
| info | CWE-306 | no authentication control detected on GET /login/2fa/totp | app.js:258 |
| info | CWE-306 | no authentication control detected on GET /account/webauthn/register | app.js:286 |
| info | CWE-306 | no authentication control detected on GET /ai/rag | app.js:331 |
| info | CWE-306 | no authentication control detected on GET /api/upload | app.js:311 |
| info | CWE-306 | no authentication control detected on GET /api/stripe | app.js:297 |
| info | CWE-306 | no authentication control detected on GET /api/here-maps | app.js:313 |
| info | CWE-306 | no authentication control detected on POST /ai/rag/ask | app.js:333 |
| info | CWE-306 | no authentication control detected on GET /api/wikipedia | app.js:320 |
| info | CWE-306 | no authentication control detected on GET /api/paypal/success | app.js:308 |
| info | CWE-306 | no authentication control detected on POST /api/twilio | app.js:301 |
| info | CWE-306 | no authentication control detected on GET /login/verify/{token} | app.js:254 |
| info | CWE-306 | no authentication control detected on POST /login/2fa | app.js:256 |
| info | CWE-306 | no authentication control detected on GET /api/chart | app.js:316 |
| info | CWE-306 | no authentication control detected on POST /ai/ai-agent/chat | app.js:335 |
| info | CWE-306 | no authentication control detected on POST /login/2fa/resend | app.js:257 |
| info | CWE-306 | no authentication control detected on POST /ai/ai-agent/reset | app.js:336 |
| info | CWE-306 | no authentication control detected on POST /login/webauthn-start | app.js:260 |
| info | CWE-306 | no authentication control detected on GET /api/github | app.js:305 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Google Sheets API | system | sheets.googleapis.com |
| Lob API | system | api.lob.com |
| news.ycombinator.com | system | news.ycombinator.com |
| api.linkedin.com | system | api.linkedin.com |
| graph.facebook.com | system | graph.facebook.com |
| www.alphavantage.co | system | www.alphavantage.co |
| Steam Openid identity provider | system | - |
| api.tumblr.com | system | api.tumblr.com |
| Last.fm API | system | - |
| Google Oauth identity provider | system | - |
| SMTP mail relay | system | - |
| Unresolved HTTP target | system | - |
| Github2 identity provider | system | - |
| Groq API | llm_api | api.groq.com |
| Twilio API | system | api.twilio.com |
| discord.com | system | discord.com |
| api.twitch.tv | system | api.twitch.tv |
| graph.microsoft.com | system | graph.microsoft.com |
| Google Drive API | system | www.googleapis.com |
| api.steampowered.com | system | api.steampowered.com |
| HTTP client | system | - |
| Facebook identity provider | system | - |
| Stripe API | system | api.stripe.com |
| GitHub API | system | api.github.com |
| pubchem.ncbi.nlm.nih.gov | system | pubchem.ncbi.nlm.nih.gov |
| api.sandbox.paypal.com | system | api.sandbox.paypal.com |
| Hugging Face Inference API | llm_api | api-inference.huggingface.co |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| MongoDB (collection unresolved) | mongodb | - | unknown | - |
| MongoDB: Session | mongodb | - | unknown | - |
| MongoDB: User | mongodb | credential, pii | unknown | - |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/lob handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/here-maps handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /contact handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/giphy handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/stripe handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /login/2fa/totp handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /ai/llm-classifier handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/paypal handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/google-maps handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /login/webauthn-start handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /login/verify/{token} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /ai/llm-classifier handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/chart handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/foursquare handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/twilio handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /login/2fa handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/paypal/cancel handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /reset/{token} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /ai/llm-camera handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/upload handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /ai/llm-camera handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /login/2fa/resend handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /forgot handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /signup handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /contact handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /auth/failure handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/twilio handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/github handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /signup handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/paypal/success handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/lastfm handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /login/webauthn-verify handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /ai/rag/ingest handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /ai/rag handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /reset/{token} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /forgot handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/pubchem handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/nyt handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/upload handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /ai/rag/ask handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /ai handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /account/webauthn/register handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /login/2fa/totp handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /login/2fa handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/wikipedia handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/stripe handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /ai/ai-agent handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /login/webauthn-start handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /ai/ai-agent/chat handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /logout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/scraping handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /ai/ai-agent/reset handler
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded tokenURL literal (config/passport.js:703)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded tokenURL literal (config/passport.js:730)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded accessTokenURL literal (config/passport.js:582)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded requestTokenURL literal (config/passport.js:581)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded tokenURL literal (config/passport.js:487)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded tokenURL literal (config/passport.js:434)
- **warning** `weakness-unencrypted-transport` CWE-319 plain http:// to api.steampowered.com (config/passport.js:663)
- **info** `black-hole-or-miracle` process GET /api/google-maps handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /account/verify/{token} handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /logout handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/tumblr/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/stripe handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/github handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /login handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process POST /login/2fa/totp handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process app has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /account handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /ai/ai-agent handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /ai/llm-camera handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/microsoft/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/linkedin/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /ai handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/lastfm handler has only inputs; a detector may be missing
- ... 109 more

## Inferred elements (dashed in diagrams)

- repository: hackathon-starter (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- passport -> Facebook identity provider (confidence 0.6): the Facebook identity provider SDK is imported in config/passport.js but no call site could be resolved
- passport -> Google Oauth identity provider (confidence 0.6): the Google Oauth identity provider SDK is imported in config/passport.js but no call site could be resolved
- api -> GitHub API (confidence 0.6): the GitHub API SDK is imported in controllers/api.js but no call site could be resolved
- passport -> Github2 identity provider (confidence 0.6): the Github2 identity provider SDK is imported in config/passport.js but no call site could be resolved
- passport -> Steam Openid identity provider (confidence 0.6): the Steam Openid identity provider SDK is imported in config/passport.js but no call site could be resolved
- Compromised external service (confidence 0.7): each of the 26 outbound dependencies is a potentially hostile responder
- Anonymous HTTP caller (confidence 0.9): 90 entry points are reachable from outside, 56 of them without a detected authentication control
- Authenticated HTTP caller (confidence 0.9): 34 entry points require authentication; a holder of valid credentials is a distinct agent
- Insider with access to repository: hackathon-starter (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` app.js:150: a mongodb access could not be traced to a collection; it is shown as a separate store
- `unresolved` config/passport.js:603: the target of an outbound call is built from a variable; the host is not resolvable statically
- `no_boundary_info` : no docker compose, Dockerfile, Kubernetes or Terraform descriptors were found; the repository is the only trust boundary
- `unresolved` models/Session.js:33: MongoDB: Session is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unknown_attribute` app.js: Question: is TLS terminated in front of the HTTP listener of hackathon-starter? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` controllers/user.js:725: Question: what is the authentication and encryption of the link to MongoDB: User?
- `unknown_attribute` controllers/api.js:88: Question: what is the authentication and encryption of the link to Unresolved HTTP target?
- `unknown_attribute` config/nodemailer.js:17: Question: what is the encryption of the link to SMTP mail relay?
- `unknown_attribute` controllers/ai-agent.js:184: Question: what is the authentication and encryption of the link to MongoDB (collection unresolved)?
- `unknown_attribute` config/passport.js:742: Question: what is the authentication of the link to discord.com?
- `unknown_attribute` controllers/api.js:241: Question: what is the authentication of the link to www.alphavantage.co?
- `unknown_attribute` controllers/api.js:956: Question: what is the authentication of the link to api.sandbox.paypal.com?
- `unknown_attribute` config/passport.js:501: Question: what is the authentication of the link to graph.microsoft.com?
- `unknown_attribute` config/passport.js:663: Question: what is the authentication of the link to api.steampowered.com?
- `unknown_attribute` controllers/api.js:142: Question: what is the authentication of the link to news.ycombinator.com?
- `unknown_attribute` controllers/api.js:121: Question: what is the authentication of the link to graph.facebook.com?
- `unknown_attribute` controllers/api.js:589: Question: what is the authentication of the link to api.twitch.tv?
- `unknown_attribute` controllers/api.js:1243: Question: what is the authentication of the link to pubchem.ncbi.nlm.nih.gov?
- `unknown_attribute` config/passport.js:446: Question: what is the authentication of the link to api.linkedin.com?
- `unknown_attribute` controllers/api.js:97: Question: what is the authentication of the link to api.tumblr.com?
- `unknown_attribute` models/User.js:287: Question: is MongoDB: User encrypted at rest? It holds credential, pii.
