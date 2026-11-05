# code2design report: hackathon-starter

Commit `fb53b17c28c9`, tool 0.3.0-prototype, 0.4s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 56 |
| (test files skipped) | 36 |

Detectors that ran: config@0.3, js@0.3

Facts: app_entry 1, config_value 34, control 69, dependencies 1, entry_point 101, listener 1, module 1, outbound_call 88, schema 8, store_access 87

## Model

| Collection | Count |
|---|---|
| processes | 118 |
| entities | 28 |
| stores | 2 |
| boundaries | 1 |
| flows | 240 |
| entry_points | 101 |
| controls | 12 |
| weaknesses | 88 |
| schemas | 3 |
| assets | 21 |
| threat_agents | 30 |
| gaps | 23 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 101 entry points, 70 without a detected authn control
- **listeners**: app.js port app.get('port')
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 62 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| POST /ai/ai-agent/reset | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /ai/llm-camera | limiter, lusca, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/github | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/google/callback | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger |
| GET /api/lob | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/giphy | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/google-maps | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /ai/ai-agent/chat | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/here-maps | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/github/callback | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger |
| POST /reset/:token | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger |
| POST /login | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger |
| POST /signup | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /login/webauthn-start | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/x | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /signup | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/discord | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /login/webauthn-verify | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger |
| POST /forgot | limiter, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger |
| GET /logout | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/steam | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/nyt | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/github | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /login/webauthn-start | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger |
| GET /login | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/quickbooks | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/foursquare | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/discord/callback | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger |
| GET /account/unlink/:provider | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /account/2fa/email/remove | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /account/2fa/totp/setup | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/microsoft | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /account/webauthn/register | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /account/verify | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /account/logout-everywhere | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/paypal/cancel | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /contact | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/failure | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /ai/rag | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /ai/rag/ask | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/scraping | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/twitch | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/facebook/callback | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger |
| GET /api/facebook | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /account/webauthn/remove | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/quickbooks | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/twitch | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /ai/ai-agent | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /login/2fa | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /login/2fa/totp | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/chart | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/linkedin | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/twilio | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /auth/linkedin/callback | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger |
| GET /auth/tumblr/callback | limiter, lusca.xframe, lusca.xssProtection, passport.authorize, morganLogger |
| POST /login/2fa | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /account/2fa/totp/setup | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| POST /account/delete | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| GET /api/wikipedia | limiter, lusca.xframe, lusca.xssProtection, morganLogger |
| ... 41 more | |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Google Sheets API | system | sheets.googleapis.com |
| Lob API | system | api.lob.com |
| Oauth1 identity provider | system | - |
| news.ycombinator.com | system | news.ycombinator.com |
| api.linkedin.com | system | api.linkedin.com |
| api.groq.com | system | api.groq.com |
| graph.facebook.com | system | graph.facebook.com |
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
| HTTP client | system | - |
| Facebook identity provider | system | - |
| Stripe API | system | api.stripe.com |
| GitHub API | system | api.github.com |
| pubchem.ncbi.nlm.nih.gov | system | pubchem.ncbi.nlm.nih.gov |
| api.sandbox.paypal.com | system | api.sandbox.paypal.com |
| Hugging Face Inference API | llm_api | api-inference.huggingface.co |
| Oauth2 Refresh identity provider | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| MongoDB | mongodb | - | - |
| MongoDB: User | mongodb | - | - |

## Lint

- **warning** `unknown-link-attributes` api -> news.ycombinator.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` ai -> MongoDB: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` user -> MongoDB: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` ai-agent -> MongoDB: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` api -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB -> passport: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` contact -> SMTP mail relay: authentication=credentials, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: User -> webauthn: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` passport -> MongoDB: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` passport -> api.linkedin.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` token-revocation -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` contact -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` passport -> graph.microsoft.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` app -> MongoDB: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB -> ai: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB -> webauthn: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` passport -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB -> User: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` user -> MongoDB: User: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: User -> user: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` api -> api.sandbox.paypal.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` MongoDB: User -> passport: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` nodemailer -> SMTP mail relay: authentication=credentials, encryption=unknown
- **warning** `unknown-link-attributes` passport -> discord.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` user -> SMTP mail relay: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB -> user: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` webauthn -> MongoDB: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` api -> graph.facebook.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` api -> pubchem.ncbi.nlm.nih.gov: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` api -> api.tumblr.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` api -> api.twitch.tv: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` ai -> api.groq.com: authentication=unknown, encryption=tls
- **warning** `unknown-link-attributes` MongoDB -> ai-agent: authentication=unknown, encryption=unknown
- **info** `black-hole-or-miracle` process GET /auth/quickbooks/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/steam handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/x handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/twitch/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/github handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/quickbooks handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/github/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/google handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/tumblr/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/microsoft handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/microsoft/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /account/webauthn/register handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/discord handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/discord/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /login/webauthn-start handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process User has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/google/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/tumblr handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/linkedin/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/linkedin handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/facebook/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/facebook handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/steam/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/twitch handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process app has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/x/callback handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /auth/failure handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: hackathon-starter (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Compromised third party: Oauth2 Refresh identity provider (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: discord.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Oauth1 identity provider (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: GitHub API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Twilio API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Last.fm API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: pubchem.ncbi.nlm.nih.gov (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Groq API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Google Oauth identity provider (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: news.ycombinator.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: api.sandbox.paypal.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Google Sheets API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: api.groq.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: graph.microsoft.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: api.tumblr.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Anonymous HTTP caller (confidence 0.9): 101 http entry points, 70 without a detected authn control
- Compromised third party: Steam Openid identity provider (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: api.linkedin.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Lob API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Unresolved HTTP target (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Facebook identity provider (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Stripe API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Google Drive API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Authenticated HTTP caller (confidence 0.9): authn controls exist on some entry points; a valid credential holder is a distinct agent
- Insider with access to repository: hackathon-starter (confidence 0.8): one insider agent per trust boundary, placed inside it
- Compromised third party: graph.facebook.com (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Github2 identity provider (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: SMTP mail relay (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: api.twitch.tv (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Hugging Face Inference API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder

## Gaps and questions

- `unresolved` config/passport.js:603: outbound call target is a variable:userInfoURL expression; host not resolvable statically
- `unresolved` config/passport.js:663: outbound call target is a variable:profileURL expression; host not resolvable statically
- `unresolved` config/token-revocation.js:110: outbound call target is a variable:finalURL expression; host not resolvable statically
- `unresolved` controllers/api.js:41: outbound call target is a variable:url expression; host not resolvable statically
- `unresolved` controllers/api.js:384: outbound call target is a variable:recentGamesURL expression; host not resolvable statically
- `unresolved` controllers/api.js:399: outbound call target is a variable:achievementsURL expression; host not resolvable statically
- `unresolved` controllers/api.js:1090: outbound call target is a variable:urlToCheck expression; host not resolvable statically
- `no_boundary_info` : No compose, Dockerfile or Kubernetes manifests found; the repository is the only trust boundary.
- `unknown_attribute` app.js: Question for the team: is TLS terminated in front of the HTTP listener on port app.get('port')? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` app.js:150: Question for the team: how is the link to MongoDB authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` config/passport.js:23: Question for the team: how is the link to MongoDB: User authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` config/nodemailer.js:17: Question for the team: how is the link to SMTP mail relay authenticated and is it encrypted in transit? (authentication=credentials, encryption=unknown)
- `unknown_attribute` config/passport.js:446: Question for the team: how is the link to api.linkedin.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` config/passport.js:501: Question for the team: how is the link to graph.microsoft.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` config/passport.js:603: Question for the team: how is the link to Unresolved HTTP target authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` config/passport.js:742: Question for the team: how is the link to discord.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` controllers/ai.js:654: Question for the team: how is the link to api.groq.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` controllers/api.js:97: Question for the team: how is the link to api.tumblr.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` controllers/api.js:121: Question for the team: how is the link to graph.facebook.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` controllers/api.js:142: Question for the team: how is the link to news.ycombinator.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` controllers/api.js:589: Question for the team: how is the link to api.twitch.tv authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` controllers/api.js:913: Question for the team: how is the link to api.sandbox.paypal.com authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
- `unknown_attribute` controllers/api.js:1243: Question for the team: how is the link to pubchem.ncbi.nlm.nih.gov authenticated and is it encrypted in transit? (authentication=unknown, encryption=tls)
