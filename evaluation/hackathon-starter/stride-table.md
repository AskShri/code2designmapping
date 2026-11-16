# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| hard-coded tokenURL literal | Weakness (high) | I E | - | - | passport | CWE-798 Hard-coded or committed credentials at config/passport.js:703 |
| hard-coded tokenURL literal | Weakness (high) | I E | - | - | passport | CWE-798 Hard-coded or committed credentials at config/passport.js:730 |
| hard-coded accessTokenURL literal | Weakness (high) | I E | - | - | passport | CWE-798 Hard-coded or committed credentials at config/passport.js:582 |
| hard-coded requestTokenURL literal | Weakness (high) | I E | - | - | passport | CWE-798 Hard-coded or committed credentials at config/passport.js:581 |
| hard-coded tokenURL literal | Weakness (high) | I E | - | - | passport | CWE-798 Hard-coded or committed credentials at config/passport.js:487 |
| hard-coded tokenURL literal | Weakness (high) | I E | - | - | passport | CWE-798 Hard-coded or committed credentials at config/passport.js:434 |
| plain http:// to api.steampowered.com | Weakness (medium) | T I | - | - | passport | CWE-319 Cleartext transport to a non-local host at config/passport.js:663 |
| nodemailer -> SMTP mail relay | Data flow | T I D | credential, pii | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system; authentication=credentials, encryption=unknown: question for the team |
| user -> SMTP mail relay | Data flow | T I D | credential, pii | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system; authentication=unknown, encryption=unknown: question for the team |
| POST /reset/{token} handler -> SMTP mail relay | Data flow | T I D | credential | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system; authentication=unknown, encryption=unknown: question for the team |
| POST /login handler -> SMTP mail relay | Data flow | T I D | credential, pii | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system; authentication=unknown, encryption=unknown: question for the team |
| contact -> SMTP mail relay | Data flow | T I D | pii | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system; authentication=credentials, encryption=unknown: question for the team |
| POST /api/stripe handler -> Stripe API | Data flow | T I D | credential, pii | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system |
| contact -> Unresolved HTTP target | Data flow | T I D | pii | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system; authentication=unknown, encryption=unknown: question for the team |
| POST /forgot handler -> SMTP mail relay | Data flow | T I D | pii | repository: hackathon-starter | none | EXIT POINT: sensitive data leaves the system; authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User | Data store | T R I D | credential, pii | in no boundary | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| HTTP client -> GET /api/lob handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /forgot handler -> MongoDB: User | Data flow | T I D | pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| GET /api/tumblr handler -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> POST /reset/{token} handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /auth/tumblr/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | authentication=credentials, encryption=unknown: question for the team |
| MongoDB: User -> GET /account/unlink/{provider} handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/here-maps handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB (collection unresolved) -> ai-agent | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| api -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /contact handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> POST /forgot handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| GET /api/lob handler -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /account/2fa/totp/setup handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/facebook/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| passport -> discord.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /api/facebook handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /account/profile handler | Data flow | T I D | pii | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| GET /api/quickbooks handler -> www.alphavantage.co | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| GET /api/paypal handler -> api.sandbox.paypal.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /account/logout-everywhere handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/giphy handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/webauthn/verify handler | Data flow | T I D | credential | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /account handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /account/webauthn/register handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| passport -> graph.microsoft.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /api/stripe handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /login handler -> MongoDB: User | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| POST /login/2fa handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| GET /api/chart handler -> www.alphavantage.co | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /login/2fa/totp handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /ai/llm-classifier handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/x/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| passport -> api.steampowered.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=none: question for the team |
| HTTP client -> GET /api/paypal handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/google/drive handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | authentication=session_id, encryption=unknown: question for the team |
| POST /account/profile handler -> MongoDB: User | Data flow | T I D | pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/google-maps handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| GET /api/scraping handler -> news.ycombinator.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /login/webauthn-start handler | Data flow | T I D | pii | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /reset/{token} handler -> MongoDB: User | Data flow | T I D | credential | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /login/verify/{token} handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| GET /api/facebook handler -> graph.facebook.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /ai/llm-classifier handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/chart handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /account/password handler -> MongoDB: User | Data flow | T I D | credential | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/foursquare handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| api -> api.twitch.tv | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /api/twilio handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /account/2fa/totp/setup handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| POST /account/2fa/totp/setup handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> POST /login/2fa/totp handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /login/2fa handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/paypal/cancel handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /reset/{token} handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /ai/llm-camera handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/delete handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /api/upload handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| GET /account/verify handler -> SMTP mail relay | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| app -> MongoDB (collection unresolved) | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> POST /login handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /auth/quickbooks/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | authentication=credentials, encryption=unknown: question for the team |
| GET /api/pubchem handler -> pubchem.ncbi.nlm.nih.gov | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| MongoDB: User -> GET /login/verify/{token} handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| POST /account/2fa/email/enable handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> POST /account/profile handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /ai/llm-camera handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, lusca | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/steam/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | authentication=credentials, encryption=unknown: question for the team |
| POST /signup handler -> MongoDB: User | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /account/password handler | Data flow | T I D | credential | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| MongoDB: User -> POST /login/2fa handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /login/2fa/resend handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /forgot handler | Data flow | T I D | pii | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| user -> MongoDB: User | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /signup handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> POST /account/2fa/email/enable handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| passport -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /contact handler | Data flow | T I D | pii | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/google/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| MongoDB (collection unresolved) -> ai | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| POST /login/webauthn-verify handler -> MongoDB: User | Data flow | T I D | credential | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| POST /login/2fa/resend handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /auth/failure handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/linkedin/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| MongoDB: User -> GET /reset/{token} handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/twilio handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/github handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> POST /login/2fa/resend handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /auth/twitch/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /signup handler | Data flow | T I D | credential, pii | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/2fa/email/remove handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/microsoft/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /account/unlink/{provider} handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/paypal/success handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| passport -> api.linkedin.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| token-revocation -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| GET /account/unlink/{provider} handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/lastfm handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /login/webauthn-verify handler | Data flow | T I D | credential | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /ai/rag/ingest handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /ai/rag handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/twitch handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | authentication=session_id, encryption=unknown: question for the team |
| GET /api/tumblr handler -> api.tumblr.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /api/tumblr handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /reset/{token} handler | Data flow | T I D | credential | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /forgot handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| GET /api/giphy handler -> www.alphavantage.co | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /api/pubchem handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> POST /account/2fa/totp/setup handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> GET /login/2fa/totp handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| POST /account/delete handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/nyt handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/upload handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, lusca | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /ai/rag/ask handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB (collection unresolved) -> User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /ai handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /account/2fa/email/remove handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /auth/discord/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| GET /login/2fa handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| passport -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| GET /api/paypal/success handler -> api.sandbox.paypal.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| MongoDB: User -> GET /login/2fa handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> POST /login/webauthn-verify handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> passport | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /account/verify handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| MongoDB: User -> POST /signup handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> POST /account/2fa/totp/remove handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| api -> www.alphavantage.co | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /account/webauthn/register handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/2fa/totp/remove handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/github/callback handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | authentication=credentials, encryption=unknown: question for the team |
| GET /login/verify/{token} handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /login/2fa/totp handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /account/2fa/totp/remove handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /login/2fa handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/wikipedia handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/quickbooks handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/steam handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | authentication=session_id, encryption=unknown: question for the team |
| MongoDB: User -> GET /account/2fa/totp/setup handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/stripe handler | Data flow | T I D | credential, pii | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /ai/ai-agent handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /login handler | Data flow | T I D | credential, pii | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| api -> api.sandbox.paypal.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /login/webauthn-start handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /account/verify/{token} handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /account/webauthn/remove handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /ai/ai-agent/chat handler | Data flow | T I D | internal | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /logout handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/scraping handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| GET /api/nyt handler -> www.alphavantage.co | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /account/2fa/email/enable handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /login handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /account/webauthn/register handler -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User -> POST /account/password handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/google/sheets handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /ai/ai-agent/reset handler | Data flow | T I D | - | repository: hackathon-starter | morganLogger, limiter, lusca.xframe, lusca.xssProtection | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> POST /account/2fa/email/remove handler | Data flow | T I D | credential, pii | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| Google Sheets API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Lob API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| news.ycombinator.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| api.linkedin.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| graph.facebook.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| www.alphavantage.co | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Steam Openid identity provider | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| api.tumblr.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Last.fm API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Google Oauth identity provider | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| SMTP mail relay | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Github2 identity provider | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Groq API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts (LLM API: check what data is sent) |
| Twilio API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| discord.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| api.twitch.tv | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| graph.microsoft.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Google Drive API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| api.steampowered.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Facebook identity provider | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Stripe API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| GitHub API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| pubchem.ncbi.nlm.nih.gov | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| api.sandbox.paypal.com | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| Hugging Face Inference API | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts (LLM API: check what data is sent) |
| MongoDB (collection unresolved) | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| MongoDB: Session | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| api -> Google Sheets API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Facebook identity provider | Data flow (inferred) | T I D | - | repository: hackathon-starter | none |  |
| api -> Google Drive API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| GET /api/lob handler -> Lob API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Google Oauth identity provider | Data flow (inferred) | T I D | - | repository: hackathon-starter | none |  |
| ai -> Groq API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| GET /api/google/sheets handler -> Google Sheets API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| GET /api/google/sheets handler -> Google Drive API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| ai -> Hugging Face Inference API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| POST /api/twilio handler -> Twilio API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| POST /ai/rag/ask handler -> Groq API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| GET /api/google/drive handler -> Google Drive API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> Last.fm API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> GitHub API | Data flow (inferred) | T I D | - | repository: hackathon-starter | none |  |
| passport -> Github2 identity provider | Data flow (inferred) | T I D | - | repository: hackathon-starter | none |  |
| passport -> Steam Openid identity provider | Data flow (inferred) | T I D | - | repository: hackathon-starter | none |  |
| GET /api/google-maps handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/google/sheets handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | entry point |
| GET /api/lob handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /ai/llm-camera handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | entry point |
| POST /account/2fa/totp/setup handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /api handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/scraping handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/tumblr handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | entry point |
| GET /account/verify/{token} handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| POST /signup handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /logout handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| token-revocation | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /login handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | entry point |
| GET /auth/tumblr/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | entry point |
| GET /api/wikipedia handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/stripe handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /account/webauthn/register handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /api/github handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /login handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/pubchem handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /login/2fa/totp handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | entry point |
| POST /forgot handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | entry point |
| app | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /account handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /ai/ai-agent handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /ai/llm-camera handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, lusca | entry point |
| GET /auth/microsoft/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| GET /auth/linkedin/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| GET /ai handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/lastfm handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /account/2fa/totp/remove handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /api/paypal handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| api | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /login/webauthn-start handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | entry point |
| GET /login/webauthn-start handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /account/webauthn/remove handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| POST /reset/{token} handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | entry point |
| GET /api/here-maps handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| contact | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/x/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| ai | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /reset/{token} handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /ai/ai-agent/reset handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /auth/steam/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | entry point |
| GET /api/paypal/cancel handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/giphy handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /account/webauthn/register handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /account/delete handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /auth/google/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| GET /api/nyt handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/paypal/success handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /login/2fa handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | entry point |
| POST /login/2fa/resend handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | entry point |
| POST /login/webauthn-verify handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | entry point |
| POST /ai/rag/ingest handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /contact handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /account/unlink/{provider} handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET / handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /ai/llm-classifier handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /ai/rag handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /account/verify handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| POST /ai/ai-agent/chat handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/chart handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /auth/discord/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| GET /auth/facebook/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| GET /api/foursquare handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /forgot handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /auth/failure handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /api/stripe handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /account/2fa/totp/setup handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /signup handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /api/quickbooks handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | entry point |
| passport | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/google/drive handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | entry point |
| POST /account/2fa/email/enable handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /api/steam handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | entry point |
| GET /api/upload handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, lusca | entry point |
| POST /ai/rag/ask handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| User | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /account/profile handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| POST /account/logout-everywhere handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| ai-agent | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /api/upload handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter, lusca | entry point |
| GET /contact handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, strictLimiter | entry point |
| GET /auth/quickbooks/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authorize | entry point |
| POST /account/webauthn/verify handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /api/twitch handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | entry point |
| GET /ai/llm-classifier handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| POST /api/twilio handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| nodemailer | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/facebook handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated, passportConfig.isAuthorized | entry point |
| POST /account/2fa/email/remove handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| GET /login/2fa/totp handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | entry point |
| GET /api/twilio handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection | entry point |
| GET /auth/github/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| GET /login/2fa handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, login2FALimiter | entry point |
| user | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/twitch/callback handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passport.authenticate | entry point |
| GET /login/verify/{token} handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, loginLimiter | entry point |
| POST /account/password handler | Process | S T R I D E | - | - | morganLogger, limiter, lusca.xframe, lusca.xssProtection, passportConfig.isAuthenticated | entry point |
| no authentication control detected on GET /auth/failure | Weakness (info) | S E | - | - | ep:nwh3h3gpxh | CWE-306 Entry point without a detected authentication control (review) at app.js:345 |
| no authentication control detected on POST /forgot | Weakness (info) | S E | - | - | ep:5io2jrqeip | CWE-306 Entry point without a detected authentication control (review) at app.js:265 |
| no authentication control detected on GET /login | Weakness (info) | S E | - | - | ep:ztkybrt6f3 | CWE-306 Entry point without a detected authentication control (review) at app.js:252 |
| no authentication control detected on GET /forgot | Weakness (info) | S E | - | - | ep:7b4vis4wxo | CWE-306 Entry point without a detected authentication control (review) at app.js:264 |
| no authentication control detected on POST /ai/llm-classifier | Weakness (info) | S E | - | - | ep:7c5lsxqurj | CWE-306 Entry point without a detected authentication control (review) at app.js:328 |
| no authentication control detected on GET /api/nyt | Weakness (info) | S E | - | - | ep:232gxtgger | CWE-306 Entry point without a detected authentication control (review) at app.js:295 |
| no authentication control detected on GET /api/lastfm | Weakness (info) | S E | - | - | ep:sh7vw5n4wi | CWE-306 Entry point without a detected authentication control (review) at app.js:294 |
| no authentication control detected on GET /login/webauthn-start | Weakness (info) | S E | - | - | ep:tgx2fhselh | CWE-306 Entry point without a detected authentication control (review) at app.js:261 |
| no authentication control detected on GET /signup | Weakness (info) | S E | - | - | ep:mypwz7sl45 | CWE-306 Entry point without a detected authentication control (review) at app.js:268 |
| no authentication control detected on POST /reset/{token} | Weakness (info) | S E | - | - | ep:axwdewkzyx | CWE-306 Entry point without a detected authentication control (review) at app.js:267 |
| no authentication control detected on GET /api/lob | Weakness (info) | S E | - | - | ep:spdlgbrwwl | CWE-306 Entry point without a detected authentication control (review) at app.js:310 |
| no authentication control detected on POST /login/2fa/totp | Weakness (info) | S E | - | - | ep:56y367ehcq | CWE-306 Entry point without a detected authentication control (review) at app.js:259 |
| no authentication control detected on POST /contact | Weakness (info) | S E | - | - | ep:q22zqe3kh4 | CWE-306 Entry point without a detected authentication control (review) at app.js:271 |
| no authentication control detected on POST /ai/rag/ingest | Weakness (info) | S E | - | - | ep:2nibl7uxlt | CWE-306 Entry point without a detected authentication control (review) at app.js:332 |
| no authentication control detected on GET /ai | Weakness (info) | S E | - | - | ep:lqy6kgrjeg | CWE-306 Entry point without a detected authentication control (review) at app.js:326 |
| no authentication control detected on GET /ai/llm-classifier | Weakness (info) | S E | - | - | ep:6qc7pe5xsn | CWE-306 Entry point without a detected authentication control (review) at app.js:327 |
| no authentication control detected on GET /api/google-maps | Weakness (info) | S E | - | - | ep:qtgo5tuxfm | CWE-306 Entry point without a detected authentication control (review) at app.js:314 |
| no authentication control detected on GET /api/paypal/cancel | Weakness (info) | S E | - | - | ep:dkniscvril | CWE-306 Entry point without a detected authentication control (review) at app.js:309 |
| no authentication control detected on GET /contact | Weakness (info) | S E | - | - | ep:frcq7vctd7 | CWE-306 Entry point without a detected authentication control (review) at app.js:270 |
| no authentication control detected on GET /api/twilio | Weakness (info) | S E | - | - | ep:gbj7go5bs6 | CWE-306 Entry point without a detected authentication control (review) at app.js:300 |
| no authentication control detected on GET /login/2fa | Weakness (info) | S E | - | - | ep:qoccidwteb | CWE-306 Entry point without a detected authentication control (review) at app.js:255 |
| no authentication control detected on GET /api/paypal | Weakness (info) | S E | - | - | ep:tsmqnoe5yg | CWE-306 Entry point without a detected authentication control (review) at app.js:307 |
| no authentication control detected on POST /api/upload | Weakness (info) | S E | - | - | ep:bvb23ulydq | CWE-306 Entry point without a detected authentication control (review) at app.js:312 |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:jf2ffufdzr | CWE-306 Entry point without a detected authentication control (review) at app.js:251 |
| no authentication control detected on GET /api/giphy | Weakness (info) | S E | - | - | ep:vjmcw7hn7v | CWE-306 Entry point without a detected authentication control (review) at app.js:321 |
| no authentication control detected on POST /login/webauthn-verify | Weakness (info) | S E | - | - | ep:faghyastqs | CWE-306 Entry point without a detected authentication control (review) at app.js:262 |
| no authentication control detected on GET /api | Weakness (info) | S E | - | - | ep:ur5kjdpnoj | CWE-306 Entry point without a detected authentication control (review) at app.js:293 |
| no authentication control detected on GET /logout | Weakness (info) | S E | - | - | ep:7xnazrpxve | CWE-306 Entry point without a detected authentication control (review) at app.js:263 |
| no authentication control detected on GET /ai/ai-agent | Weakness (info) | S E | - | - | ep:q4dknfgukh | CWE-306 Entry point without a detected authentication control (review) at app.js:334 |
| no authentication control detected on POST /signup | Weakness (info) | S E | - | - | ep:a5n4sxocb2 | CWE-306 Entry point without a detected authentication control (review) at app.js:269 |
| no authentication control detected on GET /ai/llm-camera | Weakness (info) | S E | - | - | ep:nlwy7tspiu | CWE-306 Entry point without a detected authentication control (review) at app.js:329 |
| no authentication control detected on GET /api/pubchem | Weakness (info) | S E | - | - | ep:hvrn3wsusk | CWE-306 Entry point without a detected authentication control (review) at app.js:319 |
| no authentication control detected on GET /api/foursquare | Weakness (info) | S E | - | - | ep:en3pltm2v4 | CWE-306 Entry point without a detected authentication control (review) at app.js:302 |
| no authentication control detected on POST /login | Weakness (info) | S E | - | - | ep:22tuuwqeni | CWE-306 Entry point without a detected authentication control (review) at app.js:253 |
| no authentication control detected on POST /ai/llm-camera | Weakness (info) | S E | - | - | ep:q6jgad46e6 | CWE-306 Entry point without a detected authentication control (review) at app.js:330 |
| no authentication control detected on GET /api/scraping | Weakness (info) | S E | - | - | ep:i2efkhczvp | CWE-306 Entry point without a detected authentication control (review) at app.js:299 |
| no authentication control detected on GET /reset/{token} | Weakness (info) | S E | - | - | ep:un24syvou7 | CWE-306 Entry point without a detected authentication control (review) at app.js:266 |
| no authentication control detected on POST /api/stripe | Weakness (info) | S E | - | - | ep:qwcacmxucs | CWE-306 Entry point without a detected authentication control (review) at app.js:298 |
| no authentication control detected on GET /login/2fa/totp | Weakness (info) | S E | - | - | ep:xc67nhxqn4 | CWE-306 Entry point without a detected authentication control (review) at app.js:258 |
| no authentication control detected on GET /account/webauthn/register | Weakness (info) | S E | - | - | ep:a5fysiwiil | CWE-306 Entry point without a detected authentication control (review) at app.js:286 |
| no authentication control detected on GET /ai/rag | Weakness (info) | S E | - | - | ep:yxfetvnxsk | CWE-306 Entry point without a detected authentication control (review) at app.js:331 |
| no authentication control detected on GET /api/upload | Weakness (info) | S E | - | - | ep:kabovzbpe6 | CWE-306 Entry point without a detected authentication control (review) at app.js:311 |
| no authentication control detected on GET /api/stripe | Weakness (info) | S E | - | - | ep:whh65aurww | CWE-306 Entry point without a detected authentication control (review) at app.js:297 |
| no authentication control detected on GET /api/here-maps | Weakness (info) | S E | - | - | ep:wxvxeulw4q | CWE-306 Entry point without a detected authentication control (review) at app.js:313 |
| no authentication control detected on POST /ai/rag/ask | Weakness (info) | S E | - | - | ep:w4q5v3m634 | CWE-306 Entry point without a detected authentication control (review) at app.js:333 |
| no authentication control detected on GET /api/wikipedia | Weakness (info) | S E | - | - | ep:5zl3cw7d4c | CWE-306 Entry point without a detected authentication control (review) at app.js:320 |
| no authentication control detected on GET /api/paypal/success | Weakness (info) | S E | - | - | ep:agtru2qmpu | CWE-306 Entry point without a detected authentication control (review) at app.js:308 |
| no authentication control detected on POST /api/twilio | Weakness (info) | S E | - | - | ep:zkfx2lraad | CWE-306 Entry point without a detected authentication control (review) at app.js:301 |
| no authentication control detected on GET /login/verify/{token} | Weakness (info) | S E | - | - | ep:mj5hkheno7 | CWE-306 Entry point without a detected authentication control (review) at app.js:254 |
| no authentication control detected on POST /login/2fa | Weakness (info) | S E | - | - | ep:ee5yqmq5te | CWE-306 Entry point without a detected authentication control (review) at app.js:256 |
| no authentication control detected on GET /api/chart | Weakness (info) | S E | - | - | ep:bu6kkvk3os | CWE-306 Entry point without a detected authentication control (review) at app.js:316 |
| no authentication control detected on POST /ai/ai-agent/chat | Weakness (info) | S E | - | - | ep:tmgz3gmbsr | CWE-306 Entry point without a detected authentication control (review) at app.js:335 |
| no authentication control detected on POST /login/2fa/resend | Weakness (info) | S E | - | - | ep:rzmwn7vhh7 | CWE-306 Entry point without a detected authentication control (review) at app.js:257 |
| no authentication control detected on POST /ai/ai-agent/reset | Weakness (info) | S E | - | - | ep:33ycqkevf5 | CWE-306 Entry point without a detected authentication control (review) at app.js:336 |
| no authentication control detected on POST /login/webauthn-start | Weakness (info) | S E | - | - | ep:xwh57wgpct | CWE-306 Entry point without a detected authentication control (review) at app.js:260 |
| no authentication control detected on GET /api/github | Weakness (info) | S E | - | - | ep:xiklxizdgy | CWE-306 Entry point without a detected authentication control (review) at app.js:305 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | POST /account/2fa/totp/setup handler, POST /signup handler, POST /login handler, POST /login/2fa/totp handler, POST /forgot handler, POST /account/2fa/totp/remove handler, POST /login/webauthn-start handler, POST /reset/{token} handler (+19) | MongoDB: User | SMTP mail relay, Stripe API, Unresolved HTTP target |
| credential | POST /account/2fa/totp/setup handler, POST /signup handler, POST /login handler, POST /login/2fa/totp handler, POST /forgot handler, POST /account/2fa/totp/remove handler, POST /reset/{token} handler, GET /reset/{token} handler (+17) | MongoDB: User | SMTP mail relay, Stripe API |
