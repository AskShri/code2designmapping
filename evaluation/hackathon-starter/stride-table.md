# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on GET /ai/rag | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:331 |
| no authn control detected on POST /api/stripe | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:298 |
| no authn control detected on GET /auth/twitch | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:390 |
| no authn control detected on POST /login/2fa/resend | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:257 |
| no authn control detected on GET /api/pubchem | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:319 |
| GOOGLE_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:799 |
| TUMBLR_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:585 |
| GITHUB_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:809 |
| no authn control detected on GET /api/here-maps | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:313 |
| no authn control detected on GET /api/stripe | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:297 |
| no authn control detected on GET /api/paypal/cancel | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:309 |
| no authn control detected on GET /auth/quickbooks/callback | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:411 |
| no authn control detected on POST /ai/llm-classifier | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:328 |
| no authn control detected on GET /auth/github | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:370 |
| X_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:815 |
| MICROSOFT_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:489 |
| no authn control detected on GET /auth/linkedin | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:382 |
| QUICKBOOKS_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:705 |
| no authn control detected on GET /api/upload | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:311 |
| no authn control detected on GET /login/webauthn-start | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:261 |
| DISCORD_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:827 |
| no authn control detected on GET /login/2fa/totp | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:258 |
| no authn control detected on GET /auth/facebook | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:366 |
| no authn control detected on GET /ai/llm-classifier | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:327 |
| no authn control detected on GET /api/lastfm | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:294 |
| no authn control detected on GET /contact | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:270 |
| no authn control detected on POST /login/webauthn-start | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:260 |
| no authn control detected on POST /contact | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:271 |
| no authn control detected on GET /auth/microsoft | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:386 |
| no authn control detected on GET /api/paypal | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:307 |
| LINKEDIN_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:436 |
| no authn control detected on POST /reset/:token | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:267 |
| no authn control detected on GET /auth/google | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:374 |
| no authn control detected on POST /ai/ai-agent/chat | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:335 |
| no authn control detected on GET /auth/discord | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:394 |
| no authn control detected on GET /logout | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:263 |
| no authn control detected on GET /auth/tumblr/callback | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:403 |
| no authn control detected on GET /api/nyt | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:295 |
| GOOGLE_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:392 |
| no authn control detected on GET /auth/quickbooks | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:410 |
| no authn control detected on POST /login/2fa | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:256 |
| no authn control detected on GET /auth/steam/callback | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:407 |
| no authn control detected on GET /reset/:token | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:266 |
| no authn control detected on GET /api/chart | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:316 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:251 |
| no authn control detected on GET /signup | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:268 |
| no authn control detected on POST /api/twilio | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:301 |
| no authn control detected on GET /ai/ai-agent | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:334 |
| no authn control detected on POST /ai/llm-camera | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:330 |
| TWITCH_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:541 |
| no authn control detected on GET /api/wikipedia | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:320 |
| no authn control detected on GET /api/foursquare | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:302 |
| no authn control detected on GET /api/twilio | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:300 |
| DISCORD_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:732 |
| no authn control detected on GET /auth/x | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:378 |
| no authn control detected on GET /login | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:252 |
| no authn control detected on POST /ai/rag/ask | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:333 |
| no authn control detected on GET /api/giphy | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:321 |
| no authn control detected on GET /api/google-maps | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:314 |
| no authn control detected on GET /api/lob | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:310 |
| no authn control detected on POST /login/2fa/totp | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:259 |
| FACEBOOK_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:259 |
| TWILIO_TOKEN read at module import | Weakness | - | - | - | - | secret_in_env_at_import at controllers/api.js:9 |
| no authn control detected on POST /login | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:253 |
| no authn control detected on GET /ai/llm-camera | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:329 |
| no authn control detected on GET /api/paypal/success | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:308 |
| QUICKBOOKS_CLIENT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:838 |
| no authn control detected on GET /auth/tumblr | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:402 |
| no authn control detected on GET /auth/failure | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:345 |
| no authn control detected on POST /forgot | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:265 |
| no authn control detected on POST /login/webauthn-verify | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:262 |
| GITHUB_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:302 |
| SESSION_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at app.js:144 |
| no authn control detected on GET /login/2fa | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:255 |
| no authn control detected on POST /api/upload | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:312 |
| no authn control detected on GET /login/verify/:token | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:254 |
| no authn control detected on GET /api | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:293 |
| no authn control detected on GET /auth/steam | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:406 |
| X_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:351 |
| no authn control detected on GET /api/github | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:305 |
| no authn control detected on GET /forgot | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:264 |
| no authn control detected on GET /account/webauthn/register | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:286 |
| no authn control detected on POST /ai/ai-agent/reset | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:336 |
| no authn control detected on GET /api/scraping | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:299 |
| no authn control detected on POST /signup | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:269 |
| no authn control detected on GET /ai | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:326 |
| no authn control detected on POST /ai/rag/ingest | Weakness | - | - | - | - | unauthenticated_entry_point at app.js:332 |
| LINKEDIN_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at config/passport.js:821 |
| Google Sheets API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Lob API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Oauth1 identity provider | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| news.ycombinator.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| api.linkedin.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| api.groq.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| graph.facebook.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Steam Openid identity provider | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| api.tumblr.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Last.fm API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Google Oauth identity provider | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| SMTP mail relay | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Unresolved HTTP target | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Github2 identity provider | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Groq API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts (LLM API: check what data is sent) |
| Twilio API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| discord.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| api.twitch.tv | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| graph.microsoft.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Google Drive API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| Facebook identity provider | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Stripe API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| GitHub API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| pubchem.ncbi.nlm.nih.gov | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| api.sandbox.paypal.com | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| Hugging Face Inference API | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts (LLM API: check what data is sent) |
| Oauth2 Refresh identity provider | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| HTTP client -> GET /auth/steam/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, passport.authorize, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/linkedin/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /ai/ai-agent/chat handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /login/2fa handler | Data flow | T I D | - | repository: hackathon-starter | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/github handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| api -> news.ycombinator.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /logout handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/discord handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/google/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /login/verify/:token handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/microsoft/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /account/profile handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /account/webauthn/verify handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| ai -> MongoDB | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| user -> MongoDB | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /ai/ai-agent/reset handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/2fa/email/enable handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/steam handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /ai handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/google/drive handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /account/verify/:token handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /contact handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| ai-agent -> MongoDB | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| api -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /login/2fa/resend handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| MongoDB -> passport | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /ai/rag handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| contact -> SMTP mail relay | Data flow | T I D | - | repository: hackathon-starter | none | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/paypal/success handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/logout-everywhere handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| MongoDB: User -> webauthn | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /forgot handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /login/2fa/totp handler | Data flow | T I D | - | repository: hackathon-starter | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /ai/rag/ingest handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/lob handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/facebook/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/twitch handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/tumblr handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| passport -> MongoDB | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /auth/x/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /account/2fa/totp/setup handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /login handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| passport -> api.linkedin.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| token-revocation -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/giphy handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| contact -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| passport -> graph.microsoft.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /auth/tumblr/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, passport.authorize, morganLogger | authentication=none, encryption=unknown: question for the team |
| app -> MongoDB | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB -> ai | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/paypal/cancel handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| MongoDB -> webauthn | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/paypal handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/twitch handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /login handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| passport -> Unresolved HTTP target | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB -> User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| user -> MongoDB: User | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /ai/llm-classifier handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/wikipedia handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /login/webauthn-start handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> user | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /forgot handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /account/webauthn/register handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/github/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/chart handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| api -> api.sandbox.paypal.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /account/webauthn/register handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| MongoDB: User -> passport | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/twitch/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/pubchem handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/discord/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /ai/llm-camera handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/2fa/totp/setup handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /reset/:token handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /reset/:token handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/password handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/quickbooks handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /account/2fa/totp/remove handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| nodemailer -> SMTP mail relay | Data flow | T I D | - | repository: hackathon-starter | none | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/facebook handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| passport -> discord.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /api/scraping handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/tumblr handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/twilio handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /account/unlink/:provider handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/upload handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| user -> SMTP mail relay | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /login/webauthn-verify handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /login/webauthn-start handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/lastfm handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /login/2fa/totp handler | Data flow | T I D | - | repository: hackathon-starter | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/facebook handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/stripe handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /signup handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| MongoDB -> user | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /account/verify handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /ai/llm-classifier handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /account handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| webauthn -> MongoDB | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /login/2fa handler | Data flow | T I D | - | repository: hackathon-starter | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| api -> graph.facebook.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| api -> pubchem.ncbi.nlm.nih.gov | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> GET /api/google/sheets handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/google handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/nyt handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| api -> api.tumblr.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| api -> api.twitch.tv | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /account/delete handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> POST /ai/llm-camera handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /signup handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| ai -> api.groq.com | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=tls: question for the team |
| HTTP client -> POST /account/webauthn/remove handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/failure handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/microsoft handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/twilio handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /ai/rag/ask handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| MongoDB -> ai-agent | Data flow | T I D | - | repository: hackathon-starter | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /account/2fa/email/remove handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /api/stripe handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /ai/ai-agent handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/steam handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /contact handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/github handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/google-maps handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/upload handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/here-maps handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/quickbooks handler | Data flow | T I D | - | repository: hackathon-starter | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=session_id, encryption=unknown: question for the team |
| HTTP client -> GET /auth/quickbooks/callback handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, passport.authorize, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/foursquare handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/linkedin handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /auth/x handler | Data flow | T I D | - | repository: hackathon-starter | limiter, lusca.xframe, lusca.xssProtection, morganLogger | authentication=none, encryption=unknown: question for the team |
| MongoDB | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| MongoDB: User | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| api -> Stripe API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Github2 identity provider | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> Last.fm API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> Lob API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> Twilio API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| ai -> Hugging Face Inference API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| ai-agent -> Groq API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Oauth2 Refresh identity provider | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> GitHub API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Google Oauth identity provider | Data flow | T I D | - | repository: hackathon-starter | none |  |
| ai -> Groq API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Oauth1 identity provider | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Steam Openid identity provider | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> Google Drive API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| api -> Google Sheets API | Data flow | T I D | - | repository: hackathon-starter | none |  |
| passport -> Facebook identity provider | Data flow | T I D | - | repository: hackathon-starter | none |  |
| POST /account/webauthn/verify handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| token-revocation | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /login handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /ai/llm-classifier handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/steam handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/delete handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/google-maps handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/paypal/success handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /contact handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/quickbooks/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, passport.authorize, morganLogger | entry point |
| GET /api/scraping handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| ai-agent | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/steam handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/stripe handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /api/upload handler | Process | S T R I D E | - | - | limiter, lusca, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /api/here-maps handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /login/2fa handler | Process | S T R I D E | - | - | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET / handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /forgot handler | Process | S T R I D E | - | - | limiter, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /ai/llm-classifier handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/x handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /forgot handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| passport | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/twitch/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| GET /api/wikipedia handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/facebook handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /login/2fa handler | Process | S T R I D E | - | - | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/github handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/quickbooks handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/paypal/cancel handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /login/webauthn-start handler | Process | S T R I D E | - | - | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /api/tumblr handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/2fa/totp/setup handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/2fa/email/enable handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /login/2fa/resend handler | Process | S T R I D E | - | - | limiter, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /auth/github/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| contact | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/quickbooks handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /api/stripe handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/google handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/tumblr/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, passport.authorize, morganLogger | entry point |
| POST /ai/rag/ask handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/giphy handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /account/unlink/:provider handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /ai/llm-camera handler | Process | S T R I D E | - | - | limiter, lusca, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /api/pubchem handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/twilio handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/microsoft handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /ai handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /account/verify handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/upload handler | Process | S T R I D E | - | - | limiter, lusca, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/microsoft/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| nodemailer | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /account/webauthn/register handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/nyt handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/password handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /reset/:token handler | Process | S T R I D E | - | - | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | entry point |
| POST /signup handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/logout-everywhere handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/discord handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/discord/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| POST /login handler | Process | S T R I D E | - | - | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /logout handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /contact handler | Process | S T R I D E | - | - | limiter, lusca.xframe, strictLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /ai/rag handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/webauthn/register handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /login/webauthn-start handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/foursquare handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /ai/ai-agent handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| User | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/google/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| GET /account/verify/:token handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/2fa/totp/remove handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/2fa/email/remove handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /account handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/chart handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| webauthn | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /ai/rag/ingest handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/tumblr handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /login/webauthn-verify handler | Process | S T R I D E | - | - | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | entry point |
| GET /account/2fa/totp/setup handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /ai/llm-camera handler | Process | S T R I D E | - | - | limiter, lusca, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/webauthn/remove handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/linkedin/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| GET /api/google/drive handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /reset/:token handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| user | Process | S T R I D E | - | - | n/a (internal) |  |
| ai | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/linkedin handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/facebook/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| GET /api handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/google/sheets handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /account/profile handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/lob handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /signup handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /login/2fa/totp handler | Process | S T R I D E | - | - | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/facebook handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/paypal handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/lastfm handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/steam/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, passport.authorize, morganLogger | entry point |
| api | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/twitch handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| app | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /auth/x/callback handler | Process | S T R I D E | - | - | limiter, lusca.xframe, passport.authenticate, lusca.xssProtection, morganLogger | entry point |
| POST /api/twilio handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /login/verify/:token handler | Process | S T R I D E | - | - | limiter, lusca.xframe, loginLimiter, lusca.xssProtection, morganLogger | entry point |
| POST /ai/ai-agent/chat handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /ai/ai-agent/reset handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/github handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| POST /login/2fa/totp handler | Process | S T R I D E | - | - | login2FALimiter, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /api/twitch handler | Process | S T R I D E | - | - | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |
| GET /auth/failure handler | Process | S T R I D E | - | - | limiter, lusca.xframe, lusca.xssProtection, morganLogger | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
