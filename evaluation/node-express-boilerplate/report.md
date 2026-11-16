# code2design report: node-express-boilerplate

Commit `179ae84efec6`, code2design 0.5.2, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 49 |
| (test files, not modelled) | 10 |

Detectors: config@0.5, js@0.5, synth@0.5.2

Facts: app 1, boundary_hint 6, control 25, declared_link 1, dependencies 1, entry_point 15, listener 1, module 1, outbound_call 6, router 5, router_mount 4, schema 22, store_access 19, weakness 2

## Model

| Collection | Count |
|---|---|
| processes | 32 |
| entities | 2 |
| stores | 2 |
| boundaries | 2 |
| flows | 49 |
| entry_points | 15 |
| controls | 11 |
| weaknesses | 9 |
| schemas | 21 |
| assets | 2 |
| threat_agents | 4 |
| gaps | 6 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 13 entry points, 7 without a detected authentication control (7 of them published outside the deployment), 13 guarded by conditionally registered middleware; 2 infrastructure entry points (health, preflight, docs) not counted
- **listeners**: src/index.js port config.port
- **exit points carrying sensitive data**: SMTP mail relay
- **third-party dependencies**: 24 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 1 high, 1 medium, 7 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| POST /v1/auth/reset-password | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), validate | MongoDB: User, MongoDB: Token |
| GET /v1/docs (infrastructure) | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors | - |
| POST /v1/auth/register | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), validate | MongoDB: User, MongoDB: Token |
| POST /v1/auth/verify-email | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), validate | MongoDB: User, MongoDB: Token |
| PATCH /v1/users/{userId} | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, auth, validate | MongoDB: User |
| POST /v1/auth/forgot-password | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), validate | SMTP mail relay, MongoDB: User, MongoDB: Token |
| POST /v1/auth/logout | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), validate | MongoDB: Token |
| GET /v1/users | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, auth, validate | MongoDB: User |
| POST /v1/auth/login | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), validate | MongoDB: User, MongoDB: Token |
| DELETE /v1/users/{userId} | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, auth, validate | MongoDB: User |
| OPTIONS * (infrastructure) | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors | - |
| POST /v1/auth/send-verification-email | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), auth | SMTP mail relay, MongoDB: Token |
| POST /v1/users | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, auth, validate | MongoDB: User |
| POST /v1/auth/refresh-tokens | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, authLimiter (conditional), validate | MongoDB: User, MongoDB: Token |
| GET /v1/users/{userId} | public | morgan.successHandler (conditional), morgan.errorHandler (conditional), helmet, xss, mongoSanitize, cors, auth, validate | MongoDB: User |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| high | CWE-798 | hard-coded RESET_PASSWORD literal | src/config/tokens.js:4 |
| medium | CWE-942 | cors() with default or wildcard origin | src/app.js:41 |
| info | CWE-306 | no authentication control detected on POST /v1/auth/refresh-tokens | src/routes/v1/auth.route.js:12 |
| info | CWE-306 | no authentication control detected on POST /v1/auth/register | src/routes/v1/auth.route.js:9 |
| info | CWE-306 | no authentication control detected on POST /v1/auth/logout | src/routes/v1/auth.route.js:11 |
| info | CWE-306 | no authentication control detected on POST /v1/auth/forgot-password | src/routes/v1/auth.route.js:13 |
| info | CWE-306 | no authentication control detected on POST /v1/auth/verify-email | src/routes/v1/auth.route.js:16 |
| info | CWE-306 | no authentication control detected on POST /v1/auth/login | src/routes/v1/auth.route.js:10 |
| info | CWE-306 | no authentication control detected on POST /v1/auth/reset-password | src/routes/v1/auth.route.js:14 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| SMTP mail relay | system | - |
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| MongoDB: User | mongodb | credential, pii | unknown | container: mongodb |
| MongoDB: Token | mongodb | credential, pii | unknown | container: mongodb |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> OPTIONS * handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /v1/auth/logout handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /v1/auth/forgot-password handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /v1/auth/verify-email handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /v1/auth/register handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /v1/auth/refresh-tokens handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /v1/auth/reset-password handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /v1/auth/login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /v1/docs handler
- **warning** `weakness-permissive-cors` CWE-942 cors() with default or wildcard origin (src/app.js:41)
- **warning** `weakness-plaintext-credentials` CWE-798 hard-coded RESET_PASSWORD literal (src/config/tokens.js:4)
- **info** `black-hole-or-miracle` process passport has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /v1/docs handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process OPTIONS * handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` MongoDB: User -> user.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MongoDB: Token -> token.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` token.service -> MongoDB: Token: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` auth.service -> MongoDB: Token: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MongoDB: Token -> auth.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` user.service -> MongoDB: User: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MongoDB: User -> passport: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` email.service -> SMTP mail relay: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- Compromised external service (confidence 0.7): each of the 1 outbound dependencies is a potentially hostile responder
- Anonymous HTTP caller (confidence 0.9): 13 entry points are reachable from outside, 7 of them without a detected authentication control
- Insider with access to container: node-app (confidence 0.8): one insider agent per trust boundary, placed inside it
- Authenticated HTTP caller (confidence 0.9): 6 entry points require authentication; a holder of valid credentials is a distinct agent

## Gaps and questions

- `unknown_attribute` src/index.js: Question: is TLS terminated in front of the HTTP listener of node-app? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/services/user.service.js:27: Question: what is the authentication and encryption of the link to MongoDB: User?
- `unknown_attribute` src/services/token.service.js:56: Question: what is the authentication and encryption of the link to MongoDB: Token?
- `unknown_attribute` src/services/email.service.js:5: Question: what is the authentication and encryption of the link to SMTP mail relay?
- `unknown_attribute` src/models/user.model.js:89: Question: is MongoDB: User encrypted at rest? It holds credential, pii.
- `unknown_attribute` src/models/token.model.js:42: Question: is MongoDB: Token encrypted at rest? It holds credential, pii.
