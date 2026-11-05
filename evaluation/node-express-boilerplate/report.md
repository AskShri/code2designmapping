# code2design report: node-express-boilerplate

Commit `179ae84efec6`, tool 0.3.0-prototype, 0.2s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 49 |
| (test files skipped) | 10 |

Detectors that ran: config@0.3, js@0.3

Facts: app_entry 1, boundary_hint 6, control 25, dependencies 1, entry_point 15, module 1, outbound_call 7, router_mount 4, schema 22, store_access 17, weakness 1

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
| weaknesses | 8 |
| schemas | 7 |
| assets | 0 |
| threat_agents | 4 |
| gaps | 4 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 13 entry points, 7 without a detected authn control, 13 guarded only by conditionally registered middleware; 2 infrastructure entry points (health, preflight, docs) not counted
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 24 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| POST /v1/auth/register | morgan.errorHandler (conditional), mongoSanitize, validate, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |
| GET /v1/users/:userId | morgan.errorHandler (conditional), mongoSanitize, morgan.successHandler (conditional), validate, xss, auth, cors, helmet |
| POST /v1/users | morgan.errorHandler (conditional), mongoSanitize, morgan.successHandler (conditional), validate, xss, auth, cors, helmet |
| POST /v1/auth/login | morgan.errorHandler (conditional), mongoSanitize, validate, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |
| POST /v1/auth/forgot-password | morgan.errorHandler (conditional), mongoSanitize, validate, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |
| POST /v1/auth/refresh-tokens | morgan.errorHandler (conditional), mongoSanitize, validate, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |
| GET /v1/docs (infrastructure) | morgan.errorHandler (conditional), mongoSanitize, morgan.successHandler (conditional), xss, cors, helmet |
| DELETE /v1/users/:userId | morgan.errorHandler (conditional), mongoSanitize, morgan.successHandler (conditional), validate, xss, auth, cors, helmet |
| POST /v1/auth/send-verification-email | morgan.errorHandler (conditional), mongoSanitize, auth, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |
| POST /v1/auth/logout | morgan.errorHandler (conditional), mongoSanitize, validate, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |
| OPTIONS * (infrastructure) | morgan.errorHandler (conditional), mongoSanitize, morgan.successHandler (conditional), xss, cors, helmet |
| PATCH /v1/users/:userId | morgan.errorHandler (conditional), mongoSanitize, morgan.successHandler (conditional), validate, xss, auth, cors, helmet |
| GET /v1/users | morgan.errorHandler (conditional), mongoSanitize, morgan.successHandler (conditional), validate, xss, auth, cors, helmet |
| POST /v1/auth/verify-email | morgan.errorHandler (conditional), mongoSanitize, validate, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |
| POST /v1/auth/reset-password | morgan.errorHandler (conditional), mongoSanitize, validate, morgan.successHandler (conditional), authLimiter (conditional), xss, cors, helmet |

### External entities

| Entity | Kind | Host |
|---|---|---|
| SMTP mail relay | system | - |
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| MongoDB: User | mongodb | - | container: mongodb |
| MongoDB: Token | mongodb | - | container: mongodb |

## Lint

- **warning** `unknown-link-attributes` MongoDB: Token -> token.service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: User -> user.service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` user.service -> MongoDB: User: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` auth.service -> MongoDB: Token: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` token.service -> MongoDB: Token: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: User -> passport: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` email.service -> SMTP mail relay: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` MongoDB: Token -> auth.service: authentication=unknown, encryption=unknown
- **info** `black-hole-or-miracle` process OPTIONS * handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process passport has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /v1/docs handler has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- Anonymous HTTP caller (confidence 0.9): 15 http entry points, 9 without a detected authn control
- Insider with access to container: node-app (confidence 0.8): one insider agent per trust boundary, placed inside it
- Authenticated HTTP caller (confidence 0.9): authn controls exist on some entry points; a valid credential holder is a distinct agent
- Compromised third party: SMTP mail relay (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder

## Gaps and questions

- `unknown_attribute` src/app.js: Question for the team: is TLS terminated in front of the HTTP listener? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/config/passport.js:16: Question for the team: how is the link to MongoDB: User authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/services/auth.service.js:28: Question for the team: how is the link to MongoDB: Token authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/services/email.service.js:5: Question for the team: how is the link to SMTP mail relay authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
