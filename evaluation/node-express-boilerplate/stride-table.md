# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| hard-coded RESET_PASSWORD literal | Weakness (high) | I E | - | - | config | CWE-798 Hard-coded or committed credentials at src/config/tokens.js:4 |
| cors() with default or wildcard origin | Weakness (medium) | I | - | - | node-app | CWE-942 Permissive cross-origin policy at src/app.js:41 |
| email.service -> SMTP mail relay | Data flow | T I D | pii | container: node-app | none | EXIT POINT: sensitive data leaves the system; authentication=unknown, encryption=unknown: question for the team |
| MongoDB: User | Data store | T R I D | credential, pii | in container: mongodb | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| MongoDB: Token | Data store | T R I D | credential, pii | in container: mongodb | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| MongoDB: User -> user.service | Data flow | T I D | credential, pii | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: Token -> token.service | Data flow | T I D | credential, pii | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> OPTIONS * handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| token.service -> MongoDB: Token | Data flow | T I D | credential, pii | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/logout handler | Data flow | T I D | credential | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/forgot-password handler | Data flow | T I D | pii | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /v1/users/{userId} handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> PATCH /v1/users/{userId} handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | authentication=credentials, encryption=unknown: question for the team |
| auth.service -> MongoDB: Token | Data flow | T I D | credential | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /v1/users handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /v1/users handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | authentication=credentials, encryption=unknown: question for the team |
| MongoDB: Token -> auth.service | Data flow | T I D | credential, pii | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/verify-email handler | Data flow | T I D | credential | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/register handler | Data flow | T I D | credential, pii | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| user.service -> MongoDB: User | Data flow | T I D | credential, pii | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE /v1/users/{userId} handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/refresh-tokens handler | Data flow | T I D | credential | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/reset-password handler | Data flow | T I D | credential | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> passport | Data flow | T I D | credential, pii | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/send-verification-email handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, auth | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/login handler | Data flow | T I D | credential, pii | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /v1/docs handler | Data flow | T I D | - | container: node-app | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| SMTP mail relay | External entity | S R | - | - | - | outbound dependency: confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| auth.service | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /v1/auth/logout handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | entry point |
| POST /v1/users handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | entry point |
| GET /v1/users handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | entry point |
| POST /v1/auth/refresh-tokens handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | entry point |
| POST /v1/auth/login handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | entry point |
| passport | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /v1/users/{userId} handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | entry point |
| email.service | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /v1/auth/reset-password handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | entry point |
| user.service | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /v1/auth/verify-email handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | entry point |
| POST /v1/auth/forgot-password handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | entry point |
| POST /v1/auth/send-verification-email handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, auth | entry point |
| POST /v1/auth/register handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate | entry point |
| DELETE /v1/users/{userId} handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | entry point |
| token.service | Process | S T R I D E | - | - | n/a (internal) |  |
| PATCH /v1/users/{userId} handler | Process | S T R I D E | - | - | morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, auth, validate | entry point |
| no authentication control detected on POST /v1/auth/refresh-tokens | Weakness (info) | S E | - | - | ep:y5abvcoacq | CWE-306 Entry point without a detected authentication control (review) at src/routes/v1/auth.route.js:12 |
| no authentication control detected on POST /v1/auth/register | Weakness (info) | S E | - | - | ep:ccmuulecyb | CWE-306 Entry point without a detected authentication control (review) at src/routes/v1/auth.route.js:9 |
| no authentication control detected on POST /v1/auth/logout | Weakness (info) | S E | - | - | ep:lrpmcwkwic | CWE-306 Entry point without a detected authentication control (review) at src/routes/v1/auth.route.js:11 |
| no authentication control detected on POST /v1/auth/forgot-password | Weakness (info) | S E | - | - | ep:jg7eprgebp | CWE-306 Entry point without a detected authentication control (review) at src/routes/v1/auth.route.js:13 |
| no authentication control detected on POST /v1/auth/verify-email | Weakness (info) | S E | - | - | ep:ffepfpupvw | CWE-306 Entry point without a detected authentication control (review) at src/routes/v1/auth.route.js:16 |
| no authentication control detected on POST /v1/auth/login | Weakness (info) | S E | - | - | ep:q5pzai2jjc | CWE-306 Entry point without a detected authentication control (review) at src/routes/v1/auth.route.js:10 |
| no authentication control detected on POST /v1/auth/reset-password | Weakness (info) | S E | - | - | ep:b42kjwm45b | CWE-306 Entry point without a detected authentication control (review) at src/routes/v1/auth.route.js:14 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | auth.service, POST /v1/auth/login handler, passport, email.service, user.service, POST /v1/auth/forgot-password handler, POST /v1/auth/register handler, token.service | MongoDB: User, MongoDB: Token | SMTP mail relay |
| credential | auth.service, POST /v1/auth/logout handler, POST /v1/auth/refresh-tokens handler, POST /v1/auth/login handler, passport, POST /v1/auth/reset-password handler, user.service, POST /v1/auth/verify-email handler (+2) | MongoDB: User, MongoDB: Token | - |
