# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on POST /v1/auth/reset-password | Weakness | - | - | - | - | unauthenticated_entry_point at src/routes/v1/auth.route.js:14 |
| no authn control detected on POST /v1/auth/logout | Weakness | - | - | - | - | unauthenticated_entry_point at src/routes/v1/auth.route.js:11 |
| no authn control detected on POST /v1/auth/refresh-tokens | Weakness | - | - | - | - | unauthenticated_entry_point at src/routes/v1/auth.route.js:12 |
| no authn control detected on POST /v1/auth/login | Weakness | - | - | - | - | unauthenticated_entry_point at src/routes/v1/auth.route.js:10 |
| no authn control detected on POST /v1/auth/forgot-password | Weakness | - | - | - | - | unauthenticated_entry_point at src/routes/v1/auth.route.js:13 |
| no authn control detected on POST /v1/auth/verify-email | Weakness | - | - | - | - | unauthenticated_entry_point at src/routes/v1/auth.route.js:16 |
| no authn control detected on POST /v1/auth/register | Weakness | - | - | - | - | unauthenticated_entry_point at src/routes/v1/auth.route.js:9 |
| cors() with default or wildcard origin | Weakness | - | - | - | - | permissive_cors at src/app.js:41 |
| SMTP mail relay | External entity | S R | - | - | - | outbound dependency; confirm credential storage, TLS and timeouts |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| HTTP client -> POST /v1/auth/forgot-password handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| MongoDB: Token -> token.service | Data flow | T I D | - | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/send-verification-email handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, auth, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /v1/docs handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, morgan.successHandler, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /v1/users handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | authentication=credentials, encryption=unknown: question for the team |
| MongoDB: User -> user.service | Data flow | T I D | - | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/register handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| user.service -> MongoDB: User | Data flow | T I D | - | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| auth.service -> MongoDB: Token | Data flow | T I D | - | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE /v1/users/:userId handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/refresh-tokens handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| HTTP client -> OPTIONS * handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, morgan.successHandler, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| token.service -> MongoDB: Token | Data flow | T I D | - | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/reset-password handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| MongoDB: User -> passport | Data flow | T I D | - | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/logout handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/login handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /v1/users handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /v1/users/:userId handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> PATCH /v1/users/:userId handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | authentication=credentials, encryption=unknown: question for the team |
| email.service -> SMTP mail relay | Data flow | T I D | - | container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| MongoDB: Token -> auth.service | Data flow | T I D | - | container: mongodb, container: node-app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /v1/auth/verify-email handler | Data flow | T I D | - | container: node-app | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | authentication=none, encryption=unknown: question for the team |
| MongoDB: User | Data store | T R I D | - | in container: mongodb | encryption at rest: unknown |  |
| MongoDB: Token | Data store | T R I D | - | in container: mongodb | encryption at rest: unknown |  |
| OPTIONS * handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, morgan.successHandler, xss, cors, helmet | entry point |
| POST /v1/auth/login handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |
| POST /v1/auth/send-verification-email handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, auth, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |
| POST /v1/auth/forgot-password handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |
| POST /v1/auth/verify-email handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |
| auth.service | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /v1/users/:userId handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | entry point |
| user.service | Process | S T R I D E | - | - | n/a (internal) |  |
| PATCH /v1/users/:userId handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | entry point |
| POST /v1/auth/register handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |
| GET /v1/users handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | entry point |
| token.service | Process | S T R I D E | - | - | n/a (internal) |  |
| passport | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /v1/docs handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, morgan.successHandler, xss, cors, helmet | entry point |
| POST /v1/users handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | entry point |
| DELETE /v1/users/:userId handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, morgan.successHandler, validate, xss, auth, cors, helmet | entry point |
| POST /v1/auth/logout handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |
| email.service | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /v1/auth/refresh-tokens handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |
| POST /v1/auth/reset-password handler | Process | S T R I D E | - | - | morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet | entry point |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
