## Design delta: node-express-boilerplate fbae788..179ae84 (60 commits)

### New (15)

- + **Entry point: POST /v1/auth/verify-email (public), controls: morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate**  (src/routes/v1/auth.route.js:16)
- + Control: auth  (src/routes/v1/auth.route.js:15)
- + Entry point: POST /v1/auth/send-verification-email (public), controls: morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, auth  (src/routes/v1/auth.route.js:15)
- + Flow: HTTP client -> POST /v1/auth/verify-email handler (http) carrying credential, crosses 1 boundary, controls: morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, validate  (src/routes/v1/auth.route.js:16)
- + Flow: HTTP client -> POST /v1/auth/send-verification-email handler (http), crosses 1 boundary, controls: morgan.successHandler, morgan.errorHandler, helmet, xss, mongoSanitize, cors, authLimiter, auth  (src/routes/v1/auth.route.js:15)
- + Schema: verifyEmail.query (1 fields: credential)  (src/validations/auth.validation.js:47)
- + Schema: request fields (verifyEmail) (1 fields: credential)  (src/controllers/auth.controller.js:46)
- + Weakness (info, CWE-306): no authentication control detected on POST /v1/auth/verify-email  (src/routes/v1/auth.route.js:16)
- + Flow: POST /v1/auth/send-verification-email handler -> email.service (in_process)  (src/services/email.service.js:21)
- + Flow: POST /v1/auth/verify-email handler -> token.service (in_process)  (src/services/token.service.js:54)
- + Flow: POST /v1/auth/send-verification-email handler -> token.service (in_process)  (src/services/token.service.js:37)
- + Flow: POST /v1/auth/verify-email handler -> user.service (in_process)  (src/services/user.service.js:36)
- + Flow: POST /v1/auth/verify-email handler -> auth.service (in_process)  (src/services/auth.service.js:79)
- + Process: POST /v1/auth/verify-email handler  (src/routes/v1/auth.route.js:16)
- + Process: POST /v1/auth/send-verification-email handler  (src/routes/v1/auth.route.js:15)

### Removed (0)


### Changed (15)

- ~ Asset: User credentials: processed_by +POST /v1/auth/verify-email handler  (src/validations/user.validation.js:33)
- ~ Boundary: container: node-app: contains +POST /v1/auth/verify-email handler, +POST /v1/auth/send-verification-email handler  (docker-compose.yml:4)
- ~ Control: mongoSanitize: applies_to +POST /v1/auth/verify-email, +POST /v1/auth/send-verification-email  (src/app.js:35)
- ~ Control: cors: applies_to +POST /v1/auth/verify-email, +POST /v1/auth/send-verification-email  (src/app.js:41)
- ~ Control: xss: applies_to +POST /v1/auth/verify-email, +POST /v1/auth/send-verification-email  (src/app.js:34)
- ~ Control: validate: applies_to +POST /v1/auth/verify-email  (src/routes/v1/auth.route.js:9)
- ~ Control: morgan.errorHandler: applies_to +POST /v1/auth/verify-email, +POST /v1/auth/send-verification-email  (src/app.js:21)
- ~ Control: authLimiter: applies_to +POST /v1/auth/verify-email, +POST /v1/auth/send-verification-email  (src/app.js:50)
- ~ Control: helmet: applies_to +POST /v1/auth/verify-email, +POST /v1/auth/send-verification-email  (src/app.js:25)
- ~ Control: morgan.successHandler: applies_to +POST /v1/auth/verify-email, +POST /v1/auth/send-verification-email  (src/app.js:20)
- ~ Flow: auth.service -> MongoDB: Token (mongo) carrying credential, crosses 2 boundary, controls: none: payload changed  (src/services/auth.service.js:32)
- ~ Flow: user.service -> MongoDB: User (mongo) carrying credential, pii, crosses 2 boundary, controls: none: payload changed  (src/services/user.service.js:14)
- ~ Schema: envVarsSchema (13 fields: credential, internal, pii): fields +JWT_RESET_PASSWORD_EXPIRATION_MINUTES (internal), +JWT_VERIFY_EMAIL_EXPIRATION_MINUTES (internal)  (src/config/config.js:7)
- ~ Threat agent: Insider with access to container: node-app: entry +POST /v1/auth/verify-email handler, +POST /v1/auth/send-verification-email handler  (docker-compose.yml:4)
- ~ Flow: DELETE /v1/users/{userId} handler -> user.service (in_process): purpose: calls deleteUserById -> calls getUserById  (src/services/user.service.js:36)

Unchanged: 73 elements and flows.
