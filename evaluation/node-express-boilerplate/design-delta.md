## Design delta: node-express-boilerplate fbae788..179ae84 (60 commits)

### New (13)

- + Weakness: no authn control detected on POST /v1/auth/verify-email  (src/routes/v1/auth.route.js:16)
- + Control: auth  (src/routes/v1/auth.route.js:15)
- + Entry point: POST /v1/auth/send-verification-email controls: morgan.errorHandler, mongoSanitize, auth, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:15)
- + Entry point: POST /v1/auth/verify-email controls: morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:16)
- + Flow: HTTP client -> POST /v1/auth/send-verification-email handler http crosses 1 boundary, controls: morgan.errorHandler, mongoSanitize, auth, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:15)
- + Flow: POST /v1/auth/verify-email handler -> auth.service in_process  (src/services/auth.service.js:79)
- + Flow: POST /v1/auth/send-verification-email handler -> email.service in_process  (src/services/email.service.js:21)
- + Flow: POST /v1/auth/verify-email handler -> user.service in_process  (src/services/user.service.js:36)
- + Flow: POST /v1/auth/send-verification-email handler -> token.service in_process  (src/services/token.service.js:37)
- + Flow: POST /v1/auth/verify-email handler -> token.service in_process  (src/services/token.service.js:54)
- + Flow: HTTP client -> POST /v1/auth/verify-email handler http crosses 1 boundary, controls: morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:16)
- + Process: POST /v1/auth/send-verification-email handler  (src/routes/v1/auth.route.js:15)
- + Process: POST /v1/auth/verify-email handler  (src/routes/v1/auth.route.js:16)

### Removed (0)


### Changed (12)

- ~ Boundary: container: node-app: contains changed
- ~ Flow: PATCH /v1/users/:userId handler -> user.service in_process: purpose changed
- ~ Flow: DELETE /v1/users/:userId handler -> user.service in_process: purpose changed
- ~ Control: morgan.errorHandler: applies_to changed
- ~ Control: mongoSanitize: applies_to changed
- ~ Control: validate: applies_to changed
- ~ Control: morgan.successHandler: applies_to changed
- ~ Control: authLimiter: applies_to changed
- ~ Control: xss: applies_to changed
- ~ Control: cors: applies_to changed
- ~ Control: helmet: applies_to changed
- ~ Threat agent: Insider with access to container: node-app: entry changed

Unchanged: 74 elements and flows.

