## Design delta: node-express-boilerplate fbae788..179ae84 (60 commits)

### New (8)

- + Weakness: no authn control detected on POST /v1/auth/verify-email  (src/routes/v1/auth.route.js:16)
- + Control: auth  (src/routes/v1/auth.route.js:15)
- + Entry point: POST /v1/auth/send-verification-email controls: morgan.errorHandler, mongoSanitize, auth, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:15)
- + Entry point: POST /v1/auth/verify-email controls: morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:16)
- + Flow: HTTP client -> POST /v1/auth/send-verification-email handler http crosses 1 boundary, controls: morgan.errorHandler, mongoSanitize, auth, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:15)
- + Flow: HTTP client -> POST /v1/auth/verify-email handler http crosses 1 boundary, controls: morgan.errorHandler, mongoSanitize, validate, morgan.successHandler, authLimiter, xss, cors, helmet  (src/routes/v1/auth.route.js:16)
- + Process: POST /v1/auth/send-verification-email handler  (src/routes/v1/auth.route.js:15)
- + Process: POST /v1/auth/verify-email handler  (src/routes/v1/auth.route.js:16)

### Removed (0)


### Changed (10)

- ~ Boundary: container: node-app: contains changed
- ~ Control: morgan.errorHandler: applies_to changed
- ~ Control: mongoSanitize: applies_to changed
- ~ Control: validate: applies_to changed
- ~ Control: morgan.successHandler: applies_to changed
- ~ Control: authLimiter: applies_to changed
- ~ Control: xss: applies_to changed
- ~ Control: cors: applies_to changed
- ~ Control: helmet: applies_to changed
- ~ Threat agent: Insider with access to container: node-app: entry changed

Unchanged: 60 elements and flows.

