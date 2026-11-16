# code2design report: stripe-checkout-sample

Commit `c834ba3ae155`, code2design 0.5.0, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| c_sharp | 3 |
| go | 1 |
| java | 1 |
| javascript | 9 |
| python | 1 |
| tsx | 4 |
| typescript | 7 |
| (test files, not modelled) | 0 |
| no recognizer for .php | 4 (not analyzed) |
| no recognizer for .rb | 5 (not analyzed) |

Detectors: config@0.5, csharp@0.5, go@0.5, java@0.5, js@0.5, py@0.5, synth@0.5.0

Facts: app 3, config_value 12, dependencies 6, entry_point 19, listener 4, module 5, outbound_call 29, router 4, schema 6, weakness 1

## Model

| Collection | Count |
|---|---|
| processes | 22 |
| entities | 3 |
| stores | 0 |
| boundaries | 1 |
| flows | 17 |
| entry_points | 10 |
| controls | 0 |
| weaknesses | 11 |
| schemas | 3 |
| assets | 2 |
| threat_agents | 3 |
| gaps | 6 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 10 entry points, 10 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: server/dotnet/Program.cs port ?, server/go/server.go port "0.0.0.0:4242", server/node/server.js port 4242, server/python/server.py port 4242
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 23 declared in client/react-cra/package.json, server/go/go.mod, server/java/pom.xml, server/nextjs/package.json, server/node/package.json, server/python/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 1 medium, 10 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| ANY /create-checkout-session | unknown | none | - |
| GET /config | unknown | none | Stripe API |
| POST /create-checkout-session | unknown | none | Stripe API |
| ANY /webhook | unknown | none | - |
| GET / | unknown | none | - |
| ANY /config | unknown | none | - |
| GET /checkout-session | unknown | none | Stripe API |
| ANY / | unknown | none | - |
| ANY /checkout-session | unknown | none | - |
| POST /webhook | unknown | none | Stripe API |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| medium | CWE-489 | debug=True on the application server | server/python/server.py:119 |
| info | CWE-306 | no authentication control detected on POST /create-checkout-session | server/node/server.js:60 |
| info | CWE-306 | no authentication control detected on GET / | server/node/server.js:38 |
| info | CWE-306 | no authentication control detected on GET /checkout-session | server/node/server.js:54 |
| info | CWE-306 | no authentication control detected on ANY /checkout-session | server/go/server.go:44 |
| info | CWE-306 | no authentication control detected on POST /webhook | server/node/server.js:89 |
| info | CWE-306 | no authentication control detected on ANY / | server/go/server.go:42 |
| info | CWE-306 | no authentication control detected on GET /config | server/node/server.js:43 |
| info | CWE-306 | no authentication control detected on ANY /create-checkout-session | server/go/server.go:45 |
| info | CWE-306 | no authentication control detected on ANY /config | server/go/server.go:43 |
| info | CWE-306 | no authentication control detected on ANY /webhook | server/go/server.go:46 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Unresolved HTTP target | system | - |
| HTTP client | system | - |
| Stripe API | system | api.stripe.com |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> ANY /webhook handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /config handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> ANY /config handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> ANY / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /create-checkout-session handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> ANY /create-checkout-session handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /checkout-session handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /webhook handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> ANY /checkout-session handler
- **warning** `weakness-debug-mode-enabled` CWE-489 debug=True on the application server (server/python/server.py:119)
- **info** `black-hole-or-miracle` process ANY / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /create-checkout-session handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /config handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process Success has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process success has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /webhook handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process ANY /checkout-session handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process python has only outputs; a detector may be missing
- **info** `unknown-link-attributes` Success -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` success -> Unresolved HTTP target: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: stripe-checkout-sample (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Compromised external service (confidence 0.7): each of the 2 outbound dependencies is a potentially hostile responder
- Anonymous HTTP caller (confidence 0.9): 10 entry points are reachable from outside, 10 of them without a detected authentication control
- Insider with access to repository: stripe-checkout-sample (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unresolved` client/html/success.js:5: the target of an outbound call is built from a variable; the host is not resolvable statically
- `no_boundary_info` : no docker compose, Dockerfile, Kubernetes or Terraform descriptors were found; the repository is the only trust boundary
- `unsupported_file` server/php/public/create-checkout-session.php: no recognizer for .php: 4 file(s), e.g. server/php/public/create-checkout-session.php, server/php/public/get-checkout-session.php, server/php/public/shared.php
- `unsupported_file` server/ruby/server.rb: no recognizer for .rb: 5 file(s), e.g. server/ruby/server.rb, spec/capybara_support.rb, spec/client_and_server_spec.rb
- `unknown_attribute` server/node/server.js: Question: is TLS terminated in front of the HTTP listener of stripe-checkout-sample? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` client/react-cra/src/components/Success.jsx:12: Question: what is the authentication and encryption of the link to Unresolved HTTP target?
