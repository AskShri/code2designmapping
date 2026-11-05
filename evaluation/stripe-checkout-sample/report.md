# code2design report: stripe-checkout-sample

Commit `c834ba3ae155`, tool 0.3.0-prototype, 0.0s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 9 |
| python | 1 |
| tsx | 4 |
| typescript | 7 |
| (test files skipped) | 0 |
| no recognizer for .cs | 3 (not analyzed) |
| no recognizer for .go | 1 (not analyzed) |
| no recognizer for .java | 1 (not analyzed) |
| no recognizer for .php | 4 (not analyzed) |
| no recognizer for .rb | 5 (not analyzed) |

Detectors that ran: config@0.3, js@0.3, py@0.3

Facts: app_entry 3, config_value 8, dependencies 4, entry_point 10, listener 2, module 3, outbound_call 15

## Model

| Collection | Count |
|---|---|
| processes | 22 |
| entities | 3 |
| stores | 0 |
| boundaries | 1 |
| flows | 23 |
| entry_points | 10 |
| controls | 0 |
| weaknesses | 13 |
| schemas | 0 |
| assets | 2 |
| threat_agents | 4 |
| gaps | 8 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 10 entry points, 10 without a detected authn control
- **listeners**: server/node/server.js port 4242, server/python/server.py port (port=4242, debug=True)
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 15 declared in client/react-cra/package.json, server/nextjs/package.json, server/node/package.json, server/python/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| GET /config | none |
| GET /checkout-session | none |
| POST /create-checkout-session | none |
| POST /webhook | none |
| GET /config | none |
| GET / | none |
| POST /webhook | none |
| GET / | none |
| POST /create-checkout-session | none |
| GET /checkout-session | none |

### External entities

| Entity | Kind | Host |
|---|---|---|
| Unresolved HTTP target | system | - |
| HTTP client | system | - |
| Stripe API | system | api.stripe.com |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|

## Lint

- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /config handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /create-checkout-session handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /config handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /checkout-session handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /webhook handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /webhook handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> POST /create-checkout-session handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET /checkout-session handler
- **warning** `uncontrolled-crossing` inbound flow crosses a boundary with no control: HTTP client -> GET / handler
- **warning** `unknown-link-attributes` success -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Success -> Unresolved HTTP target: authentication=unknown, encryption=unknown
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process route has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process python has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process Success has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process success has only outputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process stripe has only outputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: stripe-checkout-sample (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Anonymous HTTP caller (confidence 0.9): 10 http entry points, 10 without a detected authn control
- Compromised third party: Unresolved HTTP target (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Compromised third party: Stripe API (confidence 0.7): every outbound dependency is modeled as a potentially hostile responder
- Insider with access to repository: stripe-checkout-sample (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `no_boundary_info` : No compose, Dockerfile or Kubernetes manifests found; the repository is the only trust boundary.
- `unsupported_file` server/dotnet/Program.cs: no recognizer for .cs: 3 file(s), e.g. server/dotnet/Program.cs, server/dotnet/Configuration/StripeOptions.cs, server/dotnet/Models/ConfigResponse.cs
- `unsupported_file` server/go/server.go: no recognizer for .go: 1 file(s), e.g. server/go/server.go
- `unsupported_file` server/java/src/main/java/com/stripe/sample/Server.java: no recognizer for .java: 1 file(s), e.g. server/java/src/main/java/com/stripe/sample/Server.java
- `unsupported_file` server/php/public/create-checkout-session.php: no recognizer for .php: 4 file(s), e.g. server/php/public/create-checkout-session.php, server/php/public/get-checkout-session.php, server/php/public/shared.php
- `unsupported_file` server/ruby/server.rb: no recognizer for .rb: 5 file(s), e.g. server/ruby/server.rb, spec/capybara_support.rb, spec/client_and_server_spec.rb
- `unknown_attribute` server/node/server.js: Question for the team: is TLS terminated in front of the HTTP listener on port (port=4242, debug=True), 4242? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` client/html/success.js:5: Question for the team: how is the link to Unresolved HTTP target authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
