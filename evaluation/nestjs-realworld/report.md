# code2design report: nestjs-realworld

Commit `c1c2cc4e448b`, code2design 0.5.1, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 1 |
| typescript | 35 |
| (test files, not modelled) | 1 |

Detectors: config@0.5, js@0.5, nest@0.5, synth@0.5.1

Facts: app 1, control 3, dependencies 1, entry_point 21, global_prefix 1, listener 1, module 1, router 5, schema 5, store_access 63

## Model

| Collection | Count |
|---|---|
| processes | 32 |
| entities | 1 |
| stores | 5 |
| boundaries | 1 |
| flows | 54 |
| entry_points | 21 |
| controls | 3 |
| weaknesses | 9 |
| schemas | 5 |
| assets | 2 |
| threat_agents | 3 |
| gaps | 8 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 21 entry points, 9 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: src/main.ts port 3000
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 22 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 9 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /api/articles/feed | unknown | AuthMiddleware | MySQL: article, MySQL: follows |
| POST /api/articles/{slug}/comments | unknown | AuthMiddleware | MySQL: Comment, MySQL: article |
| GET /api/user | unknown | AuthMiddleware | MySQL: user |
| GET /api/articles/{slug}/comments | unknown | none | MySQL: article |
| GET /api/profiles/{username} | unknown | none | MySQL: user, MySQL: follows |
| POST /api/articles/{slug}/favorite | unknown | AuthMiddleware | MySQL: user, MySQL: article |
| DELETE /api/profiles/{username}/follow | unknown | AuthMiddleware | MySQL: user, MySQL: follows |
| DELETE /api/users/{slug} | unknown | none | MySQL: user |
| PUT /api/articles/{slug} | unknown | AuthMiddleware | MySQL: article |
| POST /api/users/login | unknown | none | MySQL: user |
| DELETE /api/articles/{slug}/favorite | unknown | AuthMiddleware | MySQL: user, MySQL: article |
| POST /api/users | unknown | none | MySQL: user |
| GET /api/articles/{slug} | unknown | none | MySQL: article |
| GET /api/articles | unknown | none | MySQL: user, MySQL: article |
| DELETE /api/articles/{slug}/comments/{id} | unknown | AuthMiddleware | MySQL: Comment, MySQL: article |
| POST /api/articles | unknown | AuthMiddleware | MySQL: user, MySQL: article |
| GET /api | unknown | none | - |
| GET /api/tags | unknown | none | MySQL: tag |
| POST /api/profiles/{username}/follow | unknown | AuthMiddleware | MySQL: user, MySQL: follows |
| PUT /api/user | unknown | AuthMiddleware | MySQL: user |
| DELETE /api/articles/{slug} | unknown | AuthMiddleware | MySQL: article |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| info | CWE-306 | no authentication control detected on GET /api/articles/{slug} | src/article/article.controller.ts:38 |
| info | CWE-306 | no authentication control detected on GET /api/profiles/{username} | src/profile/profile.controller.ts:18 |
| info | CWE-306 | no authentication control detected on GET /api | src/app.controller.ts:5 |
| info | CWE-306 | no authentication control detected on POST /api/users | src/user/user.controller.ts:32 |
| info | CWE-306 | no authentication control detected on POST /api/users/login | src/user/user.controller.ts:43 |
| info | CWE-306 | no authentication control detected on DELETE /api/users/{slug} | src/user/user.controller.ts:37 |
| info | CWE-306 | no authentication control detected on GET /api/articles | src/article/article.controller.ts:24 |
| info | CWE-306 | no authentication control detected on GET /api/tags | src/tag/tag.controller.ts:17 |
| info | CWE-306 | no authentication control detected on GET /api/articles/{slug}/comments | src/article/article.controller.ts:43 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| MySQL: Comment | mysql | - | unknown | - |
| MySQL: tag | mysql | - | unknown | - |
| MySQL: user | mysql | credential, pii | unknown | - |
| MySQL: article | mysql | - | unknown | - |
| MySQL: follows | mysql | - | unknown | - |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles/{slug}/comments handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/tags handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles/{slug} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/users/login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> DELETE /api/users/{slug} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/profiles/{username} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/users handler
- **info** `black-hole-or-miracle` process GET /api handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process tag.service has only inputs; a detector may be missing
- **info** `unknown-link-attributes` user.service -> MySQL: user: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: tag -> tag.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: user -> user.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: Comment -> article.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: follows -> article.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: article -> article.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` profile.service -> MySQL: follows: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: user -> article.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` article.service -> MySQL: Comment: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` article.service -> MySQL: article: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: follows -> profile.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` article.service -> MySQL: user: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` MySQL: user -> profile.service: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: nestjs-realworld (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Anonymous HTTP caller (confidence 0.9): 21 entry points are reachable from outside, 9 of them without a detected authentication control
- Authenticated HTTP caller (confidence 0.9): 12 entry points require authentication; a holder of valid credentials is a distinct agent
- Insider with access to repository: nestjs-realworld (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `no_boundary_info` : no docker compose, Dockerfile, Kubernetes or Terraform descriptors were found; the repository is the only trust boundary
- `unknown_attribute` src/main.ts: Question: is TLS terminated in front of the HTTP listener of nestjs-realworld? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/user/user.service.ts:68: Question: what is the authentication and encryption of the link to MySQL: user?
- `unknown_attribute` src/tag/tag.service.ts:14: Question: what is the authentication and encryption of the link to MySQL: tag?
- `unknown_attribute` src/article/article.service.ts:117: Question: what is the authentication and encryption of the link to MySQL: Comment?
- `unknown_attribute` src/article/article.service.ts:67: Question: what is the authentication and encryption of the link to MySQL: follows?
- `unknown_attribute` src/article/article.service.ts:28: Question: what is the authentication and encryption of the link to MySQL: article?
- `unknown_attribute` src/user/user.entity.ts:6: Question: is MySQL: user encrypted at rest? It holds credential, pii.
