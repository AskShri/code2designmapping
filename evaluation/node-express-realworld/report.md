# code2design report: node-express-realworld

Commit `30b68e1e8814`, code2design 0.5.1, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 1 |
| typescript | 37 |
| (test files, not modelled) | 11 |

Detectors: config@0.5, js@0.5, synth@0.5.1

Facts: app 1, boundary_hint 1, config_value 2, control 13, dependencies 1, entry_point 20, listener 1, module 1, router 7, router_mount 6, schema 12, store_access 36, weakness 1

## Model

| Collection | Count |
|---|---|
| processes | 31 |
| entities | 1 |
| stores | 4 |
| boundaries | 1 |
| flows | 48 |
| entry_points | 20 |
| controls | 4 |
| weaknesses | 9 |
| schemas | 6 |
| assets | 3 |
| threat_agents | 3 |
| gaps | 6 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 20 entry points, 8 without a detected authentication control (0 of them published outside the deployment)
- **listeners**: src/main.ts port PORT
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 11 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 1 medium, 8 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| POST /api/users | unknown | cors | Postgres: User |
| POST /api/users/login | unknown | cors | Postgres: User |
| GET /api/profiles/{username} | unknown | cors | Postgres: User |
| POST /api/profiles/{username}/follow | unknown | cors, auth.required | Postgres: User |
| POST /api/articles/{slug}/favorite | unknown | cors, auth.required | Postgres: Article |
| GET / | unknown | cors | - |
| DELETE /api/articles/{slug}/comments/{id} | unknown | cors, auth.required | Postgres: Comment |
| POST /api/articles | unknown | cors, auth.required | Postgres: Article |
| GET /api/tags | unknown | cors | Postgres: Tag |
| DELETE /api/articles/{slug} | unknown | cors, auth.required | Postgres: Article |
| DELETE /api/articles/{slug}/favorite | unknown | cors, auth.required | Postgres: Article |
| DELETE /api/profiles/{username}/follow | unknown | cors, auth.required | Postgres: User |
| GET /api/user | unknown | cors, auth.required | Postgres: User |
| PUT /api/user | unknown | cors, auth.required | Postgres: User |
| GET /api/articles/{slug}/comments | unknown | cors | Postgres: Article |
| PUT /api/articles/{slug} | unknown | cors, auth.required | Postgres: Article |
| GET /api/articles/{slug} | unknown | cors | Postgres: Article |
| GET /api/articles/feed | unknown | cors, auth.required | Postgres: Article |
| POST /api/articles/{slug}/comments | unknown | cors, auth.required | Postgres: Comment, Postgres: Article |
| GET /api/articles | unknown | cors | Postgres: Article |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| medium | CWE-942 | cors() with default or wildcard origin | src/main.ts:13 |
| info | CWE-306 | no authentication control detected on GET /api/articles | src/app/routes/article/article.controller.ts:30 |
| info | CWE-306 | no authentication control detected on POST /api/users/login | src/app/routes/auth/auth.controller.ts:30 |
| info | CWE-306 | no authentication control detected on POST /api/users | src/app/routes/auth/auth.controller.ts:14 |
| info | CWE-306 | no authentication control detected on GET /api/articles/{slug} | src/app/routes/article/article.controller.ts:87 |
| info | CWE-306 | no authentication control detected on GET /api/tags | src/app/routes/tag/tag.controller.ts:13 |
| info | CWE-306 | no authentication control detected on GET /api/articles/{slug}/comments | src/app/routes/article/article.controller.ts:149 |
| info | CWE-306 | no authentication control detected on GET /api/profiles/{username} | src/app/routes/profile/profile.controller.ts:14 |
| info | CWE-306 | no authentication control detected on GET / | src/main.ts:21 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| Postgres: Comment | postgres | - | unknown | - |
| Postgres: Tag | postgres | - | unknown | - |
| Postgres: User | postgres | credential, pii | unknown | - |
| Postgres: Article | postgres | - | unknown | - |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/users handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles/{slug}/comments handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles/{slug} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/profiles/{username} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/tags handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/users/login handler
- **warning** `weakness-permissive-cors` CWE-942 cors() with default or wildcard origin (src/main.ts:13)
- **info** `black-hole-or-miracle` process tag.service has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` article.service -> Postgres: Comment: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> profile.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` profile.service -> Postgres: User: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Comment -> article.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Article -> article.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` auth.service -> Postgres: User: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: Tag -> tag.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` Postgres: User -> auth.service: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` article.service -> Postgres: Article: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- Anonymous HTTP caller (confidence 0.9): 20 entry points are reachable from outside, 8 of them without a detected authentication control
- Authenticated HTTP caller (confidence 0.9): 12 entry points require authentication; a holder of valid credentials is a distinct agent
- Insider with access to container: app (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

- `unknown_attribute` src/main.ts: Question: is TLS terminated in front of the HTTP listener of app? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/app/routes/article/article.service.ts:487: Question: what is the authentication and encryption of the link to Postgres: Comment?
- `unknown_attribute` src/app/routes/profile/profile.service.ts:6: Question: what is the authentication and encryption of the link to Postgres: User?
- `unknown_attribute` src/app/routes/article/article.service.ts:71: Question: what is the authentication and encryption of the link to Postgres: Article?
- `unknown_attribute` src/app/routes/tag/tag.service.ts:16: Question: what is the authentication and encryption of the link to Postgres: Tag?
- `unknown_attribute` src/prisma/schema.prisma:43: Question: is Postgres: User encrypted at rest? It holds credential, pii.
