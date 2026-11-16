# code2design report: golang-gin-realworld

Commit `a41289b2a495`, code2design 0.5.1, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| go | 21 |
| (test files, not modelled) | 4 |

Detectors: config@0.5, go@0.5, synth@0.5.1

Facts: app 1, control 1, dependencies 1, entry_point 27, listener 1, module 1, router 10, router_mount 9, schema 7, store_access 38

## Model

| Collection | Count |
|---|---|
| processes | 28 |
| entities | 1 |
| stores | 8 |
| boundaries | 1 |
| flows | 56 |
| entry_points | 20 |
| controls | 1 |
| weaknesses | 7 |
| schemas | 7 |
| assets | 2 |
| threat_agents | 3 |
| gaps | 12 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 19 entry points, 7 without a detected authentication control (0 of them published outside the deployment); 1 infrastructure entry points (health, preflight, docs) not counted
- **listeners**: hello.go port ":" + port
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 38 declared in go.mod; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 7 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| GET /api/articles/{slug}/comments | unknown | none | SQLite: ArticleModel, SQLite: FavoriteModel |
| POST /api/users/login | unknown | none | SQLite: UserModel |
| GET /api/profiles/{username} | unknown | none | SQLite: UserModel |
| GET /api/articles | unknown | none | SQLite: FavoriteModel |
| POST /api/users | unknown | none | SQLite: UserModel, SQLite (table unresolved) |
| POST /api/articles | unknown | users.AuthMiddleware | SQLite: ArticleModel, SQLite: FavoriteModel, SQLite (table unresolved) |
| DELETE /api/articles/{slug}/comments/{id} | unknown | users.AuthMiddleware | SQLite: ArticleModel, SQLite: CommentModel |
| GET /api/ping (infrastructure) | unknown | none | - |
| DELETE /api/articles/{slug}/favorite | unknown | users.AuthMiddleware | SQLite: ArticleModel, SQLite: FavoriteModel |
| PUT /api/user | unknown | users.AuthMiddleware | SQLite: UserModel, SQLite (table unresolved) |
| GET /api/articles/{slug} | unknown | none | SQLite: ArticleModel, SQLite: FavoriteModel |
| PUT /api/articles/{slug} | unknown | users.AuthMiddleware | SQLite: ArticleModel, SQLite: TagModel, SQLite: FavoriteModel |
| DELETE /api/profiles/{username}/follow | unknown | users.AuthMiddleware | SQLite: FollowModel, SQLite: UserModel |
| GET /api/tags | unknown | none | SQLite: TagModel, SQLite: FavoriteModel |
| POST /api/articles/{slug}/favorite | unknown | users.AuthMiddleware | SQLite: ArticleModel, SQLite: FavoriteModel |
| POST /api/profiles/{username}/follow | unknown | users.AuthMiddleware | SQLite: FollowModel, SQLite: UserModel |
| POST /api/articles/{slug}/comments | unknown | users.AuthMiddleware | SQLite: ArticleModel, SQLite: FavoriteModel, SQLite (table unresolved) |
| DELETE /api/articles/{slug} | unknown | users.AuthMiddleware | SQLite: ArticleModel |
| GET /api/articles/feed | unknown | users.AuthMiddleware | SQLite: ArticleModel, SQLite: ArticleUserModel, SQLite: FavoriteModel |
| GET /api/user | unknown | users.AuthMiddleware | - |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| info | CWE-306 | no authentication control detected on GET /api/articles/{slug}/comments | articles/routers.go:31 |
| info | CWE-306 | no authentication control detected on GET /api/profiles/{username} | users/routers.go:26 |
| info | CWE-306 | no authentication control detected on GET /api/articles/{slug} | articles/routers.go:30 |
| info | CWE-306 | no authentication control detected on GET /api/tags | articles/routers.go:35 |
| info | CWE-306 | no authentication control detected on POST /api/users | users/routers.go:13 |
| info | CWE-306 | no authentication control detected on POST /api/users/login | users/routers.go:15 |
| info | CWE-306 | no authentication control detected on GET /api/articles | articles/routers.go:28 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| SQLite: FollowModel | sqlite | - | unknown | - |
| SQLite: UserModel | sqlite | credential, pii | unknown | - |
| SQLite: ArticleModel | sqlite | - | unknown | - |
| SQLite: ArticleUserModel | sqlite | - | unknown | - |
| SQLite: TagModel | sqlite | - | unknown | - |
| SQLite: FavoriteModel | sqlite | - | unknown | - |
| SQLite: CommentModel | sqlite | - | unknown | - |
| SQLite (table unresolved) | sqlite | - | unknown | - |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles/{slug} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/ping handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/users handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/articles/{slug}/comments handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/profiles/{username} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /api/users/login handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /api/tags handler
- **info** `black-hole-or-miracle` process GET /api/user handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process middlewares has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /api/ping handler has only inputs; a detector may be missing
- **info** `unknown-link-attributes` SQLite: UserModel -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: CommentModel -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> SQLite: FollowModel: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> SQLite: TagModel: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: UserModel -> middlewares: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: ArticleUserModel -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> SQLite (table unresolved): authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> SQLite: FavoriteModel: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: FollowModel -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: ArticleModel -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> SQLite: ArticleModel: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: UserModel -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> SQLite: CommentModel: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: FavoriteModel -> models: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` models -> SQLite (table unresolved): authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQLite: TagModel -> models: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: golang-gin-realworld (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Anonymous HTTP caller (confidence 0.9): 19 entry points are reachable from outside, 7 of them without a detected authentication control
- Insider with access to repository: golang-gin-realworld (confidence 0.8): one insider agent per trust boundary, placed inside it
- Authenticated HTTP caller (confidence 0.9): 12 entry points require authentication; a holder of valid credentials is a distinct agent

## Gaps and questions

- `unresolved` articles/models.go:147: a sqlite access could not be traced to a table; it is shown as a separate store
- `no_boundary_info` : no docker compose, Dockerfile, Kubernetes or Terraform descriptors were found; the repository is the only trust boundary
- `unknown_attribute` hello.go: Question: is TLS terminated in front of the HTTP listener of golang-gin-realworld? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` users/models.go:86: Question: what is the authentication and encryption of the link to SQLite: UserModel?
- `unknown_attribute` articles/models.go:161: Question: what is the authentication and encryption of the link to SQLite: CommentModel?
- `unknown_attribute` users/models.go:105: Question: what is the authentication and encryption of the link to SQLite: FollowModel?
- `unknown_attribute` articles/models.go:361: Question: what is the authentication and encryption of the link to SQLite: TagModel?
- `unknown_attribute` articles/models.go:211: Question: what is the authentication and encryption of the link to SQLite: ArticleUserModel?
- `unknown_attribute` users/models.go:95: Question: what is the authentication and encryption of the link to SQLite (table unresolved)?
- `unknown_attribute` articles/models.go:132: Question: what is the authentication and encryption of the link to SQLite: FavoriteModel?
- `unknown_attribute` articles/models.go:154: Question: what is the authentication and encryption of the link to SQLite: ArticleModel?
- `unknown_attribute` users/models.go:16: Question: is SQLite: UserModel encrypted at rest? It holds credential, pii.
