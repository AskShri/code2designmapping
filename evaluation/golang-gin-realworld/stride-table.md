# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| SQLite: UserModel | Data store | T R I D | credential, pii | in no boundary | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| SQLite: UserModel -> models (3dfh) | Data flow | T I D | credential, pii | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| SQLite: CommentModel -> models (k4l4) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| models (3dfh) -> SQLite: FollowModel | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug} handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| models (k4l4) -> SQLite: TagModel | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/feed handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| SQLite: UserModel -> middlewares | Data flow | T I D | credential, pii | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/{slug}/comments handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/{slug} handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> PUT /api/articles/{slug} handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| SQLite: ArticleUserModel -> models (k4l4) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| models (3dfh) -> SQLite (table unresolved) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/profiles/{username}/follow handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/ping handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| models (k4l4) -> SQLite: FavoriteModel | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/users handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug}/favorite handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| SQLite: FollowModel -> models (3dfh) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/{slug}/comments handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/profiles/{username}/follow handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| SQLite: ArticleModel -> models (k4l4) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| models (k4l4) -> SQLite: ArticleModel | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/profiles/{username} handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug}/comments/{id} handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| SQLite: UserModel -> models (k4l4) | Data flow | T I D | credential, pii | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| models (k4l4) -> SQLite: CommentModel | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/{slug}/favorite handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /api/users/login handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> PUT /api/user handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| SQLite: FavoriteModel -> models (k4l4) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/tags handler | Data flow | T I D | - | repository: golang-gin-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| models (k4l4) -> SQLite (table unresolved) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| SQLite: TagModel -> models (k4l4) | Data flow | T I D | - | repository: golang-gin-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/user handler | Data flow | T I D | - | repository: golang-gin-realworld | users.AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| SQLite: FollowModel | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQLite: ArticleModel | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQLite: ArticleUserModel | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQLite: TagModel | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQLite: FavoriteModel | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQLite: CommentModel | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQLite (table unresolved) | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| PUT /api/articles/{slug} handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| PUT /api/user handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| models | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/articles/{slug} handler | Process | S T R I D E | - | - | none | entry point |
| POST /api/profiles/{username}/follow handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| POST /api/articles/{slug}/comments handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| GET /api/tags handler | Process | S T R I D E | - | - | none | entry point |
| DELETE /api/articles/{slug}/comments/{id} handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| POST /api/users handler | Process | S T R I D E | - | - | none | entry point |
| DELETE /api/articles/{slug}/favorite handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| GET /api/user handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| GET /api/articles handler | Process | S T R I D E | - | - | none | entry point |
| GET /api/articles/{slug}/comments handler | Process | S T R I D E | - | - | none | entry point |
| DELETE /api/profiles/{username}/follow handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| middlewares | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /api/users/login handler | Process | S T R I D E | - | - | none | entry point |
| models | Process | S T R I D E | - | - | n/a (internal) |  |
| DELETE /api/articles/{slug} handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| GET /api/profiles/{username} handler | Process | S T R I D E | - | - | none | entry point |
| POST /api/articles handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| GET /api/articles/feed handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| POST /api/articles/{slug}/favorite handler | Process | S T R I D E | - | - | users.AuthMiddleware | entry point |
| no authentication control detected on GET /api/articles/{slug}/comments | Weakness (info) | S E | - | - | ep:3x7h6w6w6y | CWE-306 Entry point without a detected authentication control (review) at articles/routers.go:31 |
| no authentication control detected on GET /api/profiles/{username} | Weakness (info) | S E | - | - | ep:aw7aoy7pir | CWE-306 Entry point without a detected authentication control (review) at users/routers.go:26 |
| no authentication control detected on GET /api/articles/{slug} | Weakness (info) | S E | - | - | ep:namxldnlhp | CWE-306 Entry point without a detected authentication control (review) at articles/routers.go:30 |
| no authentication control detected on GET /api/tags | Weakness (info) | S E | - | - | ep:sh4mb7p5pj | CWE-306 Entry point without a detected authentication control (review) at articles/routers.go:35 |
| no authentication control detected on POST /api/users | Weakness (info) | S E | - | - | ep:f6a4m74ipc | CWE-306 Entry point without a detected authentication control (review) at users/routers.go:13 |
| no authentication control detected on POST /api/users/login | Weakness (info) | S E | - | - | ep:4qtbwu7r5d | CWE-306 Entry point without a detected authentication control (review) at users/routers.go:15 |
| no authentication control detected on GET /api/articles | Weakness (info) | S E | - | - | ep:eaajq5wukw | CWE-306 Entry point without a detected authentication control (review) at articles/routers.go:28 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | models (3dfh), middlewares, models (k4l4) | SQLite: UserModel | - |
| credential | models (3dfh), middlewares, models (k4l4) | SQLite: UserModel | - |
