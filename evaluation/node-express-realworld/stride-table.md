# STRIDE per element

Rows are ordered by priority hint (exit points and weaknesses first).

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |
|---|---|---|---|---|---|---|
| no authn control detected on POST /api/users/login | Weakness | - | - | - | - | unauthenticated_entry_point at src/app/routes/auth/auth.controller.ts:30 |
| no authn control detected on GET / | Weakness | - | - | - | - | unauthenticated_entry_point at src/main.ts:21 |
| JWT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at src/app/routes/auth/auth.ts:21 |
| cors() with default or wildcard origin | Weakness | - | - | - | - | permissive_cors at src/main.ts:13 |
| JWT_SECRET read at module import | Weakness | - | - | - | - | secret_in_env_at_import at src/app/routes/auth/auth.ts:16 |
| no authn control detected on POST /api/users | Weakness | - | - | - | - | unauthenticated_entry_point at src/app/routes/auth/auth.controller.ts:14 |
| HTTP client | External entity | S R | - | - | - | inbound caller; verify authentication on every entry point |
| HTTP client -> DELETE /api/articles/:slug handler | Data flow | T I D | - | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/feed handler | Data flow | T I D | internal | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /api/users handler | Data flow | T I D | internal | repository: @api/source | cors | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/user handler | Data flow | T I D | - | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/:slug/favorite handler | Data flow | T I D | - | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: @api/source | cors | authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles handler | Data flow | T I D | - | repository: @api/source | auth.optional, cors | authentication=credentials, encryption=unknown: question for the team |
| article.service -> Postgres: Article | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Comment -> article.service | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/profiles/:username handler | Data flow | T I D | - | repository: @api/source | auth.optional, cors | authentication=credentials, encryption=unknown: question for the team |
| auth.service -> Postgres: User | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: Article -> article.service | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| Postgres: User -> auth.service | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> PUT /api/articles/:slug handler | Data flow | T I D | internal | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| Postgres: Tag -> tag.service | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/:slug/comments handler | Data flow | T I D | internal | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/:slug handler | Data flow | T I D | - | repository: @api/source | auth.optional, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/:slug/favorite handler | Data flow | T I D | - | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /api/profiles/:username/follow handler | Data flow | T I D | - | repository: @api/source | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles handler | Data flow | T I D | internal | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/:slug/comments handler | Data flow | T I D | - | repository: @api/source | auth.optional, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/:slug/comments/:id handler | Data flow | T I D | - | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/tags handler | Data flow | T I D | - | repository: @api/source | cors, auth.optional | authentication=credentials, encryption=unknown: question for the team |
| Postgres: User -> profile.service | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> PUT /api/user handler | Data flow | T I D | internal | repository: @api/source | auth.required, cors | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/profiles/:username/follow handler | Data flow | T I D | - | repository: @api/source | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| profile.service -> Postgres: User | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| article.service -> Postgres: Comment | Data flow | T I D | - | repository: @api/source | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/users/login handler | Data flow | T I D | internal | repository: @api/source | cors | authentication=none, encryption=unknown: question for the team |
| Postgres: Comment | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: Tag | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: User | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: Article | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| POST /api/articles/:slug/comments handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| GET / handler | Process | S T R I D E | - | - | cors | entry point |
| POST /api/profiles/:username/follow handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| POST /api/users/login handler | Process | S T R I D E | - | - | cors | entry point |
| PUT /api/articles/:slug handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| DELETE /api/articles/:slug/comments/:id handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| PUT /api/user handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| GET /api/profiles/:username handler | Process | S T R I D E | - | - | auth.optional, cors | entry point |
| tag.service | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /api/articles/:slug/favorite handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| GET /api/articles/:slug/comments handler | Process | S T R I D E | - | - | auth.optional, cors | entry point |
| DELETE /api/articles/:slug/favorite handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| POST /api/articles handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| DELETE /api/profiles/:username/follow handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| GET /api/articles/:slug handler | Process | S T R I D E | - | - | auth.optional, cors | entry point |
| GET /api/tags handler | Process | S T R I D E | - | - | cors, auth.optional | entry point |
| DELETE /api/articles/:slug handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| POST /api/users handler | Process | S T R I D E | - | - | cors | entry point |
| auth.service | Process | S T R I D E | - | - | n/a (internal) |  |
| article.service | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/articles/feed handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| GET /api/articles handler | Process | S T R I D E | - | - | auth.optional, cors | entry point |
| GET /api/user handler | Process | S T R I D E | - | - | auth.required, cors | entry point |
| profile.service | Process | S T R I D E | - | - | n/a (internal) |  |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
