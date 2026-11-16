# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| cors() with default or wildcard origin | Weakness (medium) | I | - | - | app | CWE-942 Permissive cross-origin policy at src/main.ts:13 |
| Postgres: User | Data store | T R I D | credential, pii | in no boundary | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| HTTP client -> GET /api/articles handler | Data flow | T I D | - | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug} handler | Data flow | T I D | - | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| article.service -> Postgres: Comment | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug}/comments/{id} handler | Data flow | T I D | - | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| Postgres: User -> profile.service | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/{slug}/comments handler | Data flow | T I D | internal | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| profile.service -> Postgres: User | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/{slug}/favorite handler | Data flow | T I D | - | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/profiles/{username}/follow handler | Data flow | T I D | - | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /api/users handler | Data flow | T I D | internal | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> PUT /api/articles/{slug} handler | Data flow | T I D | internal | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| Postgres: Comment -> article.service | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles handler | Data flow | T I D | internal | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug}/favorite handler | Data flow | T I D | - | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| Postgres: Article -> article.service | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/feed handler | Data flow | T I D | internal | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| auth.service -> Postgres: User | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/{slug}/comments handler | Data flow | T I D | - | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/{slug} handler | Data flow | T I D | - | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/profiles/{username}/follow handler | Data flow | T I D | - | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> PUT /api/user handler | Data flow | T I D | internal | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| Postgres: Tag -> tag.service | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/profiles/{username} handler | Data flow | T I D | - | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| Postgres: User -> auth.service | Data flow | T I D | credential, pii | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/tags handler | Data flow | T I D | - | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| article.service -> Postgres: Article | Data flow | T I D | - | container: app | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/user handler | Data flow | T I D | - | container: app | cors, auth.required | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> POST /api/users/login handler | Data flow | T I D | internal | container: app | cors | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| Postgres: Comment | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: Tag | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| Postgres: Article | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| POST /api/articles handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| DELETE /api/articles/{slug} handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| POST /api/users/login handler | Process | S T R I D E | - | - | cors | entry point |
| POST /api/profiles/{username}/follow handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| GET /api/articles/{slug}/comments handler | Process | S T R I D E | - | - | cors | entry point |
| PUT /api/articles/{slug} handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| GET /api/articles/{slug} handler | Process | S T R I D E | - | - | cors | entry point |
| GET /api/articles/feed handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| GET /api/tags handler | Process | S T R I D E | - | - | cors | entry point |
| POST /api/users handler | Process | S T R I D E | - | - | cors | entry point |
| POST /api/articles/{slug}/favorite handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| auth.service | Process | S T R I D E | - | - | n/a (internal) |  |
| DELETE /api/profiles/{username}/follow handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| article.service | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/profiles/{username} handler | Process | S T R I D E | - | - | cors | entry point |
| DELETE /api/articles/{slug}/comments/{id} handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| GET /api/articles handler | Process | S T R I D E | - | - | cors | entry point |
| tag.service | Process | S T R I D E | - | - | n/a (internal) |  |
| DELETE /api/articles/{slug}/favorite handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| GET / handler | Process | S T R I D E | - | - | cors | entry point |
| PUT /api/user handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| POST /api/articles/{slug}/comments handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| GET /api/user handler | Process | S T R I D E | - | - | cors, auth.required | entry point |
| profile.service | Process | S T R I D E | - | - | n/a (internal) |  |
| no authentication control detected on GET /api/articles | Weakness (info) | S E | - | - | ep:yzeu66lt42 | CWE-306 Entry point without a detected authentication control (review) at src/app/routes/article/article.controller.ts:30 |
| no authentication control detected on POST /api/users/login | Weakness (info) | S E | - | - | ep:3thytlcx65 | CWE-306 Entry point without a detected authentication control (review) at src/app/routes/auth/auth.controller.ts:30 |
| no authentication control detected on POST /api/users | Weakness (info) | S E | - | - | ep:2cxtkdmljh | CWE-306 Entry point without a detected authentication control (review) at src/app/routes/auth/auth.controller.ts:14 |
| no authentication control detected on GET /api/articles/{slug} | Weakness (info) | S E | - | - | ep:vknyow6e26 | CWE-306 Entry point without a detected authentication control (review) at src/app/routes/article/article.controller.ts:87 |
| no authentication control detected on GET /api/tags | Weakness (info) | S E | - | - | ep:jcoosm64n2 | CWE-306 Entry point without a detected authentication control (review) at src/app/routes/tag/tag.controller.ts:13 |
| no authentication control detected on GET /api/articles/{slug}/comments | Weakness (info) | S E | - | - | ep:rd3qalpik6 | CWE-306 Entry point without a detected authentication control (review) at src/app/routes/article/article.controller.ts:149 |
| no authentication control detected on GET /api/profiles/{username} | Weakness (info) | S E | - | - | ep:4g2iyi4gjl | CWE-306 Entry point without a detected authentication control (review) at src/app/routes/profile/profile.controller.ts:14 |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:bvfubx2g5n | CWE-306 Entry point without a detected authentication control (review) at src/main.ts:21 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | auth.service, profile.service | Postgres: User | - |
| credential | auth.service, profile.service | Postgres: User | - |
