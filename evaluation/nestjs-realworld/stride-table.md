# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| MySQL: user | Data store | T R I D | credential, pii | in no boundary | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| HTTP client -> POST /api/articles handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| user.service -> MySQL: user | Data flow | T I D | credential, pii | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/{slug}/comments handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug} handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug}/favorite handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api/tags handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/feed handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| MySQL: tag -> tag.service | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles/{slug} handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/profiles/{username}/follow handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| MySQL: user -> user.service | Data flow | T I D | credential, pii | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| MySQL: Comment -> article.service | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/{slug}/comments handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| MySQL: follows -> article.service | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| MySQL: article -> article.service | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> PUT /api/articles/{slug} handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> PUT /api/user handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| profile.service -> MySQL: follows | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/user handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> GET /api handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MySQL: user -> article.service | Data flow | T I D | credential, pii | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/articles/{slug}/comments/{id} handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| article.service -> MySQL: Comment | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| article.service -> MySQL: article | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /api/users/login handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/articles/{slug}/favorite handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/users/{slug} handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| MySQL: follows -> profile.service | Data flow | T I D | - | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| article.service -> MySQL: user | Data flow | T I D | credential, pii | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| MySQL: user -> profile.service | Data flow | T I D | credential, pii | repository: nestjs-realworld | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /api/profiles/{username} handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /api/articles handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /api/users handler | Data flow | T I D | - | repository: nestjs-realworld | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> DELETE /api/profiles/{username}/follow handler | Data flow | T I D | - | repository: nestjs-realworld | AuthMiddleware | authentication=credentials, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| MySQL: Comment | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| MySQL: tag | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| MySQL: article | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| MySQL: follows | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| POST /api/users handler | Process | S T R I D E | - | - | none | entry point |
| GET /api/profiles/{username} handler | Process | S T R I D E | - | - | none | entry point |
| POST /api/articles handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| PUT /api/articles/{slug} handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| POST /api/profiles/{username}/follow handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| GET /api/articles/{slug}/comments handler | Process | S T R I D E | - | - | none | entry point |
| GET /api/user handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| DELETE /api/articles/{slug}/comments/{id} handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| article.service | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api handler | Process | S T R I D E | - | - | none | entry point |
| user.service | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /api/articles/{slug} handler | Process | S T R I D E | - | - | none | entry point |
| GET /api/tags handler | Process | S T R I D E | - | - | none | entry point |
| DELETE /api/articles/{slug} handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| DELETE /api/articles/{slug}/favorite handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| GET /api/articles/feed handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| GET /api/articles handler | Process | S T R I D E | - | - | none | entry point |
| POST /api/articles/{slug}/favorite handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| DELETE /api/users/{slug} handler | Process | S T R I D E | - | - | none | entry point |
| PUT /api/user handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| POST /api/articles/{slug}/comments handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| profile.service | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /api/users/login handler | Process | S T R I D E | - | - | none | entry point |
| tag.service | Process | S T R I D E | - | - | n/a (internal) |  |
| DELETE /api/profiles/{username}/follow handler | Process | S T R I D E | - | - | AuthMiddleware | entry point |
| no authentication control detected on GET /api/articles/{slug} | Weakness (info) | S E | - | - | ep:pa4qt6624r | CWE-306 Entry point without a detected authentication control (review) at src/article/article.controller.ts:38 |
| no authentication control detected on GET /api/profiles/{username} | Weakness (info) | S E | - | - | ep:cei35nlsey | CWE-306 Entry point without a detected authentication control (review) at src/profile/profile.controller.ts:18 |
| no authentication control detected on GET /api | Weakness (info) | S E | - | - | ep:rkbb4stivj | CWE-306 Entry point without a detected authentication control (review) at src/app.controller.ts:5 |
| no authentication control detected on POST /api/users | Weakness (info) | S E | - | - | ep:nnmc7v6pma | CWE-306 Entry point without a detected authentication control (review) at src/user/user.controller.ts:32 |
| no authentication control detected on POST /api/users/login | Weakness (info) | S E | - | - | ep:frfy4jtm6k | CWE-306 Entry point without a detected authentication control (review) at src/user/user.controller.ts:43 |
| no authentication control detected on DELETE /api/users/{slug} | Weakness (info) | S E | - | - | ep:dqg7qhkmho | CWE-306 Entry point without a detected authentication control (review) at src/user/user.controller.ts:37 |
| no authentication control detected on GET /api/articles | Weakness (info) | S E | - | - | ep:qztradodta | CWE-306 Entry point without a detected authentication control (review) at src/article/article.controller.ts:24 |
| no authentication control detected on GET /api/tags | Weakness (info) | S E | - | - | ep:ug7w62z7oi | CWE-306 Entry point without a detected authentication control (review) at src/tag/tag.controller.ts:17 |
| no authentication control detected on GET /api/articles/{slug}/comments | Weakness (info) | S E | - | - | ep:b5bnlf72w4 | CWE-306 Entry point without a detected authentication control (review) at src/article/article.controller.ts:43 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | article.service, user.service, profile.service | MySQL: user | - |
| credential | article.service, user.service, profile.service | MySQL: user | - |
