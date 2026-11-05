# code2design report: node-express-realworld

Commit `30b68e1e8814`, tool 0.3.0-prototype, 0.1s.

## Coverage

| Language | Files parsed |
|---|---|
| javascript | 1 |
| typescript | 37 |
| (test files skipped) | 11 |

Detectors that ran: config@0.3, js@0.3

Facts: app_entry 1, config_value 3, control 18, dependencies 1, entry_point 20, listener 1, module 1, router_mount 5, schema 4, store_access 36, weakness 1

## Model

| Collection | Count |
|---|---|
| processes | 31 |
| entities | 1 |
| stores | 4 |
| boundaries | 1 |
| flows | 48 |
| entry_points | 20 |
| controls | 7 |
| weaknesses | 6 |
| schemas | 4 |
| assets | 1 |
| threat_agents | 3 |
| gaps | 6 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).

- **http**: 20 entry points, 3 without a detected authn control
- **listeners**: src/main.ts port PORT
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 11 declared in package.json; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface

### Entry points

| Entry point | Controls |
|---|---|
| POST /api/articles | auth.required, cors |
| GET /api/articles/:slug | auth.optional, cors |
| DELETE /api/articles/:slug/favorite | auth.required, cors |
| POST /api/users/login | cors |
| GET /api/profiles/:username | auth.optional, cors |
| POST /api/articles/:slug/comments | auth.required, cors |
| DELETE /api/profiles/:username/follow | cors, auth.required |
| DELETE /api/articles/:slug/comments/:id | auth.required, cors |
| GET /api/articles/:slug/comments | auth.optional, cors |
| GET /api/articles/feed | auth.required, cors |
| POST /api/users | cors |
| GET /api/user | auth.required, cors |
| GET /api/articles | auth.optional, cors |
| PUT /api/user | auth.required, cors |
| DELETE /api/articles/:slug | auth.required, cors |
| POST /api/articles/:slug/favorite | auth.required, cors |
| PUT /api/articles/:slug | auth.required, cors |
| GET / | cors |
| GET /api/tags | cors, auth.optional |
| POST /api/profiles/:username/follow | cors, auth.required |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Boundary |
|---|---|---|---|
| Postgres: Comment | postgres | - | - |
| Postgres: Tag | postgres | - | - |
| Postgres: User | postgres | - | - |
| Postgres: Article | postgres | - | - |

## Lint

- **warning** `unknown-link-attributes` article.service -> Postgres: Article: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Postgres: Comment -> article.service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` auth.service -> Postgres: User: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Postgres: Article -> article.service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Postgres: User -> auth.service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Postgres: Tag -> tag.service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` Postgres: User -> profile.service: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` profile.service -> Postgres: User: authentication=unknown, encryption=unknown
- **warning** `unknown-link-attributes` article.service -> Postgres: Comment: authentication=unknown, encryption=unknown
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process tag.service has only inputs; a detector may be missing

## Inferred elements (dashed in diagrams)

- repository: @api/source (confidence 0.5): No container or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Anonymous HTTP caller (confidence 0.9): 20 http entry points, 3 without a detected authn control
- Insider with access to repository: @api/source (confidence 0.8): one insider agent per trust boundary, placed inside it
- Authenticated HTTP caller (confidence 0.9): authn controls exist on some entry points; a valid credential holder is a distinct agent

## Gaps and questions

- `no_boundary_info` : No compose, Dockerfile or Kubernetes manifests found; the repository is the only trust boundary.
- `unknown_attribute` src/main.ts: Question for the team: is TLS terminated in front of the HTTP listener on port PORT? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/app/routes/article/article.service.ts:71: Question for the team: how is the link to Postgres: Article authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/app/routes/article/article.service.ts:487: Question for the team: how is the link to Postgres: Comment authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/app/routes/auth/auth.service.ts:10: Question for the team: how is the link to Postgres: User authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
- `unknown_attribute` src/app/routes/tag/tag.service.ts:16: Question for the team: how is the link to Postgres: Tag authenticated and is it encrypted in transit? (authentication=unknown, encryption=unknown)
