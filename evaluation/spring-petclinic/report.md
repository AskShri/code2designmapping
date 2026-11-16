# code2design report: spring-petclinic

Commit `500158f73241`, code2design 0.5.2, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| java | 50 |
| (test files, not modelled) | 20 |

Detectors: config@0.5, java@0.5, synth@0.5.2

Facts: app 1, boundary_hint 4, call_edge 19, control 5, dependencies 1, entry_point 17, module 1, router 6, schema 4, service_host 2, store_access 24, weakness 3

## Model

| Collection | Count |
|---|---|
| processes | 25 |
| entities | 1 |
| stores | 6 |
| boundaries | 1 |
| flows | 41 |
| entry_points | 17 |
| controls | 3 |
| weaknesses | 20 |
| schemas | 4 |
| assets | 1 |
| threat_agents | 2 |
| gaps | 9 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **http**: 17 entry points, 17 without a detected authentication control (0 of them published outside the deployment)
- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 30 declared in pom.xml; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface
- **weaknesses**: 3 high, 17 info (see stride-table.md and findings.sarif)

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|
| POST /owners/new | unknown | @Valid | SQL database: owners |
| GET /owners/{ownerId}/pets/{petId}/edit | unknown | none | SQL database: owners, SQL database: types |
| GET /vets | unknown | none | SQL database: vets |
| GET /owners/{ownerId} | unknown | none | SQL database: owners |
| POST /owners/{ownerId}/edit | unknown | @Valid | SQL database: owners |
| GET /owners/{ownerId}/pets/{petId}/visits/new | unknown | none | SQL database: owners |
| GET /owners/find | unknown | none | - |
| POST /owners/{ownerId}/pets/{petId}/visits/new | unknown | @Valid | SQL database: owners |
| GET /vets.html | unknown | none | SQL database: vets |
| POST /owners/{ownerId}/pets/new | unknown | @Valid | SQL database: owners, SQL database: types |
| GET /owners/{ownerId}/pets/new | unknown | none | SQL database: owners, SQL database: types |
| GET /owners/new | unknown | none | - |
| GET /oups | unknown | none | - |
| GET / | unknown | none | - |
| GET /owners | unknown | none | SQL database: owners |
| POST /owners/{ownerId}/pets/{petId}/edit | unknown | @Valid | SQL database: owners, SQL database: types |
| GET /owners/{ownerId}/edit | unknown | none | SQL database: owners |

### Weaknesses

| Severity | CWE | Weakness | Location |
|---|---|---|---|
| high | CWE-798 | POSTGRES_PASSWORD set in compose service 'postgres' | docker-compose.yml:19 |
| high | CWE-798 | MYSQL_PASSWORD set in compose service 'mysql' | docker-compose.yml:10 |
| high | CWE-798 | MYSQL_ALLOW_EMPTY_PASSWORD set in compose service 'mysql' | docker-compose.yml:8 |
| info | CWE-306 | no authentication control detected on GET /owners/{ownerId} | src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:178 |
| info | CWE-306 | no authentication control detected on GET /vets | src/main/java/org/springframework/samples/petclinic/vet/VetController.java:72 |
| info | CWE-306 | no authentication control detected on GET /oups | src/main/java/org/springframework/samples/petclinic/system/CrashController.java:31 |
| info | CWE-306 | no authentication control detected on POST /owners/{ownerId}/pets/{petId}/edit | src/main/java/org/springframework/samples/petclinic/owner/PetController.java:144 |
| info | CWE-306 | no authentication control detected on GET /owners/{ownerId}/pets/{petId}/edit | src/main/java/org/springframework/samples/petclinic/owner/PetController.java:139 |
| info | CWE-306 | no authentication control detected on GET /owners/{ownerId}/pets/new | src/main/java/org/springframework/samples/petclinic/owner/PetController.java:100 |
| info | CWE-306 | no authentication control detected on GET /owners/{ownerId}/pets/{petId}/visits/new | src/main/java/org/springframework/samples/petclinic/owner/VisitController.java:90 |
| info | CWE-306 | no authentication control detected on GET /owners/new | src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:72 |
| info | CWE-306 | no authentication control detected on GET /owners/find | src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:89 |
| info | CWE-306 | no authentication control detected on GET /owners | src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:94 |
| info | CWE-306 | no authentication control detected on POST /owners/{ownerId}/pets/{petId}/visits/new | src/main/java/org/springframework/samples/petclinic/owner/VisitController.java:97 |
| info | CWE-306 | no authentication control detected on GET /vets.html | src/main/java/org/springframework/samples/petclinic/vet/VetController.java:45 |
| info | CWE-306 | no authentication control detected on POST /owners/new | src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:77 |
| info | CWE-306 | no authentication control detected on POST /owners/{ownerId}/edit | src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:153 |
| info | CWE-306 | no authentication control detected on GET / | src/main/java/org/springframework/samples/petclinic/system/WelcomeController.java:25 |
| info | CWE-306 | no authentication control detected on GET /owners/{ownerId}/edit | src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:148 |
| info | CWE-306 | no authentication control detected on POST /owners/{ownerId}/pets/new | src/main/java/org/springframework/samples/petclinic/owner/PetController.java:107 |

### External entities

| Entity | Kind | Host |
|---|---|---|
| HTTP client | system | - |

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|
| SQL database: pets | sql (one of mysql, postgres) | pii | unknown | - |
| SQL database: specialties | sql (one of mysql, postgres) | - | unknown | - |
| SQL database: owners | sql (one of mysql, postgres) | pii | unknown | - |
| SQL database: vets | sql (one of mysql, postgres) | - | unknown | - |
| SQL database: visits | sql (one of mysql, postgres) | - | unknown | - |
| SQL database: types | sql (one of mysql, postgres) | - | unknown | - |

## Lint

- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /vets.html handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /owners/{ownerId}/edit handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /oups handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners/{ownerId}/pets/new handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /owners/{ownerId}/pets/new handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners/{ownerId}/pets/{petId}/edit handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /owners/{ownerId}/pets/{petId}/visits/new handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /owners/{ownerId}/pets/{petId}/edit handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners/find handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners/{ownerId}/edit handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /vets handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET / handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> POST /owners/new handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners/new handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners/{ownerId} handler
- **warning** `unauthenticated-crossing` inbound flow crosses a boundary without authentication: HTTP client -> GET /owners/{ownerId}/pets/{petId}/visits/new handler
- **warning** `weakness-plaintext-credentials` CWE-798 POSTGRES_PASSWORD set in compose service 'postgres' (docker-compose.yml:19)
- **warning** `weakness-plaintext-credentials` CWE-798 MYSQL_PASSWORD set in compose service 'mysql' (docker-compose.yml:10)
- **warning** `weakness-plaintext-credentials` CWE-798 MYSQL_ALLOW_EMPTY_PASSWORD set in compose service 'mysql' (docker-compose.yml:8)
- **info** `black-hole-or-miracle` process GET /oups handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /owners/new handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process VetController has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET / handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process VisitController has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /owners/find handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process GET /vets handler has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process PetTypeFormatter has only inputs; a detector may be missing
- **info** `black-hole-or-miracle` process OwnerController has only inputs; a detector may be missing
- **info** `unknown-link-attributes` SQL database: types -> PetController: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /owners/{ownerId}/pets/{petId}/visits/new handler -> SQL database: owners: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL database: owners -> OwnerController: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL database: vets -> VetController: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL database: owners -> VisitController: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /owners/{ownerId}/edit handler -> SQL database: owners: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL database: owners -> PetController: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL database: owners -> GET /owners/{ownerId} handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` PetController -> SQL database: owners: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL database: types -> PetTypeFormatter: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /owners/new handler -> SQL database: owners: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` SQL database: vets -> GET /vets handler: authentication=unknown, encryption=unknown
- **info** `unknown-link-attributes` POST /owners/{ownerId}/pets/new handler -> SQL database: owners: authentication=unknown, encryption=unknown

## Inferred elements (dashed in diagrams)

- repository: spring-petclinic (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to repository: spring-petclinic (confidence 0.8): one insider agent per trust boundary, placed inside it
- Anonymous HTTP caller (confidence 0.9): 17 entry points are reachable from outside, 17 of them without a detected authentication control

## Gaps and questions

- `unresolved` src/main/java/org/springframework/samples/petclinic/owner/Pet.java:44: SQL database: pets is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unresolved` src/main/java/org/springframework/samples/petclinic/vet/Specialty.java:28: SQL database: specialties is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unresolved` src/main/java/org/springframework/samples/petclinic/owner/Visit.java:35: SQL database: visits is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)
- `unknown_attribute` src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java: Question: is TLS terminated in front of the HTTP listener of spring-petclinic? Inbound flows are marked encryption=unknown until answered.
- `unknown_attribute` src/main/java/org/springframework/samples/petclinic/owner/PetController.java:64: Question: what is the authentication and encryption of the link to SQL database: types?
- `unknown_attribute` src/main/java/org/springframework/samples/petclinic/owner/VisitController.java:109: Question: what is the authentication and encryption of the link to SQL database: owners?
- `unknown_attribute` src/main/java/org/springframework/samples/petclinic/vet/VetController.java:69: Question: what is the authentication and encryption of the link to SQL database: vets?
- `unknown_attribute` src/main/java/org/springframework/samples/petclinic/owner/Pet.java:44: Question: is SQL database: pets encrypted at rest? It holds pii.
- `unknown_attribute` src/main/java/org/springframework/samples/petclinic/owner/Owner.java:48: Question: is SQL database: owners encrypted at rest? It holds pii.
