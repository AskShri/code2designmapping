# STRIDE per element

Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. STRIDE letters: S Spoofing, T Tampering, R Repudiation, I Information disclosure, D Denial of service, E Elevation of privilege. Risk ratings are left to the team.

| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |
|---|---|---|---|---|---|---|
| POSTGRES_PASSWORD set in compose service 'postgres' | Weakness (high) | I E | - | - | spring-petclinic | CWE-798 Hard-coded or committed credentials at docker-compose.yml:19 |
| MYSQL_PASSWORD set in compose service 'mysql' | Weakness (high) | I E | - | - | spring-petclinic | CWE-798 Hard-coded or committed credentials at docker-compose.yml:10 |
| MYSQL_ALLOW_EMPTY_PASSWORD set in compose service 'mysql' | Weakness (high) | I E | - | - | spring-petclinic | CWE-798 Hard-coded or committed credentials at docker-compose.yml:8 |
| SQL database: pets | Data store | T R I D | pii | in no boundary | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| SQL database: owners | Data store | T R I D | pii | in no boundary | encryption at rest: unknown | holds sensitive data: confirm encryption at rest, access control and retention |
| SQL database: types -> PetController | Data flow | T I D | - | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /vets.html handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /owners/{ownerId}/pets/{petId}/visits/new handler -> SQL database: owners | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| SQL database: owners -> OwnerController | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| SQL database: vets -> VetController | Data flow | T I D | - | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /owners/{ownerId}/edit handler | Data flow | T I D | pii | repository: spring-petclinic | @Valid | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| SQL database: owners -> VisitController | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /oups handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /owners/{ownerId}/pets/new handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| POST /owners/{ownerId}/edit handler -> SQL database: owners | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /owners/{ownerId}/pets/new handler | Data flow | T I D | pii | repository: spring-petclinic | @Valid | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /owners/{ownerId}/pets/{petId}/edit handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> POST /owners/{ownerId}/pets/{petId}/visits/new handler | Data flow | T I D | pii | repository: spring-petclinic | @Valid | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| SQL database: owners -> PetController | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /owners/{ownerId}/pets/{petId}/edit handler | Data flow | T I D | pii | repository: spring-petclinic | @Valid | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /owners/find handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /owners/{ownerId}/edit handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /vets handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| SQL database: owners -> GET /owners/{ownerId} handler | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET / handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| PetController -> SQL database: owners | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| SQL database: types -> PetTypeFormatter | Data flow | T I D | - | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| POST /owners/new handler -> SQL database: owners | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> POST /owners/new handler | Data flow | T I D | pii | repository: spring-petclinic | @Valid | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /owners handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /owners/new handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client -> GET /owners/{ownerId} handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| SQL database: vets -> GET /vets handler | Data flow | T I D | - | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| POST /owners/{ownerId}/pets/new handler -> SQL database: owners | Data flow | T I D | pii | repository: spring-petclinic | none | authentication=unknown, encryption=unknown: question for the team |
| HTTP client -> GET /owners/{ownerId}/pets/{petId}/visits/new handler | Data flow | T I D | - | repository: spring-petclinic | none | inbound crossing without authentication; authentication=none, encryption=unknown: question for the team |
| HTTP client | External entity | S R | - | - | - | inbound caller: verify authentication on every entry point |
| SQL database: specialties | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQL database: vets | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQL database: visits | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| SQL database: types | Data store | T R I D | - | in no boundary | encryption at rest: unknown |  |
| GET /oups handler | Process | S T R I D E | - | - | none | entry point |
| GET /owners/{ownerId}/pets/{petId}/visits/new handler | Process | S T R I D E | - | - | none | entry point |
| GET /owners/{ownerId}/pets/new handler | Process | S T R I D E | - | - | none | entry point |
| GET /owners/new handler | Process | S T R I D E | - | - | none | entry point |
| GET /owners/{ownerId}/edit handler | Process | S T R I D E | - | - | none | entry point |
| VetController | Process | S T R I D E | - | - | n/a (internal) |  |
| GET / handler | Process | S T R I D E | - | - | none | entry point |
| VisitController | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /owners/new handler | Process | S T R I D E | - | - | @Valid | entry point |
| GET /owners/find handler | Process | S T R I D E | - | - | none | entry point |
| GET /owners/{ownerId}/pets/{petId}/edit handler | Process | S T R I D E | - | - | none | entry point |
| GET /vets handler | Process | S T R I D E | - | - | none | entry point |
| PetTypeFormatter | Process | S T R I D E | - | - | n/a (internal) |  |
| OwnerController | Process | S T R I D E | - | - | n/a (internal) |  |
| POST /owners/{ownerId}/edit handler | Process | S T R I D E | - | - | @Valid | entry point |
| GET /vets.html handler | Process | S T R I D E | - | - | none | entry point |
| POST /owners/{ownerId}/pets/{petId}/visits/new handler | Process | S T R I D E | - | - | @Valid | entry point |
| POST /owners/{ownerId}/pets/new handler | Process | S T R I D E | - | - | @Valid | entry point |
| POST /owners/{ownerId}/pets/{petId}/edit handler | Process | S T R I D E | - | - | @Valid | entry point |
| PetController | Process | S T R I D E | - | - | n/a (internal) |  |
| GET /owners/{ownerId} handler | Process | S T R I D E | - | - | none | entry point |
| GET /owners handler | Process | S T R I D E | - | - | none | entry point |
| no authentication control detected on GET /owners/{ownerId} | Weakness (info) | S E | - | - | ep:a4ljx6jlu2 | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:178 |
| no authentication control detected on GET /vets | Weakness (info) | S E | - | - | ep:7nnbiu2dom | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/vet/VetController.java:72 |
| no authentication control detected on GET /oups | Weakness (info) | S E | - | - | ep:qjddrrdu6q | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/system/CrashController.java:31 |
| no authentication control detected on POST /owners/{ownerId}/pets/{petId}/edit | Weakness (info) | S E | - | - | ep:xuu6gwnxqa | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/PetController.java:144 |
| no authentication control detected on GET /owners/{ownerId}/pets/{petId}/edit | Weakness (info) | S E | - | - | ep:3apiaamxjh | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/PetController.java:139 |
| no authentication control detected on GET /owners/{ownerId}/pets/new | Weakness (info) | S E | - | - | ep:nzixwt7m2i | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/PetController.java:100 |
| no authentication control detected on GET /owners/{ownerId}/pets/{petId}/visits/new | Weakness (info) | S E | - | - | ep:cxlegd7vr5 | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/VisitController.java:90 |
| no authentication control detected on GET /owners/new | Weakness (info) | S E | - | - | ep:odr7wxkgvg | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:72 |
| no authentication control detected on GET /owners/find | Weakness (info) | S E | - | - | ep:dlvpmbw2yx | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:89 |
| no authentication control detected on GET /owners | Weakness (info) | S E | - | - | ep:xl27ucp5tq | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:94 |
| no authentication control detected on POST /owners/{ownerId}/pets/{petId}/visits/new | Weakness (info) | S E | - | - | ep:ililw2cmzh | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/VisitController.java:97 |
| no authentication control detected on GET /vets.html | Weakness (info) | S E | - | - | ep:lyqhiqti3g | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/vet/VetController.java:45 |
| no authentication control detected on POST /owners/new | Weakness (info) | S E | - | - | ep:2rabe5cdxl | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:77 |
| no authentication control detected on POST /owners/{ownerId}/edit | Weakness (info) | S E | - | - | ep:cfbtagmsm4 | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:153 |
| no authentication control detected on GET / | Weakness (info) | S E | - | - | ep:wda5gm5qms | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/system/WelcomeController.java:25 |
| no authentication control detected on GET /owners/{ownerId}/edit | Weakness (info) | S E | - | - | ep:ywmzt6awdj | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java:148 |
| no authentication control detected on POST /owners/{ownerId}/pets/new | Weakness (info) | S E | - | - | ep:msfsvwu5kp | CWE-306 Entry point without a detected authentication control (review) at src/main/java/org/springframework/samples/petclinic/owner/PetController.java:107 |

## Data assets

| Data class | Processed by | Stored in | Leaves the system via |
|---|---|---|---|
| pii | VisitController, POST /owners/new handler, OwnerController, POST /owners/{ownerId}/edit handler, POST /owners/{ownerId}/pets/{petId}/visits/new handler, POST /owners/{ownerId}/pets/new handler, POST /owners/{ownerId}/pets/{petId}/edit handler, PetController (+1) | SQL database: pets, SQL database: owners | - |
