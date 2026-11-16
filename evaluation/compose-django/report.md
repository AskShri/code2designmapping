# code2design report: compose-django

Commit `30f4b7f6a6c3`, code2design 0.5.2, IR 0.2.

## Coverage

| Language | Files parsed |
|---|---|
| python | 5 |
| (test files, not modelled) | 0 |

Detectors: config@0.5, py@0.5, synth@0.5.2

Facts: boundary_hint 2, config_value 1, dependencies 1, router 1

## Model

| Collection | Count |
|---|---|
| processes | 3 |
| entities | 0 |
| stores | 0 |
| boundaries | 2 |
| flows | 0 |
| entry_points | 0 |
| controls | 0 |
| weaknesses | 0 |
| schemas | 0 |
| assets | 1 |
| threat_agents | 1 |
| gaps | 0 |

## Attack surface

Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.

- **exit points carrying sensitive data**: none detected
- **third-party dependencies**: 2 declared in app/requirements.txt; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface

### Entry points

| Entry point | Exposure | Controls (registration order) | Reaches |
|---|---|---|---|

### Weaknesses

None detected.

### External entities

| Entity | Kind | Host |
|---|---|---|

### Data stores

| Store | Technology | Data classes | Encryption at rest | Boundary |
|---|---|---|---|---|

## Lint

No findings.

## Inferred elements (dashed in diagrams)

- repository: compose-django (confidence 0.5): no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary
- Insider with access to container: web (confidence 0.8): one insider agent per trust boundary, placed inside it

## Gaps and questions

