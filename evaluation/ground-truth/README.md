# Ground truth

Hand-written from reading each sample's source. Vocabulary:

* `entry_points`: `METHOD /path` (route parameters normalized to `:param`), or `grpc Name` for gRPC services. Infrastructure entry points (health, preflight, docs) are listed under `infrastructure` and scored separately.
* `stores`: `technology:logical` with the logical name lower-cased, or `technology:*` when any store of that technology counts.
* `entities`: a distinctive substring of the external entity's name (case-insensitive).
* `edges`: `[entry point, target]` reachability edges: the handler of that entry point reaches the target (a store, an entity, or `svc:<service>` for another service in the same repository) directly or through calls. This is the question a threat model asks ("does this route reach the users table?"), so it is what is scored, rather than the module-level flow layout.

Scoring (scripts/evaluate.py): precision = matched predictions / predictions, recall = matched truths / truths, per collection. A prediction matches a truth when both ends match under the rules above.
