# Codexploit v1 machine-readable contracts

Maturity: layered design baseline with implemented adapters for sources, artifacts,
pinned knowledge views, the builtin plugin host, and the first deployment-installed
process scanner. See the implementation map in the layered specification;
container/remote worker transports remain planned.

See [the layered interface specification](../../docs/design/interfaces/v1/README.md).
Schemas use JSON Schema 2020-12. All schema IDs live under the reserved offline
namespace `https://codexploit.invalid/contracts/v1/`; resolve them from this
folder, never through network retrieval.

`examples.json` maps each complete synthetic fixture to its schema. Example
hashes are synthetic, and credential references are identifiers, not credentials.
Shape validation does not establish authorization, graph referential integrity,
DAG acyclicity, verdict eligibility, or database atomicity; those semantic rules
are specified per layer and require adapter conformance tests.

Run `make check-contracts`. The prototype imports these same schemas for its
interface browser and contract export. Versioned objects reject unknown fields.

`plugin-runtime.schema.json` validates the formal catalog and invocation responses;
manifests still use `plugin.schema.json`. Records now distinguish `installed` from
`executable`. This does not authorize execution of audited source code: the
process scanner parses a frozen source tar without building or running it.

`scanner-alerts.schema.json` is the native report of the fixed
`codexploit.static-patterns@1.0.0` process scanner. It carries alert locations,
coverage and limitations only; `discovery.schema.json` is the normalized result
the host publishes after verifying Scope, producer and artifact digests.

`discovery.schema.json` defines normalized semantic facts and path observations.
Candidates have an immutable `candidate` status and an optional high/medium/low
severity hint. Invocation `analysis` follows `analysis.schema.json`; observed
call reachability does not establish taint flow or a vulnerability verdict.
