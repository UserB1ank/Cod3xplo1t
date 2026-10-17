# Codexploit v1 machine-readable contracts

Maturity: design baseline / interactive prototype, not a production transport implementation.

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
