# Java sink catalogue

The Joern plugin ships `java-sink-catalog@1.0.0` in
[`java-sinks.json`](../plugins/joern/java-sinks.json). It is versioned,
digest-bound data rather than Java-specific regular expressions embedded in
Go or Scala.

## Why inventory and flows are separate

The semantic operation performs two independent jobs:

1. match the catalogue against every saved Java CPG and retain every matched
   sink, including sinks for which no data flow is found;
2. query data flow for the configured sources and the high-risk catalogue
   partitions, retaining every returned native trace.

The inventory is not reconstructed from `reachableByFlows`. A zero-flow sink
therefore remains searchable and reviewable. A sink match is still only a rule
observation: it does not establish source control, a dangerous argument value,
an ineffective control or exploitability.

## Catalogue contract

Each entry contains:

- a stable `id` and a security `category`;
- an exact `receiver_type` and `method`, with `match_type=exact` preferred;
- zero-based `dangerous_arguments` positions, translated to Joern's one-based
  argument selector only inside the adapter;
- a bounded `priority` for review ordering;
- an `evidence` level and explicit `limitations`.

The first version covers command execution, deserialization, SpEL / script /
OGNL expression injection, JNDI, JDBC / MyBatis / Hibernate SQL and HQL, XXE,
server-side HTTP, file read/write, LDAP and Freemarker / Thymeleaf template
execution. Exact receiver and method matching is required; regex matching
exists only for compatibility entries. Unknown fields, duplicate IDs, invalid
argument indexes, unsupported categories and changed catalogue semantics fail
closed. A MyBatis call-site match does not prove that a mapper contains
attacker-controlled `${}` interpolation; the mapper definition remains source
evidence to inspect.

The semantic report records the catalogue ID, version, canonical SHA-256,
entry count, matched sink ID, CPG artifact ID, receiver / method signature,
dangerous argument indexes, priority and limitations. The standard security
facts retain those fields in the ASG node detail and in the rule-set metadata.

## Scheduling

For each CPG, high-risk catalogue flows receive up to 80% of `max_flows`; the
remaining budget goes to configured fallback rules. Catalogue categories are
ordered by their highest entry priority, and unused share rolls forward instead
of being assigned permanently to the first category. `max_flows` is therefore a
per-CPG partition budget: one language cannot spend the budget required by a
later language.

The native `flows` artifact contains a partition ledger with one row per
catalogue category and fallback rule. Each row fixes the CPG, rule IDs,
priority, candidate count, flow budget, returned count and status (`complete`,
`truncated` or `pending`). The artifact is stored through the normal
content-addressed and PostgreSQL-bound invocation output path, so it survives
restart and remains readable with historical catalogues. Joern has no
mid-query cursor; an incomplete partition is rerun deterministically from its
fixed CPG, source selectors and rule IDs, and native identities prevent old
evidence from changing. Pending and truncated rows always produce PARTIAL
coverage; they are never interpreted as a safe result.

`GET /api/v1/projects/{project}/knowledge/views/{view}/sinks` exposes the
view-pinned catalogue. It accepts `category`, `partition=high_risk|unclassified`,
`rule_id`, `receiver_type`, `has_flow`, `file`, `generator`, `limit` and
`offset`. Catalogue rows sort by catalogue priority and stable label / node ID.
The formal attack-surface page opens the high-risk partition and keeps an
explicit unclassified exploration switch.

## Review ordering

The paths operation places the sink priority hint on each real data-flow
candidate. The enhancement version `joern.static-support/v2` adds half of that
hint to the static-support score and records `catalog_priority` in the selection
features and reasons. This changes review order only. It does not change
severity, a validation verdict or a finding's confirmed state.

## Validation

The normal tests validate catalogue structure, canonical digests, zero-flow sink
retention and sink identity reuse between inventory and flow.

An opt-in test runs the real sealed Joern package in a container:

```sh
JOERN_TEST_DOCKER_CONTAINER=<container> \
JOERN_TEST_DOCKER_SOURCE_PACKAGE=/app/plugin-packages/codexploit.joern@<version> \
go test ./cmd/joern-adapter \
  -run TestRealDockerJoernCatalogsJavaSinksAndPartitionsFlows -v
```

The Java fixture covers `Runtime.exec`, `ObjectInputStream.readObject`,
`XMLDecoder.readObject`, SpEL, MyBatis, Hibernate HQL, `InitialContext.lookup`,
`Context.lookup`, `DocumentBuilder.parse`, Freemarker, Thymeleaf and a
prepared-statement negative control. The test asserts zero-flow inventory,
category and fallback partition records, real high-risk flows, priority
projection and catalogue digest propagation.

## Next versions

- Add framework-specific source/sink wrappers and parse mapper XML with an
  explicit Java semantic model rather than treating a MyBatis call as proof of
  `${}` interpolation.
- Benchmark recall, incidental discoveries, false positives and query cost on
  a Java vulnerable-safe corpus.
