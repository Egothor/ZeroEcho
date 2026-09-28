# Outstanding work

This is the sole implementation plan. Completed milestones are not retained here;
current behavior is documented in the architecture, API and deployment references.

## Future proposals — not approved implementation scope

These are retained product ideas, not current release acceptance criteria or an undertaking to
match every feature of another PKI product. Each requires an owner scope decision
before design or implementation. The existing selection APIs already supply known
PKI identities to the frontend.

| Proposal | Decision/dependency | Acceptance to define if approved |
| --- | --- | --- |
| Advanced certificate search | Select required subject, SAN, serial and status filters; establish authorized data exposure and indexing/resource costs. | Bounded, authorized queries with explicit pagination and failure behavior. |
| Machine-readable operation parameter schema | Choose an API representation and frontend migration scope. | Server schema and decoder agree on types, required fields and constraints; frontend contract drift is tested. |
| Enrollment profiles | Define allowed issuers, certificate profiles, subject/SAN constraints and approval rules. | Issuance enforces the selected enrollment policy without weakening certificate-profile validation. |
| EST, SCEP or CMP | Select protocols and target deployments; do not assume all are required. | Protocol, authentication and authorization conformance for the selected listeners. |
| Recurring status generation | Choose documented external scheduling or an in-product scheduler. | Defined CRL/delta cadence, ownership and failure handling; no duplicate signing on retry. |
| Publisher endpoint administration | Decide whether endpoints remain deployment configuration or become managed data. | Authorized endpoint lifecycle and safe secret references; preserve publication semantics. |
| Content-aware profile reconciliation | Define explicit update/activation policy for changed profiles. | Unchanged content is a no-op; changed content creates and activates only the intended version. Current bootstrap deliberately skips known IDs. |
| Aggregate dashboard metrics | Define useful counts, authorization and computational bounds. | Realm-scoped summaries expose only authorized data and document freshness/cost. |

## Maintenance proposal — not approved implementation scope

The existing `pki` tasks `signingPerformanceBenchmark` and
`signingPerformanceAggregate` refer to absent entry-point classes. Decide whether
to remove those obsolete task registrations or supply a separately scoped benchmark.
Acceptance: every retained advertised task has a runnable entry point. Signing measurements
use their own current-runtime harness and do not rely on these tasks.
