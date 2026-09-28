# Selection API and validation contract

The frontend catalog contains 107 operations: 41 PKI operations, ten signing
operations and 56 server controls. New read operations extend the same admin
POST envelope, gateway authorization and audit path; no separate selection
service, persistent registry, index or server-held cursor is introduced.

| Operation | Scope / permission | Rows under `result` |
|---|---|---|
| `profile.list-all` | realm / `PROFILE_READ` | `profiles` |
| `request.list` | realm / `REQUEST_READ_ANY` | `requests` |
| `credential.search` | authority / `CERTIFICATE_SEARCH` | `credentials` |
| `issuer.generation.list` | authority / `AUTHORITY_READ` | `generations` |
| `configuration.choices` | realm / `SERVER_CONFIGURATION_READ` | `value` (see below) |
| `security.disclosure.capability.list` | resolved object / `DISCLOSURE_READ` | `value.items` |

New collection arguments are `{limit, after?}`; capability listing additionally
requires `objectId`. Authority-scoped operations take `authorityId` in the outer
envelope. Limits are 1–1000. `after` is an exclusive public identifier in ascending
lexical order. Responses include `count`, `truncated`, and `nextCursor` only when
another authorized row exists. The cursor is the last returned authorized ID.
Existing `ca.list`, `inventory.status`, `publication.list`, and
`algorithm.binding.list` accept the same optional `after` continuation.

Authorization filters candidates before page limiting. Credential and issuer
rows use persisted authority/issuer/profile coordinates; publication rows use
their persisted source. Capability listing resolves its object scope before
reading records and returns only `capabilityId`, `objectId`, `expiresAt`, `revoked`.
Bearer tokens, token commitments, private keys, DER/CSR bytes and provider options are
not part of selection projections.

`configuration.choices` returns `result.value` with `formats`, `signingProviders`,
`publicationTargets`, `algorithms`, `acmeChallengeProviders`, `acmeEabProviders`,
and `keys: {items, count, truncated, nextCursor?}`. Keys combine known local
private-key aliases, exact configured topology references and stored CA key
references. Arbitrary remote-only keys unknown to PKI cannot be inventoried by
the current provider SPI; explicit new external references remain authorable.
Publication choices identify actual runtime targets, not backend provider IDs.

Existing control lists retain `result.value.items`, `hasMore`, `nextOffset`;
role templates use `result.value`, audit search uses `result.value.events`.
Profile versions use `result.versions`, and issuer paths use `result.paths`.
The frontend keeps one result page and exposes continuation/refresh. Searches
scan successive authorized pages until matches are found; failures are visible.
Each page reads a fresh snapshot. Concurrent inserts before the current cursor
require returning to the first page; this is not a cross-request frozen snapshot.

## Resource behavior

Without a new index, persisted ID selections scan N candidates per page and
retain at most L+1 records: O(N log L) comparisons and O(L) retained records,
plus one decoded candidate and existing cursor state. Authorization can add
O(N·G) grant checks; decoding and existing integrity validation add payload I/O.
Walking every page can therefore visit O(N²/L) candidates. These are bounded-memory
administration reads, not an indexed search latency claim.

Known-key union costs O(K log L) comparisons and O(L) selected identifiers, plus
the existing local alias snapshot (bounded by the keyring's 16,384-entry maximum).
Capability selection scans its namespace under the existing control-store
monitor; concurrent control operations may wait. Cancellation is cooperative
between candidates and cannot interrupt every individual filesystem read.
Frontend polling retains only the last receipt and performs one request at a time.

## Verification

Targeted Java regressions cover 1,005-request traversal, lexical cursors,
authorization before limiting, profile/issuer denial, cancellation, safe
configuration and capability projections, local key references, and strict HTTP
decoding. Frontend tests cover asynchronous signing receipts, explicit approval classification,
selection pagination/errors, parent invalidation, exact wire identities, and
profile-derived policy. Demo browser tests use the same response nesting.

Live backend and packaged nginx/mTLS browser checks are separate from the
in-browser demo suite. The [packaged deployment gate](../e2e/packaged/README.md)
verifies certificate forwarding and authorization over the deployed topology.
Current test totals, toolchain details and completed PMD/Javadoc checks are
recorded in the [validation evidence](../../docs/pki-validation.md).
