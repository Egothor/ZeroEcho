# ZeroEcho administrative HTTPS server

The `pki-server` distribution exposes the transport-neutral realm gateway through mutual TLS. One process opens one realm and one long-lived PKI session; all administrative execution uses the existing typed operation catalog and `ServerOperationGateway`.

## Starting the server

```text
zeroecho-pki-server --validate-config --config server-config.json
zeroecho-pki-server --config server-config.json
```

Use `--help` and `--version` for launcher information. Validation parses the strict versioned JSON and checks finite security bounds without opening a listener, realm, store, provider, or audit sink.

The direct examples are [pki-server-loopback-example.json](pki-server-loopback-example.json) and [pki-server-production-example.json](pki-server-production-example.json). Trusted-proxy examples are [pki-server-trusted-proxy-rfc9440-example.json](pki-server-trusted-proxy-rfc9440-example.json) and [pki-server-trusted-proxy-nginx-example.json](pki-server-trusted-proxy-nginx-example.json). They contain no credentials or key material. Replace every illustrative commitment and identity with provisioned values before use. Mapped principals must already exist in the durable server-control store and have explicit scoped grants; a certificate mapping establishes identity only and never grants authority.

## TLS and authentication modes

Administrative access has no anonymous mode. Schema version 2 requires exactly one explicit mode: `DIRECT_MTLS` or `TRUSTED_REVERSE_PROXY`. The listener always requires a client certificate in either mode. Schema version 1 is rejected; there is no inferred direct-mode compatibility decoder.

In `DIRECT_MTLS`, the TLS peer is the end-client principal. Forwarded certificate headers are rejected. The built-in `jsse-pkcs12` TLS provider reads server identity and direct administrative-client trust stores from configured files, while passwords are resolved exclusively from named environment variables.

In `TRUSTED_REVERSE_PROXY`, the TLS peer is a dedicated `SERVICE` transport principal. Its only enabled allowing authority must be `FORWARD_AUTHENTICATED_CLIENT_IDENTITY`, explicitly scoped to the realm. ZeroEcho first validates backend mutual TLS and that permission, then independently parses and validates the forwarded external client certificate against `administrativeClientTrust`. Authorization, approvals, break-glass ownership and PII auditing use only the mapped end-client principal. Neither identity inherits the other identity's permissions.

The preferred forwarding representation is RFC 9440 `Client-Cert` plus optional `Client-Cert-Chain`. The compatibility representation `NGINX_ESCAPED_PEM_V1` accepts one explicitly named header containing only the URL-escaped, canonical single-certificate PEM emitted by `$ssl_client_escaped_cert`. Formats are never auto-detected. Duplicate leaf or chain headers, mixed representations, malformed escapes, raw PEM, non-canonical Base64, concatenated objects and oversized values fail closed.

Client certificates map to persisted principals through an exact SHA-256 certificate, canonical SPKI, or issuer-and-positive-serial commitment. Proxy and forwarded-client mappings additionally require an exact certificate or SPKI commitment and cannot overlap. Subject and SAN strings, source addresses, `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, PROXY protocol data and certificate-header possession are not trust identities. An absent, ambiguous, expired, malformed, untrusted, wrong-usage, unauthorized or disabled mapping fails before typed operation decoding.

Direct mode obtains proof of possession from ZeroEcho's TLS handshake. Proxy mode relies on the mutually authenticated and narrowly authorized proxy's attestation that external mutual-TLS proof of possession succeeded. Independently parsing and validating the forwarded certificate does not itself prove possession.

Provider exceptions, aliases, references, certificate subjects, SANs, fingerprints, forwarded header values and paths are not returned to clients or written to request audit details. Safe audit records the authentication mode and keeps the transport and end-client principal identities separate.

## Trusted NGINX topology

The secure topology is:

```text
administrator --mTLS--> NGINX --mTLS--> ZeroEcho
```

RFC 9440 is preferred where the proxy can emit it. For the explicit NGINX compatibility mode, the essential NGINX policy is conceptually:

```nginx
server {
    listen 443 ssl;
    ssl_verify_client on;
    ssl_client_certificate /external/reference/admin-client-trust.pem;

    location /admin/ {
        proxy_set_header Client-Cert "";
        proxy_set_header Client-Cert-Chain "";
        proxy_set_header X-ZeroEcho-Client-Cert "";
        proxy_set_header X-ZeroEcho-Client-Cert $ssl_client_escaped_cert;

        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /external/reference/backend-server-trust.pem;
        proxy_ssl_certificate /external/reference/proxy-client-certificate.pem;
        proxy_ssl_certificate_key /external/reference/proxy-client-key.pem;
        proxy_pass https://zeroecho_backend;
    }
}
```

The paths and upstream name above are placeholders, not deployment values. The proxy must remove or replace all inbound forwarded-certificate headers, verify the external client certificate, and use a dedicated backend client certificate mapped to the narrowly authorized proxy principal. `proxy_pass` must remain HTTPS. `X-Forwarded-For` and the client source address are never authorization evidence. Separate mapping sets identify the proxy transport principal and forwarded end clients.


## API

The listener exposes only:

```text
GET  /health/live
GET  /health/ready
GET  /admin/v1/realm
GET  /admin/v1/operations
GET  /admin/v1/operations/{operationId}
GET  /admin/v1/signing-operations/{privatePkiId}
POST /admin/v1/operations/{operationId}
```

No ACME or public certificate repository routes are registered on the administrative listener. Optional ACME and public repository listeners are independently configured and bounded; see [pki-server-acme.md](pki-server-acme.md) and [pki-server-public-repository.md](pki-server-public-repository.md). Administrative POST bodies are strict UTF-8 JSON containing version, optional authority and approval identities, an optional shortening deadline, and the closed argument object for one typed operation. Batch execution, file paths, raw DER, polymorphic class metadata, unknown keys, duplicate keys, and trailing JSON are rejected.

Responses are deterministic version-one JSON. They carry only safe typed results
or stable failure codes. A signing-backed operation that has yielded returns
HTTP 202 with a `Location` under the authenticated
`/admin/v1/signing-operations/{privatePkiId}` route. That route reports the
explicit `SUCCEEDED`, `PENDING`, or `FAILED` application outcome without exposing
the signed payload. The private `PkiId` is never a bearer capability: every
lookup applies current RBAC to the exact original action and authority,
issuer/profile, certificate, or status resource reconstructed from the durable
domain continuation. Any currently authorized administrator may inspect it;
denied, cross-realm, leaked, and absent identifiers all return the same 404.
Status responses are `no-store` and carry `Referrer-Policy: no-referrer`.
`RECOVERY_REQUIRED` and `EXTERNAL_OUTCOME_UNKNOWN` remain
distinct; deadlines never claim rollback and never trigger automatic retry.

### Pending credential-confirmation review

`credential.confirmation.pending.list` is the read-only administrative review
operation for credentials whose persisted confirmation lifecycle is still
`PENDING`. It requires `CERTIFICATE_SEARCH` on a `CERTIFICATE` resource with an
exact mandatory `authorityId`; `profileId` is an optional narrower scope. The
operation uses `METADATA_REDACTED`, never requires approval, and is authorized
and audited by the ordinary `ServerOperationGateway` path.

```json
{
  "version": 1,
  "authorityId": "ca:internal",
  "arguments": {
    "profileId": "server-tls",
    "cutoffInclusive": "2026-08-30T12:00:00Z",
    "limit": 100
  }
}
```

Results are ordered by `confirmationReviewAt` and then the canonical credential
identity. Each item contains only `credentialId`, `authorityId`, `profileId`,
`confirmationReviewAt`, and `initialDisclosurePolicy`. The result never exposes
certificate DER, public keys, requester or owner identity, proof suites,
commitments, challenges, nonces, presentations, or proof responses. A page may
include an opaque `nextCursor`; it is bounded and valid only for the same store,
cutoff, authority, and optional profile. The administrative transport accepts
1 through 1000 items per page; the underlying application/store contract is
bounded at 4096. A page can contain zero items and still carry `nextCursor`;
clients must continue exclusively while the cursor is present and must not use
item count as an end condition.

The store maintains separate derived authority and authority-profile review
projections so an authorized page never scans and subsequently filters another
scope. Both projections are created atomically with a new pending lifecycle and
removed atomically when confirmation succeeds. A review is actionable only
while the lifecycle is `PENDING` and the credential has no revocation history.
Authoritative revocation therefore suppresses a stale projection immediately;
startup omits or deletes revoked projections while rebuilding from the lifecycle
and immutable issued credential. Each list call examines at most `limit`
projection entries and opportunistically repairs at most ten distinct
permanently-revoked credentials (at most thirty exact-revision deletes covering
both review projections and the proof challenge). Repair occurs after the read
snapshot closes; a concurrent revision conflict is benign, while an uncertain
or failed durable commit fails the read safely. The cursor advances from the
last examined projection, including an anchor deleted by repair, so empty
continuation pages make bounded progress. Non-permanent history is suppressed
but not repaired, and malformed derived state fails closed. No worker, queue,
cache, resident workflow object, or additional lifecycle state is introduced.

### Overdue pending-confirmation revocation

`credential.confirmation.pending.revoke` is the transport-neutral conditional
mutation for one non-public credential returned by the review workflow. Its
strict arguments contain only `credentialId` and an optional operator
justification of at most 1024 characters. The standard outer `authorityId` is
mandatory. A client cannot supply a cutoff, clock value, lifecycle or CAS field,
profile, owner, issuer, responder, or revocation reason.

```json
{
  "version": 1,
  "authorityId": "ca:internal",
  "arguments": {
    "credentialId": "x509:0123456789abcdef",
    "justification": "ticket-200"
  }
}
```

Before RBAC, the gateway performs one authoritative credential-scope lookup and
reconstructs the exact realm, authority, frozen profile, and credential object.
Authorization requires `CERTIFICATE_REVOKE` on that `CERTIFICATE` scope with
relationship `ANY` and `METADATA_REDACTED`. `CERTIFICATE_SEARCH`, required by
the separate list operation, does not authorize this mutation. An existing
grant may require the ordinary durable approval flow; execution after approval
re-evaluates all lifecycle and time conditions rather than trusting the earlier
list result.

Under the exact credential lock, the store requires an existing credential, a
still-`PENDING` non-public lifecycle, no permanent revocation, and its own
authoritative time to be strictly after `confirmationReviewAt`. Equality remains
timely and is rejected. The operation always records the permanent PKIX reason
`UNSPECIFIED`; the specialized operation identity and committed justification
retain the more precise administrative meaning without publishing an unsupported
claim about key compromise or affiliation.

The authoritative revocation log is committed first. Derived authority/profile
review projections and any outstanding proof challenge are then removed. A
cleanup interruption returns `RECOVERY_REQUIRED`; it never claims rollback,
returns the credential to the actionable list, or permits later proof completion.
An exact evidence-bound retry completes cleanup, and startup independently omits
and deletes stale derived state from the authoritative revocation history. The
confirmation lifecycle remains historically `PENDING`; revocation history owns
the terminal credential status. Certificate storage and download retention are
unchanged, and existing OCSP, CRL, and status paths consume the same revocation
authority.

The operation commitment binds the specialized operation name, exact credential,
fixed `UNSPECIFIED` reason, exact resource scope, and the optional justification
commitment. Plaintext justification and confirmation proof material do not enter
revocation evidence, audit, or diagnostics. One mutation performs a constant
number of `O(log M)` point operations plus one bounded revocation append/fsync and
bounded derived-metadata cleanup, using `O(1)` auxiliary memory. It adds no scan,
index, worker, retry loop, queue, cache, handle, or new lifecycle state.

### Credential-confirmation proof challenge issuance

`credential.confirmation.challenge.issue` is the authenticated administrative
operation that issues or replays the proof challenge for one persisted
`PENDING` lifecycle. The strict argument object contains only `credentialId`;
the standard outer `authorityId` is mandatory. Before RBAC, the gateway loads
the committed credential and reconstructs its exact realm, issuer authority,
frozen end-entity profile, and credential object identity. A missing credential
or an outer-authority mismatch is denied without backend execution or existence
disclosure. Authorization uses relationship `ANY`, `METADATA_REDACTED`, and the
existing `CERTIFICATE_PUBLICATION_CHANGE` action on `CERTIFICATE`; the operation
is mutating, Admin-only, and approval-free.

```json
{
  "version": 1,
  "authorityId": "ca:internal",
  "arguments": {
    "credentialId": "x509:0123456789abcdef"
  }
}
```

After authorization, the executor loads the authoritative lifecycle and builds
the internal challenge request from its current revision and record commitment.
The existing confirmation service owns live replay, concurrent convergence,
expired replacement, frozen audience and suite settings, provider selection,
and store mutation. The response contains exactly `credentialId`, the expected
lifecycle revision and lifecycle/challenge commitments, proof-suite ID and
configuration commitment, RSA maximum modulus bits, expiry, maximum response
bytes, and the canonical unpadded Base64url presentation. It never returns DER,
keys, nonce, audience, suite payload, owner/requester data, challenge internals,
or proof data. Administrative responses retain the listener's existing
`no-store` behavior.

After authorization, issuance uses `O(D + K + T)` CPU, bounded
credential-content I/O, and a constant number of `O(log M)` metadata point
operations. `D` is bounded certificate DER (at most 1 MiB), `K` is public-key
processing, `T` is bounded suite-presentation work (at most 2048 bytes before
Base64url), and per-request memory is bounded by those inputs. Whole-request
cost additionally includes the existing grant/role scans and audit/transport
I/O. No handle, worker, queue, cache, registry, thread, or request state is
retained.

### Credential-confirmation proof completion

`credential.confirmation.proof.complete` is the authenticated administrative
adapter over the shared credential-confirmation proof service. Its strict
argument object contains exactly the credential identity, both lifecycle CAS
coordinates, and one canonical unpadded Base64url response. The standard outer
`authorityId` is mandatory. The gateway reconstructs the exact committed
authority, frozen profile, and credential object scope before RBAC, performs
exactly one credential-scope lookup, and denies missing or mismatched scope
without proof-service execution or existence disclosure.

```json
{
  "version": 1,
  "authorityId": "ca:internal",
  "arguments": {
    "credentialId": "x509:0123456789abcdef",
    "expectedLifecycleRevision": 1,
    "expectedLifecycleRecordCommitment": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "expectedChallengeRecordCommitment": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "response": "canonical-unpadded-base64url"
  }
}
```

Authorization requires `CERTIFICATE_CONFIRM` on the exact `CERTIFICATE`
authority/profile/object scope with relationship `ANY` and
`METADATA_REDACTED`; the operation is mutating, Admin-only, and approval-free.
The built-in requester role receives this action with relationship `ANY`
because possession is proven cryptographically rather than inferred from a
persisted requester or owner. Authentication, scoped RBAC, and valid proof of
possession must all succeed.

The response decodes to 1 through 16384 bytes. Empty, padded, whitespace,
standard-Base64, non-round-tripping, and oversized encodings are rejected. The
maximum canonical unpadded Base64url representation is therefore 21846
characters. The configurable Admin `maximumBodyBytes` must be at least 25230:
this is the exact compact request framing plus worst-case JSON escaping of the
bounded authority and credential identifiers, two commitments, and the maximum
response. Startup rejects a smaller value; the existing upper bound remains in
force and public/ACME listener limits are independent.

The executor delegates exactly once to the shared proof service and returns
only `confirmationResult`, with value `CONFIRMED` or `REJECTED`. A rejected
proof is a successful operation with no confirmation mutation. An exact
terminal replay returns `CONFIRMED` without re-running provider verification.
Operation commitments bind both CAS coordinates and a SHA-256 digest of the
response; raw proof bytes never enter operation text, audit, or diagnostics.
Responses retain the listener's existing `no-store` behavior.

For a pending lifecycle, post-authorization work uses
`O(D + T + R + V(K))` CPU and a constant number of `O(log M)` metadata point
operations. Exact terminal replay uses `O(R + log M)` and performs no provider,
DER, or cryptographic verification work. `D` is bounded credential content (at
most 1 MiB), `T` is the bounded challenge presentation (at most 2 KiB), `R` is
the proof response (at most 16 KiB), and `V(K)` is the suite verification cost
for the credential public key. Per-request memory is bounded by those inputs;
whole-request work additionally includes existing grant/role scans and
audit/transport I/O. No state, worker, queue, cache, handle, or retry mechanism
is added.

## Capacity and shutdown

Transport workers, transport backlog, concurrent operation workers, waiting operation capacity, admitted requests, request body size, deadlines, and both shutdown periods are finite configuration values. Saturation never runs a request on the caller thread and a rejected request never invokes the gateway.

Configuration schema version 7 is the only accepted server schema. Every realm
has a mandatory `confirmationProof` object. Its `audience` is a public,
non-secret deployment or cluster identifier expressed as an exact lowercase
UUID-v4 URN. Operators provision the same audience mapping into participating
clients and keep it unique across independently administered deployments. The
value is never accepted from a request or generated at startup. Omitting
`challengeTtlMillis` or `rsaMaximumModulusBits` selects decoder defaults of five
minutes and 8192 bits. Rotating proof policy applies only to confirmation
lifecycles without a persisted challenge. Any existing challenge, including an
expired challenge replacement, retains its frozen audience and settings.

The mandatory `auditProjection` object configures the audit worker with production
values of 256 examined records, 64 sink calls, and a 2-second idle interval.
`maxRecords` is 1 through 4096, `maxSinkCalls` is 1 through the record bound,
and `idleIntervalMillis` is positive and at most five minutes. Revocation and
each evidence-family projector receive independent budgets. The former
`signingReconciliation` object, enable flag, and signing timeouts are rejected;
there is no compatibility adapter in this prerelease schema replacement.
Signing dispatch belongs to the PKI reactor, not this worker.

Shutdown first removes readiness and admission, stops listener acceptance, drains for the configured graceful period, cooperatively cancels remaining work, waits only for the forced period, then closes the one realm context. Already committed PKI changes remain committed.

An audit projection or synchronous sink call that remains live after forced
shutdown causes `AUDIT_PROJECTION_SHUTDOWN_TIMEOUT`; realm dependencies stay open
and `close` may be retried after the call returns. The same dependency-preserving
rule applies during partial startup cleanup. Projection cancellation is
cooperative and does not forcibly terminate a blocking sink call.

## Request correlation

Clients may supply `X-ZeroEcho-Request-Id` using 16–128 ASCII letters, digits, underscore, or hyphen. Otherwise the server creates a random opaque identifier. It is correlation metadata—not an idempotency key, object identity, approval, or capability token.

## Security-control administration

The operation catalog is the single administrative namespace for both existing
PKI operations and closed `SERVER_CONTROL_OPERATION` requests. Subject to scoped
authorization, it exposes principal lifecycle, immutable role-template
inspection, scoped assignments and grants, approval decisions, break-glass
lifecycle, disclosure policy, and auditor projections. Lists are explicitly
paged; revocation disables a control record without erasing its history.

High-risk changes use a separately created approval request committed to the
exact typed target operation and scope. An approval decision never executes the
target. The later ordinary operation request supplies the approval ID and the
gateway claims and completes it exactly once.

Approval inspection, decisions and cancellation resolve the complete authorization
scope from the persisted approval ID, including any profile or issuer coordinates.
Clients need not reconstruct that scope. Any supplied authority must match the
stored record; typed callers' other supplied scope coordinates must also match.
Authorization still evaluates the complete stored scope, and requester separation,
cancellation ownership and exact target binding remain enforced. No additional
HTTP fields are required for profile-scoped approvals.

`security.disclosure.capability.issue` is the only one-time-sensitive response.
The durable store receives the token commitment before the raw 256-bit token is
returned. Its HTTPS response additionally carries `Cache-Control: no-store`,
`Pragma: no-cache`, and `Referrer-Policy: no-referrer`. The token is absent from
catalogs, inspection results and audit details. A response-write failure is
classified as delivery-unknown; the server neither regenerates nor retries the
token automatically.
