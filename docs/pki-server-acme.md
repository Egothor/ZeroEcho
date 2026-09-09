# ACME automated certificate management

ZeroEcho exposes ACME on an optional listener that is independent of the administrative and public-repository listeners. All three listeners share one realm and one long-lived `PkiSession`, but they have separate routes, workers, queues, and admission limits. The ACME listener serves only `/acme/{directoryAlias}/...`; it never exposes `/admin/v1` or `/public/v1`.

An ACME directory is an immutable policy revision bound to one realm, logical authority, active end-entity profile, explicit current issuer generation, and explicit issuance chain path. It also freezes DNS namespaces, key and X.509 binding policy, validity, challenge providers, EAB policy, and an exact copy of the profile-owned credential-confirmation policy with its commitment. Directory registration never accepts a separate disclosure or confirmation policy. A client cannot select another authority, profile, issuer, path, binding, or disclosure state in an order.

## Listener and topology

Direct deployments use server-authenticated TLS. A client TLS certificate is not ACME account authority; ACME identity is the account key authenticated by JWS. Trusted-reverse-proxy deployments require the established mutually authenticated proxy-to-ZeroEcho TLS hop and a dedicated enabled proxy principal with `FORWARD_AUTHENTICATED_CLIENT_IDENTITY`. Forwarded administrative identity is not used as an ACME account. Source addresses and `Forwarded` or `X-Forwarded-*` headers never authorize ACME.

The server configuration schema is version 7. ACME is disabled explicitly with:

```json
"acmeListener": {"enabled": false}
```

An enabled direct listener uses the following safe structural example (provider properties are deployment references, never embedded secrets):

```json
{
  "enabled": true,
  "listenerId": "acme-internal",
  "address": "127.0.0.1",
  "port": 8445,
  "tlsProvider": {"id": "jsse-pkcs12", "properties": {"keyStore": "tls/acme.p12", "keyStorePasswordEnvironment": "ZEROECHO_ACME_TLS_PASSWORD"}},
  "transportMode": "DIRECT_TLS",
  "externalBaseUri": "https://acme.example.invalid",
  "maximumHeaderBytes": 32768,
  "maximumBodyBytes": 1048576,
  "execution": {"transportWorkers": 4, "transportQueueCapacity": 32, "operationWorkers": 4, "operationQueueCapacity": 32, "maximumAdmittedRequests": 32, "defaultDeadlineMillis": 30000, "maximumDeadlineMillis": 120000, "gracefulShutdownMillis": 30000, "forcedShutdownMillis": 10000},
  "validationExecution": {"transportWorkers": 2, "transportQueueCapacity": 8, "operationWorkers": 2, "operationQueueCapacity": 8, "maximumAdmittedRequests": 8, "defaultDeadlineMillis": 30000, "maximumDeadlineMillis": 120000, "gracefulShutdownMillis": 30000, "forcedShutdownMillis": 10000},
  "nonceLifetimeMillis": 300000,
  "maximumOutstandingNonces": 4096,
  "maximumAccountsPresented": 100,
  "maximumOrdersPresented": 100,
  "admissionWindowMillis": 60000,
  "maximumNewAccountsPerWindow": 100,
  "maximumNewOrdersPerAccountWindow": 100,
  "maximumPendingOrdersPerAccount": 50,
  "maximumChallengeValidationsPerAccountWindow": 100,
  "maximumConcurrentFinalizations": 4,
  "challengeProviders": [],
  "eabProviders": []
}
```

Trusted-proxy mode changes `transportMode` to `TRUSTED_REVERSE_PROXY` and additionally configures exact cryptographic proxy-certificate mappings plus the matching `trustedProxyPrincipalIds`. The TLS provider must require and validate the proxy certificate. There is no plaintext proxy mode.

## Directory examples

Directory registration is performed through the unified administrative operation catalog, followed by an approved `acme.directory.activate` when configured policy requires approval. Before approval canonicalization, the server resolves and binds the exact active profile reference and its confirmation-policy commitment. These are authoritative comparison preconditions, not request fields; activation or policy drift before execution invalidates the approval instead of silently changing the directory.

- An internal DNS directory restricts `dnsNamespaces` to the enterprise suffix, enables only `DNS_01`, and configures `zeroecho.dns-01.jndi.v1` with an explicit numeric DNS provider URL.
- A public HTTP directory enables `HTTP_01` through `zeroecho.http-01.v1`; private and internal validation targets remain rejected unless the directory provider configuration explicitly permits them.
- A wildcard directory enables `DNS_01`; wildcard identifiers cannot use HTTP-01.
- An EAB-required enterprise directory sets `eabRequired` and selects one explicitly enabled EAB provider. EAB secrets remain inside the provider boundary and are never persisted in ACME records.
- A trusted-proxy directory uses the same directory policy as a direct deployment; only listener transport composition differs.

## Protocol and validation

Replay nonces contain 256 bits of randomness, are listener/directory bound, one-time, finite-lived, and process-local. JWS accepts only flattened, canonical, unpadded Base64url ES256 with exact URL binding and exactly one of `jwk` or `kid`. The effective external URL comes from configuration, not an untrusted host or forwarding header.

HTTP-01 probes the canonical challenge URL on port 80, pins policy-validated resolution results, bounds response bytes and deadlines, and never forwards credentials. The optional `targetPort` provider setting exists only for explicitly private test or internal validation environments: a nonstandard port is rejected unless `allowPrivate` is also explicitly enabled. Production Internet-facing directories should omit `targetPort` and therefore use port 80. DNS-01 uses absolute `_acme-challenge` queries, exact TXT digest matching, explicit DNS resolver configuration, and bounded optional CNAME delegation. Challenge success becomes authoritative only after provider-produced evidence is durably bound to the exact authorization. There is no administrative force-valid operation.

## Issuance, chains, disclosure, and revocation

Finalization requires every authorization to be valid and unexpired, strict
canonical CSR/PoP validation, and exact equality between canonical CSR
identifiers and order identifiers. Issuance uses the directory's frozen
authority/profile policy plus the authority's explicit current issuer and
explicit issuance chain path. A durable issuance intent prevents duplicate
certificate creation after an uncertain response. When signing yields,
finalization persists the same private signing `PkiId` on the order and returns
the existing order as `processing`; it retains no request thread. Repeated
finalize/order polling recovers the identifier through the order correlation,
returns `processing` while the durable outer continuation is live, and changes
the order to `valid` or `invalid` only after the durable domain result reaches a
terminal state. Restart therefore resumes the exact issuance without duplicate
cryptography or certificate publication.
The issuance correlation commitment is derived only from the order's immutable
canonical issuance inputs and the canonical CSR identity. Mutable order status,
order-record commitment, and attachment fields never change that identity, so
repeated finalization before attachment, while processing, and after restart
addresses the same issuance operation.
Profile activation affects only new directory registration. Existing directories
and orders resolve the exact imported profile reference frozen in their directory
revision, so activating a newer profile revision cannot change or block their
validation, issuance, recovery, or confirmation policy.

Directory deactivation likewise affects discovery and admission only: a
deactivated revision no longer serves directory discovery, new-account, or
new-order requests. An authenticated account may still retrieve and complete
already-issued resources through the exact directory identity, revision, and
immutable policy commitment persisted on those resources. The directory's
whole-record commitment remains the compare-and-set coordinate and therefore
changes when its mutable status changes; accounts and orders never freeze that
mutable coordinate. Every existing-resource request retains canonical
account-KID JWS verification,
one-time nonce and exact URL binding, exact current account-key commitment, and
account ownership checks; neither an alias nor an object identifier acts as
authority to cross an account or directory boundary.

Replay nonces are scoped to the listener and canonical directory alias rather
than one mutable directory revision. The existing `new-nonce` URL therefore
continues to issue a bounded process-local one-time nonce for a known alias when
none of its revisions is active. Unknown aliases receive no usable nonce.
Discovery, new-account, and new-order admission remain active-revision-only.

Before an order becomes `valid`, both immediate and recovered issuance validate the exact account, order, directory revision, authority, profile, issuer, path, and issued credential, then pass the credential through the shared publication gate. That gate initializes the profile-owned confirmation lifecycle before it registers the exact disclosure decision. Replays are idempotent only when every frozen value and owner correlation still matches.

The authenticated certificate resource returns deterministic PEM in the order `issued leaf -> selected issuer/path certificates`. It performs no runtime path guessing. This resource remains accessible to the owning ACME account while a non-public confirmation lifecycle is pending, but retrieval does not confirm receipt. Anonymous Public Repository access remains governed exclusively by the persisted disclosure policy, so an owner-only ACME certificate is not publicly retrievable.

For a valid order whose non-public credential still requires confirmation, the
order object advertises this versioned extension:

```json
"credentialConfirmation": {
  "version": 1,
  "challenge": "https://acme.example.invalid/acme/example/credential-confirmation/v1/challenge/{orderId}",
  "complete": "https://acme.example.invalid/acme/example/credential-confirmation/v1/complete/{orderId}"
}
```

Public credentials and credentials whose policy does not require confirmation
omit the extension. The challenge URL accepts an account-KID-authenticated JWS
whose decoded payload is exactly `{}`. Its response carries version 1 plus the
bounded proof presentation, proof-suite binding, expiry, response limit, and
the exact lifecycle/challenge compare-and-set coordinates required by the
client. The completion URL accepts only
`expectedLifecycleRevision`, `expectedLifecycleRecordCommitment`,
`expectedChallengeRecordCommitment`, and a canonical unpadded Base64url
`response`. The server derives the credential identity from the owned order;
clients cannot supply or redirect it. Completion returns only version 1 and
`CONFIRMED` or `REJECTED`. Rejection is a successful non-mutating proof result;
an exact terminal replay remains `CONFIRMED`.

Both confirmation operations validate the account, exact valid owned order,
frozen directory revision, issued credential, disclosure policy, and persisted
publication correlation before calling the transport-neutral confirmation
service. Malformed, padded, empty, oversized, stale, cross-account,
wrong-directory, non-valid, and not-required requests fail with a safe ACME
problem and do not invoke that service. Responses retain `Cache-Control:
no-store`. Proof bytes, presentations, JWS material, compare-and-set crypto
values, and provider diagnostics are excluded from audit, exceptions, and
diagnostics. The transport-owned decoded proof temporary is cleared. Immutable
defensive presentation and proof copies remain bounded, request-local,
unpersisted, unlogged, and eligible for collection after the synchronous call;
the API does not claim a wipeable immutable carrier.

`maximumBodyBytes` remains deployment-configurable, but startup derives and
enforces its exact lower bound from the configured external base URI and the
largest supported version-1 completion in the existing flattened JWS form.
The derivation includes the maximum alias and object identifiers, protected
header, account KID, nonce, exact completion URL, payload, maximum 16 KiB proof
response, canonical Base64url expansion, ES256 signature, and JSON framing.
This prevents a valid bounded completion from being rejected by a listener
configured below the protocol's own maximum; public and administrative listener
limits are unchanged.

Challenge construction is `O(D + K + T + log M)`, pending completion is
`O(D + T + R + V(K) + log M)`, and exact terminal replay is
`O(J + R + log M)`, where the named proof and persistence operations retain
their existing meanings. Auxiliary memory is bounded and request-local. The
adapter is synchronous and persisted-state based, so a future short-lived CLI
listener can reuse the same service without adding an A7-specific command,
resident workflow object, worker, queue, cache, or handle.

Revocation delegates to the existing `RevocationService`, is limited to the account's issued certificate and supported ACME reason semantics, and never edits revocation records directly. Account key rollover uses strict nested JWS and atomically replaces the account key; the previous key stops authorizing after commit.

Contacts and identifiers are sensitive. Audit events contain safe IDs and classifications only—never JWS signatures, JWKs, contacts, tokens, key authorizations, DNS values, HTTP responses, CSR DER, certificate subject/SAN, EAB material, paths, or provider failures.
