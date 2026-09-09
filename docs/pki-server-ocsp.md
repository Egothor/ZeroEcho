# ZeroEcho OCSP responder

ZeroEcho serves OCSP only on the separately bounded public listener at
`/ocsp/{responderAlias}`. Administrative operations remain under `/admin/v1`,
the public repository remains under `/public/v1`, and ACME remains on its own
listener. All four surfaces share one realm and one long-lived `PkiSession`, but
they do not share authorization or admission authority.

## Responder authority

An OCSP responder is a durable server-control record. Its alias binds exactly
one realm, logical authority, issuer generation, responder certificate,
`KeyRef`, explicit chain path, signature algorithm/binding commitment, nonce
policy, response-validity policy, accepted CertID hashes, and finite request
bounds. Each record also carries an explicit request-authentication mode and,
for signed modes, a finite immutable requester trust, mapping, signature,
revocation, and chain-bound policy. Activation revalidates those dependencies and freezes their
commitments. There is no first/last issuer selection, filename inference,
timestamp inference, runtime path building, or fallback signing algorithm.

The unified administrative catalog exposes:

- `ocsp.responder.register`
- `ocsp.responder.inspect`
- `ocsp.responder.list`
- `ocsp.responder.activate`
- `ocsp.responder.deactivate`

Inspection requires `OCSP_RESPONDER_READ`; mutation requires the scoped
`OCSP_ADMINISTER` permission. Registration and activation are high-risk
operations and use the existing approval policy. Registration input does not
accept authoritative creation timestamps, lifecycle state, or record
commitments; the server creates those values. Ordinary results omit `KeyRef`,
certificate DER, and provider configuration.

## Signing modes

`ISSUER_SIGNED` is intended for explicitly approved internal deployments. The
configured credential and `KeyRef` must be the exact issuer-generation binding.
It should not be used to place an offline root key in an online service.

`DELEGATED_RESPONDER` is preferred for public online operation. Before
activation ZeroEcho verifies the responder certificate, its exact issuer
relationship, validity, `id-kp-OCSPSigning` EKU, digital-signature key usage
when present, explicit chain path, signing binding, and configured key
capability. Private keys remain confined behind `KeyRef` and the existing
signing workflow; the HTTP layer never obtains a `PrivateKey`.

Conceptual registration policies:

```text
issuer-signed internal:
  signingMode = ISSUER_SIGNED
  responderCredentialId = exact issuer-generation credential
  noncePolicy = REQUIRED

delegated public:
  signingMode = DELEGATED_RESPONDER
  responderCredentialId = exact OCSP-signing credential
  noncePolicy = REJECT

cacheable public:
  noncePolicy = REJECT
  cacheLifetime <= responseValidity

nonce echo:
  noncePolicy = OPTIONAL_ECHO
  nonce-bearing responses use no-store
```

## Request authentication

Every responder selects exactly one mode:

- `UNSIGNED_ONLY` is the default public responder policy. Unsigned requests are
  accepted and syntactically signed requests receive OCSP `unauthorized`.
- `UNSIGNED_OR_AUTHORIZED_SIGNED` preserves anonymous requests, but any signed
  request must authenticate and authorize completely; it never falls back to
  anonymous handling.
- `AUTHORIZED_SIGNED_REQUIRED` returns OCSP `sigRequired` for unsigned requests
  and accepts only authorized signed requests.

Signed request authentication is protocol-scoped. ZeroEcho retains the exact
canonical `tbsRequest` DER, requires a canonical `directoryName`
`requestorName` equal to the signer certificate subject, validates the bounded
included signer chain against configured trust selectors, and verifies the
signature using an active `OCSP_REQUEST_SIGNATURE` binding. Current standard
bindings permit ECDSA/SHA-256, Ed25519, RSA PKCS#1/SHA-256 and strict
RSA-PSS/SHA-256 when explicitly listed. SHA-1 request signatures are rejected.

Trust and authorization are independent. A cryptographic certificate, SPKI, or
managed issuer-generation-plus-serial commitment must map to exactly one enabled
persisted `SecurityPrincipal`. That principal needs an explicit
`OCSP_STATUS_QUERY` grant scoped to the exact realm, responder, authority, and
issuer generation. Explicit deny wins. `OCSP_ADMINISTER` grants no query right,
and query authority grants no administration, content, search, ownership,
disclosure, or PII right. Multi-entry authorization is all-or-nothing.

Requester certificate revocation uses one explicit policy:

- `LOCAL_AUTHORITATIVE_REQUIRED` requires a managed ZeroEcho credential and
  current local revocation state. It is the recommended closed-enterprise mode.
- `LOCAL_AUTHORITATIVE_IF_MANAGED` checks managed credentials locally and uses
  validity plus configured trust for external credentials.
- `VALIDITY_AND_TRUST_ONLY` performs no revocation check and must be selected
  deliberately with its stale-credential risk understood.

ZeroEcho does not follow AIA, CRL, or OCSP URLs while authenticating a requester
and never calls the responder recursively. A request signature authenticates
integrity and requester identity; it does not replace nonce freshness. Replay of
a permitted read-only request remains valid when nonce policy permits it.
`REQUIRED` nonce responders keep a finite derived process-local replay window;
restart may discard that operational window without changing PKI authority.

Safe policy examples omit real identities and commitments:

```text
public unsigned:
  requestAuthenticationMode = UNSIGNED_ONLY

mixed transition:
  requestAuthenticationMode = UNSIGNED_OR_AUTHORIZED_SIGNED
  requesterRevocationPolicy = LOCAL_AUTHORITATIVE_REQUIRED

closed managed enterprise:
  requestAuthenticationMode = AUTHORIZED_SIGNED_REQUIRED
  trustSelectors = [managed issuer generations]
  requiredPermission = OCSP_STATUS_QUERY
  requesterRevocationPolicy = LOCAL_AUTHORITATIVE_REQUIRED

closed external trust:
  requestAuthenticationMode = AUTHORIZED_SIGNED_REQUIRED
  trustSelectors = [configured trust anchors]
  requesterRevocationPolicy = LOCAL_AUTHORITATIVE_IF_MANAGED
```

Migration is explicit: replace the pre-release responder record with its desired
mode and complete requester policy, validate scoped grants, and activate it
through the configured approval workflow. The obsolete schema is rejected; no
mode is inferred and no compatibility reader exists.

## Requests and responses

POST uses `Content-Type: application/ocsp-request`. GET uses an unpadded,
canonical URL-safe Base64 request path:

```text
/ocsp/{responderAlias}/{base64url-request}
```

Query-string requests and alternate Base64 normalization are rejected. The
strict DER parser consumes the complete input, rejects all per-entry extensions
and duplicate or unknown critical request extensions, and enforces configured
byte, entry, signer-certificate, and chain bounds. Signed requests additionally
require the exact canonical optional-signature structure described above.

Configured CertID hashing supports SHA-1 and SHA-256. SHA-1 is permitted only
for RFC-compatible issuer-name/key hashes. It is never enabled as a certificate
or OCSP response signature algorithm. The responder validates hashes against
its exact issuer-generation certificate and performs a disk-backed direct
issuer-generation-plus-serial lookup; it never searches another authority or
scans all credentials per request.

One response captures one revocation revision and commitment. `good` means the
exact credential was issued by that issuer and is not revoked in that stable
ZeroEcho view; it is not a general statement of application validity.
`revoked` preserves the authoritative revocation time and supported reason.
`unknown` means exact issuance could not be established. Corrupt or
recovery-required authority returns a transient protocol/transport failure, not
`unknown`.

Successful responses are strict signed DER with
`application/ocsp-response`, `nosniff`, `producedAt`, `thisUpdate`, and
`nextUpdate`. Nonce-free unsigned responses carry a strong ETag and bounded public cache
policy. An echoed nonce is returned exactly and makes the response non-cacheable.
Every authenticated signed response uses `Cache-Control: private, no-store` and
`Pragma: no-cache`, even without a nonce; shared caches never store it.
No request DER, response DER, serial, issuer hash, nonce, certificate identity,
key reference, or parser/provider exception is logged or audited.

Live OCSP response signing is deliberately immediate-only. If its provider does
not produce a terminal result in the initial bounded step and single
observation, the server cancels or reconciles that signing operation to terminal
cleanup and returns the canonical DER OCSP `tryLater` response with `no-store`.
It does not retain an HTTP worker, cache the response, or create a durable OCSP
domain continuation. Signing-runtime admission overload remains the separate
HTTP 429 mapping.

## Deployment topology and capacity

Direct mode permits anonymous OCSP over the public TLS listener. An optional
public client certificate neither replaces nor supplements the signed requester
and does not change certificate status; forwarded identity headers remain
rejected. In trusted-reverse-proxy mode the backend proxy hop still requires
mTLS and the dedicated forwarding permission. The proxy transport principal,
forwarded administrative principal, and signed OCSP requester remain distinct
and do not inherit one another's permissions or select OCSP status. Source
IP, `Forwarded`, and `X-Forwarded-For` are never responder authority.

OCSP has a separate bounded runtime lane even though it shares the public
transport listener. Parsing, lookup, signing, and response validation are
protected by finite request, queue, admission, concurrency, and deadline bounds.
OCSP saturation cannot consume administrative, public-stream, or ACME operation
permits. Shutdown quiesces admission, cancels remaining operations after the
finite grace period, and never retries an uncertain signature automatically.

Example topologies use the existing strict public-listener configuration:

```text
direct public listener:
  public TLS identity + DIRECT_MTLS optional-client mapping policy

trusted proxy public listener:
  proxy-to-ZeroEcho mTLS + dedicated proxy principal
  + FORWARD_AUTHENTICATED_CLIENT_IDENTITY
```

The current release is single-node. It has no distributed responder cache,
cluster coordination, or automatic status/checkpoint scheduling. Deployments
must route a responder alias to the node owning its realm and provision normal
external availability monitoring without treating that monitoring as PKI
authority.
