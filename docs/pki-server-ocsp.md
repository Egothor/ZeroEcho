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
bounds. Activation revalidates those dependencies and freezes their
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

## Requests and responses

POST uses `Content-Type: application/ocsp-request`. GET uses an unpadded,
canonical URL-safe Base64 request path:

```text
/ocsp/{responderAlias}/{base64url-request}
```

Query-string requests and alternate Base64 normalization are rejected. The
strict DER parser accepts unsigned requests only, consumes the complete input,
rejects duplicate or unknown critical extensions, and enforces configured byte
and entry bounds. Signed OCSP requests are rejected in this release; a request
signature is never treated as administrative or certificate-owner authority.

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
`nextUpdate`. Nonce-free responses carry a strong ETag and bounded public cache
policy. An echoed nonce is returned exactly and makes the response non-cacheable.
No request DER, response DER, serial, issuer hash, nonce, certificate identity,
key reference, or parser/provider exception is logged or audited.

## Deployment topology and capacity

Direct mode permits anonymous OCSP over the public TLS listener. An optional
public client certificate does not change certificate status, and forwarded
identity headers are rejected. In trusted-reverse-proxy mode the backend proxy
hop still requires mTLS and the dedicated forwarding permission; proxy and
forwarded end-client identities do not authorize or select OCSP status. Source
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
