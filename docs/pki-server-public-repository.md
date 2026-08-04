# ZeroEcho public PKI repository

The public repository is an optional listener that is configured independently
from the administrative HTTPS listener. Both listeners use the same realm and
long-lived PKI session, but they have separate ports, TLS policy, worker pools,
queues and admission limits. Administrative routes are never registered on the
public listener, and public routes are never registered on the administrative
listener.

Non-loopback public service requires TLS. Explicit loopback plaintext is intended
only for deterministic development tests. A direct TLS listener requests an
optional client certificate: an absent certificate is anonymous, while a supplied
invalid or unmapped certificate fails authentication. A trusted-reverse-proxy
listener requires mutual TLS on the proxy-to-ZeroEcho hop. Its transport principal
must have only `FORWARD_AUTHENTICATED_CLIENT_IDENTITY`; an absent forwarded client
identity remains anonymous, and an invalid forwarded identity never falls back to
anonymous. RFC 9440 is preferred. The explicitly selected NGINX escaped-PEM format
uses the same strict validation described in the administrative-server guide.

## Disclosure and retrieval

`PUBLIC` objects are anonymously retrievable. `AUTHENTICATED`, `OWNER_ONLY` and
`RESTRICTED` objects require the corresponding end-client identity and scope.
`NOT_PUBLISHED` objects are unavailable. `PUBLIC_UNLISTED` retrieval uses exactly:

```text
Authorization: Bearer <one-time-issued-capability>
```

Capabilities are never accepted in a query, cookie, form body or alternate
header. They are bound to one realm, object, action and expiry. Capability
responses are private and non-cacheable. An object ID is not authentication
authority, and the repository intentionally provides no leaf-certificate search
or listing endpoint.

Single certificates and CRLs use canonical DER with `application/pkix-cert` and
`application/pkix-crl`. Explicit chain paths and the stable chain route return
deterministic JSON containing the ordered certificate retrieval links and the
path commitment; no ambiguous concatenated DER representation is defined.

Immutable public objects use strong ETags and the configured immutable cache
duration. Stable alias routes use both alias and target commitments and a shorter
configured cache duration. Authenticated responses are private and non-cacheable.
`HEAD` performs the same authorization and integrity checks as `GET`, and
`If-None-Match` returns `304` only after access has been re-evaluated.

The versioned route set is deliberately finite:

```text
GET|HEAD /public/v1/authorities
GET|HEAD /public/v1/authorities/{authorityId}
GET|HEAD /public/v1/authorities/{authorityId}/issuers/{issuerId}/certificate
GET|HEAD /public/v1/authorities/{authorityId}/issuers/{issuerId}/paths/{pathId}
GET|HEAD /public/v1/authorities/{authorityId}/chain
GET|HEAD /public/v1/authorities/{authorityId}/crl
GET|HEAD /public/v1/certificates/{credentialId}
GET|HEAD /public/v1/status/{statusObjectId}
```

Authority listing uses bounded keyset pagination through `after` and `limit`.
No leaf-certificate collection or search route exists. Explicit chain paths are
never inferred from certificate dates, filenames, local trust stores, or list
order.

## Stable repository aliases

Issuer generations and chain paths are PKI authority. Repository aliases are
separate operational metadata. `CURRENT_CRL` points to one exact public CRL status
object. `CURRENT_CHAIN` points to one exact issuer generation and immutable chain
path. Updates require expected-current conflict protection and never alter the
target object, issuance selection, revocation state or disclosure policy.

A typical administrative workflow is:

```text
status.generate
→ inspect the status object
→ security.disclosure.set to PUBLIC
→ repository.alias.set with type CURRENT_CRL and expected-current commitment
→ GET /public/v1/authorities/{authorityId}/crl
```

Chain publication is similarly explicit: validate or register the backend chain
path, make every path certificate public, then set `CURRENT_CHAIN`. Generating a
CRL or rotating an issuer never changes a public alias automatically.

The direct public-listener example is in
`docs/pki-server-loopback-example.json`. The RFC 9440 trusted-proxy example is in
`docs/pki-server-trusted-proxy-rfc9440-example.json`. The production and NGINX
administrative examples explicitly disable the public listener with
`"publicListener":{"enabled":false}`. A disabled section rejects every ignored
listener field; enabling requires the complete independent transport,
authentication, capacity, deadline, and cache configuration.
