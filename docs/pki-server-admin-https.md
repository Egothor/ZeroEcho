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
POST /admin/v1/operations/{operationId}
```

No ACME or public certificate repository routes are registered on the administrative listener. Optional ACME and public repository listeners are independently configured and bounded; see [pki-server-acme.md](pki-server-acme.md) and [pki-server-public-repository.md](pki-server-public-repository.md). Administrative POST bodies are strict UTF-8 JSON containing version, optional authority and approval identities, an optional shortening deadline, and the closed argument object for one typed operation. Batch execution, file paths, raw DER, polymorphic class metadata, unknown keys, duplicate keys, and trailing JSON are rejected.

Responses are deterministic version-one JSON. They carry only safe typed results or stable failure codes. `RECOVERY_REQUIRED` and `EXTERNAL_OUTCOME_UNKNOWN` remain distinct; deadlines never claim rollback and never trigger automatic retry.

## Capacity and shutdown

Transport workers, transport backlog, concurrent operation workers, waiting operation capacity, admitted requests, request body size, deadlines, and both shutdown periods are finite configuration values. Saturation never runs a request on the caller thread and a rejected request never invokes the gateway.

Configuration schema version 6 adds `signingReconciliation`. Its production
defaults are enabled, 256 examined records, 64 provider calls, a 30-second pass
timeout, a 10-second provider-call timeout, and a fixed 2-second idle interval.
`maxRecords` is 1 through 4096, `maxCalls` is 1 through the record
bound, all durations are positive, and the provider timeout cannot exceed the
pass timeout. Version 5 configurations migrate to these defaults. Set `enabled`
to `false` only when an external owner deliberately invokes the transport-neutral
session reconciliation API.

Shutdown first removes readiness and admission, stops listener acceptance, drains for the configured graceful period, cooperatively cancels remaining work, waits only for the forced period, then closes the one realm context. Already committed PKI changes remain committed.

Signing-provider deadlines and cancellation are cooperative for trusted
in-process implementations. A provider call that remains live after forced
shutdown causes `SIGNING_RECONCILIATION_SHUTDOWN_TIMEOUT`; the session, provider,
and store stay open and `close` may be retried after the call returns. Hard
isolation for non-cooperative providers requires an out-of-process boundary.

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

`security.disclosure.capability.issue` is the only one-time-sensitive response.
The durable store receives the token commitment before the raw 256-bit token is
returned. Its HTTPS response additionally carries `Cache-Control: no-store`,
`Pragma: no-cache`, and `Referrer-Policy: no-referrer`. The token is absent from
catalogs, inspection results and audit details. A response-write failure is
classified as delivery-unknown; the server neither regenerates nor retries the
token automatically.
