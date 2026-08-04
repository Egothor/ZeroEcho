# ZeroEcho administrative HTTPS server

The `pki-server` distribution exposes the transport-neutral realm gateway through mutual TLS. One process opens one realm and one long-lived PKI session; all administrative execution uses the existing typed operation catalog and `ServerOperationGateway`.

## Starting the server

```text
zeroecho-pki-server --validate-config --config server-config.json
zeroecho-pki-server --config server-config.json
```

Use `--help` and `--version` for launcher information. Validation parses the strict versioned JSON and checks finite security bounds without opening a listener, realm, store, provider, or audit sink.

The loopback and production examples are [pki-server-loopback-example.json](pki-server-loopback-example.json) and [pki-server-production-example.json](pki-server-production-example.json). They contain no credentials or key material. Replace every illustrative commitment and identity with provisioned values before use. The mapped principal must already exist in the durable server-control store and have explicit scoped grants; a certificate mapping establishes identity only and never grants authority.

## TLS and authentication

Administrative access has no anonymous mode. The listener always requires a client certificate. The built-in `jsse-pkcs12` TLS provider reads server identity and client trust stores from configured files, while passwords are resolved exclusively from named environment variables. Provider exceptions, aliases, references, certificate subjects, SANs, fingerprints, and paths are not returned to clients or written to request audit details.

Client certificates map to persisted principals through an exact SHA-256 certificate, canonical SPKI, or issuer-and-positive-serial commitment. Subject and SAN strings are not trust identities. An absent, ambiguous, expired, malformed, untrusted, or disabled mapping fails before typed operation decoding.

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

No ACME or public certificate repository routes are part of this server. Administrative POST bodies are strict UTF-8 JSON containing version, optional authority and approval identities, an optional shortening deadline, and the closed argument object for one typed operation. Batch execution, file paths, raw DER, polymorphic class metadata, unknown keys, duplicate keys, and trailing JSON are rejected.

Responses are deterministic version-one JSON. They carry only safe typed results or stable failure codes. `RECOVERY_REQUIRED` and `EXTERNAL_OUTCOME_UNKNOWN` remain distinct; deadlines never claim rollback and never trigger automatic retry.

## Capacity and shutdown

Transport workers, transport backlog, concurrent operation workers, waiting operation capacity, admitted requests, request body size, deadlines, and both shutdown periods are finite configuration values. Saturation never runs a request on the caller thread and a rejected request never invokes the gateway.

Shutdown first removes readiness and admission, stops listener acceptance, drains for the configured graceful period, cooperatively cancels remaining work, waits only for the forced period, then closes the one realm context. Already committed PKI changes remain committed.

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
