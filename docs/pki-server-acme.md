# ACME automated certificate management

ZeroEcho exposes ACME on an optional listener that is independent of the administrative and public-repository listeners. All three listeners share one realm and one long-lived `PkiSession`, but they have separate routes, workers, queues, and admission limits. The ACME listener serves only `/acme/{directoryAlias}/...`; it never exposes `/admin/v1` or `/public/v1`.

An ACME directory is an immutable policy revision bound to one realm, logical authority, active end-entity profile, explicit current issuer generation, and explicit issuance chain path. It also freezes DNS namespaces, key and X.509 binding policy, validity, challenge providers, EAB policy, disclosure policy, and a policy commitment. A client cannot select another authority, profile, issuer, path, binding, or disclosure state in an order.

## Listener and topology

Direct deployments use server-authenticated TLS. A client TLS certificate is not ACME account authority; ACME identity is the account key authenticated by JWS. Trusted-reverse-proxy deployments require the established mutually authenticated proxy-to-ZeroEcho TLS hop and a dedicated enabled proxy principal with `FORWARD_AUTHENTICATED_CLIENT_IDENTITY`. Forwarded administrative identity is not used as an ACME account. Source addresses and `Forwarded` or `X-Forwarded-*` headers never authorize ACME.

The server configuration schema is version 4. ACME is disabled explicitly with:

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

Directory registration is performed through the unified administrative operation catalog, followed by an approved `acme.directory.activate` when configured policy requires approval.

- An internal DNS directory restricts `dnsNamespaces` to the enterprise suffix, enables only `DNS_01`, and configures `zeroecho.dns-01.jndi.v1` with an explicit numeric DNS provider URL.
- A public HTTP directory enables `HTTP_01` through `zeroecho.http-01.v1`; private and internal validation targets remain rejected unless the directory provider configuration explicitly permits them.
- A wildcard directory enables `DNS_01`; wildcard identifiers cannot use HTTP-01.
- An EAB-required enterprise directory sets `eabRequired` and selects one explicitly enabled EAB provider. EAB secrets remain inside the provider boundary and are never persisted in ACME records.
- A trusted-proxy directory uses the same directory policy as a direct deployment; only listener transport composition differs.

## Protocol and validation

Replay nonces contain 256 bits of randomness, are listener/directory bound, one-time, finite-lived, and process-local. JWS accepts only flattened, canonical, unpadded Base64url ES256 with exact URL binding and exactly one of `jwk` or `kid`. The effective external URL comes from configuration, not an untrusted host or forwarding header.

HTTP-01 probes the canonical challenge URL on port 80, pins policy-validated resolution results, bounds response bytes and deadlines, and never forwards credentials. The optional `targetPort` provider setting exists only for explicitly private test or internal validation environments: a nonstandard port is rejected unless `allowPrivate` is also explicitly enabled. Production Internet-facing directories should omit `targetPort` and therefore use port 80. DNS-01 uses absolute `_acme-challenge` queries, exact TXT digest matching, explicit DNS resolver configuration, and bounded optional CNAME delegation. Challenge success becomes authoritative only after provider-produced evidence is durably bound to the exact authorization. There is no administrative force-valid operation.

## Issuance, chains, disclosure, and revocation

Finalization requires every authorization to be valid and unexpired, strict canonical CSR/PoP validation, and exact equality between canonical CSR identifiers and order identifiers. Issuance uses the directory's frozen authority/profile policy plus the authority's explicit current issuer and explicit issuance chain path. A durable issuance intent prevents duplicate certificate creation after an uncertain response.

The authenticated certificate resource returns deterministic PEM in the order `issued leaf -> selected issuer/path certificates`. It performs no runtime path guessing. This resource is account-authorized and does not bypass the separate Public Repository disclosure decision. The directory controls the resulting leaf disclosure policy and never makes certificates publicly searchable.

Revocation delegates to the existing `RevocationService`, is limited to the account's issued certificate and supported ACME reason semantics, and never edits revocation records directly. Account key rollover uses strict nested JWS and atomically replaces the account key; the previous key stops authorizing after commit.

Contacts and identifiers are sensitive. Audit events contain safe IDs and classifications only—never JWS signatures, JWKs, contacts, tokens, key authorizations, DNS values, HTTP responses, CSR DER, certificate subject/SAN, EAB material, paths, or provider failures.
