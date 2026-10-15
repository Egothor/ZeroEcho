# Server configuration reference

The ZeroEcho PKI server is configured by one strict, versioned JSON file, passed
with `--config`. The file describes exactly one realm and one server instance: its
store and audit locations, its signing key material, its TLS identity and client
trust, its listeners, and its administrative authentication mode. The server owns
no secret values in this file — it holds only the *names* of environment variables
that carry secrets.

This page documents the current schema (`version` **8**). For the deployment
topology that surrounds it, see the
[deployment configuration guide](../deployment/configuration.md); for the API the
listeners serve, see the [administrative API](admin-api.md).

!!! info "Validate before you run"
    Run a preflight validation without opening any provider, store, listener, or
    audit sink:

    ```bash
    zeroecho-pki-server --validate-config --config /etc/zeroecho/server-config.json
    ```

    It parses and fully validates the strict document and prints
    `configuration valid` on success, exiting non-zero on any framing or
    semantic error. The container entry point runs this as a fail-fast preflight
    before starting the server.

## Top-level structure

This is a structural outline; use the complete example below for validation.

```text
{
  "version": 8,
  "serverName": "zeroecho-admin",
  "realm": { },
  "listener": { },
  "authentication": { },
  "execution": { },
  "auditProjection": { },
  "publicListener": { "enabled": false },
  "acmeListener": { "enabled": false },
  "estListener": { "enabled": false },
  "scepListener": { "enabled": false },
  "cmpListener": { "enabled": false },
  "runtime": { }
}
```

| Field | Required | Description |
| --- | --- | --- |
| `version` | yes | Schema version. Must be `8`. |
| `serverName` | yes | A safe operational name (≤ 128 characters). |
| `realm` | yes | Realm identity, store/audit, signing, approval, and disclosure policy. |
| `listener` | yes | The administrative HTTPS listener. |
| `authentication` | yes | Administrative client-certificate authentication. |
| `execution` | yes | Worker, queue, admission, deadline, and shutdown bounds. |
| `auditProjection` | yes | Audit projection batch and idle interval bounds. |
| `publicListener` | yes | The public repository listener, or `{ "enabled": false }`. |
| `acmeListener` | yes | The ACME listener, or `{ "enabled": false }`. |
| `estListener`, `scepListener`, `cmpListener` | yes | Protocol listener configuration, or `{ "enabled": false }` for each. |
| `runtime` | yes | Process-local capability references (for example the keyring unlock variable). |

Unknown fields anywhere in the document are rejected.

## Complete example

The following loopback example is a complete, valid `version 8` document. The
notes below describe its security and storage fields. Replace the example policy
commitments and certificate mapping with your deployment's values before use.
The codec validates structure and policy consistency without opening providers
or checking that referenced TLS files exist.

```json
{
  "version": 8,
  "serverName": "zeroecho-admin",
  "realm": {
    "realmId": "production",
    "displayName": "ZeroEcho Production",
    "confirmationProof": {
      "audience": "urn:uuid:11111111-1111-4111-8111-111111111111",
      "challengeTtlMillis": 300000,
      "rsaMaximumModulusBits": 8192
    },
    "authorityExposure": {
      "mode": "ALL_REALM_AUTHORITIES",
      "authorityIds": [],
      "creationPermitted": false
    },
    "authorizationCommitment": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "approvalCommitment": "96f85d99cb556b16af9b963833a832f905010681f437a757d94aab4a22e4c29c",
    "disclosureCommitment": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "disclosureDefaults": {
      "rootCa": "PUBLIC",
      "intermediateCa": "PUBLIC",
      "caChain": "PUBLIC",
      "crl": "PUBLIC",
      "leaf": "OWNER_ONLY",
      "sensitiveLeaf": "RESTRICTED"
    },
    "controlLog": "state/server-control.log",
    "controlStoreId": "0123456789abcdef0123456789abcdef",
    "approvalPolicy": {
      "policyId": "high-risk",
      "threshold": 1,
      "eligibleApprovers": [
        "bootstrap-approver"
      ],
      "requiredRoleTemplateIds": [],
      "requesterSeparation": true,
      "lifetimeMillis": 3600000,
      "justificationRequired": true
    },
    "pkiSession": {
      "version": 6,
      "store": {
        "id": "fs",
        "properties": {
          "root": "state/pki"
        }
      },
      "audit": {
        "id": "file",
        "properties": {
          "root": "state/audit"
        }
      },
      "publishers": [],
      "bindingProviders": []
    }
  },
  "listener": {
    "address": "127.0.0.1",
    "port": 8443,
    "tlsProvider": {
      "id": "jsse-pkcs12",
      "properties": {
        "keyStore": "tls/server-identity.p12",
        "keyStorePasswordEnvironment": "ZEROECHO_TLS_KEYSTORE_PASSWORD",
        "trustStore": "tls/administrators-trust.p12",
        "trustStorePasswordEnvironment": "ZEROECHO_TLS_TRUSTSTORE_PASSWORD"
      }
    },
    "clientCertificateRequired": true,
    "maximumHeaderBytes": 32768,
    "maximumBodyBytes": 1048576
  },
  "authentication": {
    "mode": "DIRECT_MTLS",
    "directClientMappings": [
      {
        "mappingId": "bootstrap-administrator",
        "principalId": "bootstrap-admin",
        "certificateSha256": "0000000000000000000000000000000000000000000000000000000000000000"
      }
    ]
  },
  "execution": {
    "transportWorkers": 8,
    "transportQueueCapacity": 64,
    "operationWorkers": 4,
    "operationQueueCapacity": 32,
    "maximumAdmittedRequests": 96,
    "defaultDeadlineMillis": 30000,
    "maximumDeadlineMillis": 120000,
    "gracefulShutdownMillis": 30000,
    "forcedShutdownMillis": 10000
  },
  "auditProjection": {
    "maxRecords": 256,
    "maxSinkCalls": 64,
    "idleIntervalMillis": 2000
  },
  "publicListener": {
    "enabled": false
  },
  "acmeListener": {
    "enabled": false
  },
  "estListener": {
    "enabled": false
  },
  "scepListener": {
    "enabled": false
  },
  "cmpListener": {
    "enabled": false
  },
  "runtime": {
    "keyUnlockEnvironmentVariable": "ZEROECHO_KEYRING_PASSWORD"
  }
}
```

1. Tamper-evidence commitments (SHA-256 hex) over the authorization, approval,
   and disclosure policy. They pin the policy the durable records were created
   under; the server rejects the file if they do not match the supplied policy.
2. The dedicated server-control metadata log; its parent directory must exist.
3. The **store root** — where issued objects and metadata live. The provider is
   selected by `id`; `properties` are provider-specific.
4. The **audit sink**. Its provider and properties are, likewise, chosen by `id`.
5. Secrets are referenced **by environment-variable name**, never inline. The
   value of `keyStorePasswordEnvironment` is a variable name the process reads at
   startup.
6. Must be `true`: the administrative listener always requires a client
   certificate.
7. A client-certificate mapping binds a certificate commitment to a server
   principal. At least one of `certificateSha256`,
   `subjectPublicKeyInfoSha256`, or `issuerSerialSha256` is required.
8. The keyring unlock secret is read from this named environment variable at
   startup.

## Realm

| Field | Description |
| --- | --- |
| `realmId` | Canonical realm identity. |
| `displayName` | Administrative display name (≤ 256 characters). |
| `confirmationProof` | Credential-confirmation proof `audience`, `challengeTtlMillis`, `rsaMaximumModulusBits`. |
| `authorityExposure` | `mode`, an explicit `authorityIds` list, and `creationPermitted`. |
| `authorizationCommitment`, `approvalCommitment`, `disclosureCommitment` | SHA-256 hex commitments to the corresponding policy. |
| `extendedApprovalCommitment` | Commitment over any non-high-risk approval policies; required when issuance approval policies are present. |
| `disclosureDefaults` | Default [disclosure level](security-model.md#data-view-redaction) per object class (`rootCa`, `intermediateCa`, `caChain`, `crl`, `leaf`, `sensitiveLeaf`). |
| `controlLog`, `controlStoreId` | Server-control metadata log path and durable store identity. |
| `approvalPolicy` | The high-risk approval policy (see the [Security model](security-model.md)). |
| `issuanceSingleApprovalPolicy`, `issuanceThresholdApprovalPolicy` | Optional issuance approval policies. |
| `pkiSession` | The shared PKI session: store, audit, signing, publishers, and binding providers. |

### Store, audit, and publishers

Inside `realm.pkiSession`:

| Field | Description |
| --- | --- |
| `version` | PKI session schema version. |
| `store` | The object/metadata store provider: `{ "id": …, "properties": { … } }`. The store root is the store provider's `properties`. |
| `audit` | The audit sink provider, same `{ "id", "properties" }` shape. |
| `signing` | Optional signing provider, signature algorithm, signing TTL, and finite lane topology. |
| `publishers` | A list of publisher output providers. |
| `bindingProviders` | A list of algorithm-binding providers. |

Every provider block is `{ "id": "<provider-id>", "properties": { "<k>": "<v>" } }`.
Property values are strings; those that reference secrets hold environment-variable
names, not the secret itself.

#### Optional credential-search index

The `fs` store can enable credential search with an embedded **H2 2.5.252**
database. Add these string properties to `realm.pkiSession.store.properties`:

```json
{
  "root": "state/pki",
  "credentialSearch": "h2",
  "credentialSearchCacheKiB": "16384",
  "credentialSearchQueryTimeoutMillis": "5000",
  "credentialSearchMaximumCertificateBytes": "1048576"
}
```

These are example budgets, not defaults. Omit all four `credentialSearch*`
properties to disable search. Disabled installations open no search database and
do not expose `credential.search` through runtime discovery; direct execution is
also unavailable. Other PKI operations remain available under their existing
permissions. There is no unindexed search fallback.

| Property | Supported values |
| --- | --- |
| `credentialSearch` | `h2`; required to activate search. |
| `credentialSearchCacheKiB` | 16–1048576 KiB; required when enabled. Controls the database cache, not total JVM heap. |
| `credentialSearchQueryTimeoutMillis` | 1–600000 ms; required when enabled. One search deadline covers admission, lock waiting, SQL and result authorization. |
| `credentialSearchMaximumCertificateBytes` | 1–1048576 bytes; required when enabled. Bounds certificate DER before allocation. |

Missing budgets, unsupported engines and unknown search options are rejected.
The application constructs a local embedded connection; JDBC URLs, network
listeners and initialization SQL are not configurable.

The index is derived from authoritative PKI records and rebuilt before search
becomes available on each store open. Initial activation and subsequent starts
therefore read the stored certificate content and build its SQL indexes. Malformed
or oversized certificate content produces an explicit failure, not a silently
incomplete index. An index update failure after a committed credential disables
search until recovery; it does not undo successful issuance. The logical PKI
backup excludes the database and restored deployments rebuild it.

Exact SAN lookup uses the index, but existing substring filters can still scan
many rows. A timeout fails the request rather than returning a partial page.
Allow appropriate startup time, disk space and JVM memory for the selected
deployment size; the database cache setting alone is not a heap limit.

#### Built-in publisher providers

| Provider ID | Required properties | Optional properties | Description |
| --- | --- | --- | --- |
| `filesystem` | `root` (directory path), `targetId` (stable publication target identifier) | — | Publishes artifacts to a local directory. |
| `https` | `url` (HTTPS endpoint URL), `method` (`PUT` or `POST`), `targetId` (stable publication target identifier) | `credentials` (verbatim `Authorization` header value; supports `keyring:`, `env:`, and `dev-plaintext:` prefixes) | Publishes artifacts to a remote HTTPS endpoint via HTTP PUT or POST. |

Publisher property values that contain secrets should use a `keyring:` reference (resolved against the publisher secrets store) or an `env:` reference (resolved from the environment) rather than `dev-plaintext:`, which is for development only.

#### Built-in audit sink providers

| Provider ID | Required keys | Optional keys (default) | Description |
| --- | --- | --- | --- |
| `file` | `root` | — | Durable newline-delimited JSON records in a rotating log under `root`. Recommended for production. |
| `syslog` | `host` | `port` (514), `protocol` (udp), `app-name` (zeroecho-pki) | Forwards RFC 5424 syslog messages to a remote collector. `protocol` is `udp` or `tcp`. |
| `stdout` | — | — | Prints a single summary line per event to standard output. Useful for development. |
| `memory` | — | — | Retains events in-process (for testing only; not persistent). |

Example — syslog over TCP to a SIEM:

```json
"audit": {
  "id": "syslog",
  "properties": {
    "host": "siem.internal",
    "port": "6514",
    "protocol": "tcp",
    "app-name": "pki-prod"
  }
}
```

### Keyring unlock

The signing keyring is unlocked from an environment variable. Set
`runtime.keyUnlockEnvironmentVariable` to the variable **name**; the process reads that
variable at startup. The name must match `[A-Z][A-Z0-9_]{0,127}`.

## Listener (administrative HTTPS)

| Field | Description |
| --- | --- |
| `address` | Canonical IP literal bind address. |
| `port` | TCP port (`0` requests an ephemeral test port). |
| `tlsProvider` | The server TLS identity and administrative-client trust provider. |
| `clientCertificateRequired` | Must be `true`. |
| `maximumHeaderBytes` | Aggregate decoded request-header bound (1 KiB – 1 MiB). |
| `maximumBodyBytes` | Request-body bound (up to 16 MiB). |

The `tlsProvider` properties for the PKCS#12-based provider are `keyStore`,
`keyStorePasswordEnvironment`, `trustStore`, and `trustStorePasswordEnvironment` —
each store is a PKCS#12 file, each password is an environment-variable name.

## Administrative authentication

The `authentication` block selects one of two mutually exclusive modes.

=== "DIRECT_MTLS"

    The server terminates TLS and maps the TLS peer directly.

    ```json
    {
      "mode": "DIRECT_MTLS",
      "directClientMappings": [
        {
          "mappingId": "bootstrap-administrator",
          "principalId": "bootstrap-admin",
          "certificateSha256": "…"
        }
      ]
    }
    ```

    Only `mode` and `directClientMappings` are permitted; any proxy or
    forwarding field is rejected.

=== "TRUSTED_REVERSE_PROXY"

    An authenticated proxy terminates the client TLS and forwards the validated
    client certificate.

    ```json
    {
      "mode": "TRUSTED_REVERSE_PROXY",
      "proxyTransportMappings": [ { "mappingId": "proxy-transport", "principalId": "trusted-proxy", "certificateSha256": "…" } ],
      "forwardedClientMappings": [ { "mappingId": "forwarded-admin", "principalId": "bootstrap-admin", "subjectPublicKeyInfoSha256": "…" } ],
      "trustedProxyPrincipalIds": ["trusted-proxy"],
      "forwardedCertificateFormat": "RFC9440",
      "forwardedCertificateHeaderName": "Client-Cert",
      "forwardedCertificateChainHeaderName": "Client-Cert-Chain",
      "administrativeClientTrust": { "id": "jsse-pkcs12-client-trust", "properties": { "trustStore": "tls/administrators-trust.p12", "trustStorePasswordEnvironment": "ZEROECHO_ADMIN_TRUSTSTORE_PASSWORD" } },
      "maximumForwardedCertificateBytes": 65536,
      "maximumForwardedChainBytes": 524288
    }
    ```

    | Field | Description |
    | --- | --- |
    | `proxyTransportMappings` | Certificate commitments for the proxy's own transport certificate. |
    | `forwardedClientMappings` | Commitments mapping forwarded end-client certificates to principals. |
    | `trustedProxyPrincipalIds` | The exact set of admitted infrastructure principals; must equal the proxy mapping principals. |
    | `forwardedCertificateFormat` | `RFC9440` or `NGINX_ESCAPED_PEM_V1`. |
    | `forwardedCertificateHeaderName` | Leaf header name. For `RFC9440` it must be `Client-Cert`. |
    | `forwardedCertificateChainHeaderName` | Chain header name. For `RFC9440` it must be `Client-Cert-Chain`. |
    | `administrativeClientTrust` | Independent trust provider validating the forwarded client leaf. |
    | `maximumForwardedCertificateBytes`, `maximumForwardedChainBytes` | Bounds on forwarded material. |

!!! danger "Modes are strictly separated"
    The server enforces that proxy and end-client principal mappings never
    overlap in identity or in certificate/SPKI commitment. In `DIRECT_MTLS` any
    forwarded-identity header on a request is refused. See the
    [security model](security-model.md#trust-boundaries).

## Execution

| Field | Description |
| --- | --- |
| `transportWorkers`, `transportQueueCapacity` | HTTPS handler worker count and backlog. |
| `operationWorkers`, `operationQueueCapacity` | Concurrent gateway executions and their queue. |
| `maximumAdmittedRequests` | Maximum requests admitted across parsing and execution. |
| `defaultDeadlineMillis`, `maximumDeadlineMillis` | Default and hard-ceiling request deadlines. |
| `gracefulShutdownMillis`, `forcedShutdownMillis` | Graceful drain and forced-termination durations. |

## Audit projection and signing reconciliation

The required `auditProjection` block controls audit delivery:

| Field | Description |
| --- | --- |
| `maxRecords` | Maximum records examined per pass (1–4096). |
| `maxSinkCalls` | Maximum sink calls per pass (1–`maxRecords`). |
| `idleIntervalMillis` | Delay between passes (1–300000 ms). |

Signing reconciliation is owned by `realm.pkiSession.signing.topology`; the
removed top-level `signingReconciliation` field is rejected. Configure the
signing provider and finite coordinator/lane topology, including coordinator
bounds, exact key groups, and the required `catchAll` lane pool.

## Public repository listener

Set `{ "enabled": false }` to disable it, or supply the full block:

| Field | Description |
| --- | --- |
| `address`, `port` | Bind address and port. |
| `tlsProvider` | TLS identity/trust provider (or omit with `allowPlaintextLoopback` for loopback-only development). |
| `allowPlaintextLoopback` | Loopback-only plaintext development exception. |
| `authentication` | Optional-client authentication block (same `DIRECT_MTLS` / `TRUSTED_REVERSE_PROXY` shape). |
| `maximumHeaderBytes`, `maximumBodyBytes` | Independent public request bounds. |
| `execution` | Isolated public transport/stream execution bounds. |
| `maximumStreamDurationMillis` | Stream deadline. |
| `publicImmutableCacheMillis`, `publicAliasCacheMillis` | Public cache durations for immutable objects and stable aliases. |
| `authorityListExposed` | Whether the public authority-list routes are enabled. |

## Enrollment runtime configuration

Enabled ACME, EST, SCEP or CMP listeners require a separate
`--enrollment-config /absolute/path/enrollment.json` companion. Its
`"version": 1` is independent of the main server schema version 8. Relative file
paths resolve against the process working directory; use absolute paths in
deployment configuration. Unknown fields and invalid cross-references are rejected.
For the packaged container, mount the companion and set
`ZEROECHO_ENROLLMENT_CONFIG` to its path inside the container.
The repository's `docs/pki-enrollment-example.json` illustrates a SCEP credential
set. Replace its authority, issuer and chain identifiers with actual repository
identifiers, provision the referenced key and DER chain, and choose budgets for
your deployment. Its values are examples, not automatically selected defaults.
For ACME and EST enrollment/renewal without server-keygen, the required `keyrings`,
`credentialSets` and `activeCredentials` arrays may be empty.

The `budgets` object supplies explicit limits; there are no implicit defaults:

| Field | Meaning |
| --- | --- |
| `maximumTransactions` | Retained transactions, including terminal replay records, and one additional retained identity-history entry per ACME account. |
| `maximumPending` | Pending requests; cannot exceed `maximumTransactions`. |
| `maximumRetainedRequestBytes` | Retained request bytes and transaction metadata, including requester aliases, approval decisions and ACME account key-exclusion history. |
| `maximumRequestBytes` | One encoded request, at most 1 MiB. Transport bounds also apply. |
| `maximumConcurrentDispatches` | Concurrent dispatches, at most the pending limit. |
| `pendingLifetimeSeconds` | Positive pending lifetime, at most 30 days. |
| `retryAfterSeconds` | Positive polling interval, at most the pending lifetime. |

Each ACME account retains its initial key identity and any proven rollover
relationships solely to prevent those identities from approving their own
enrollment requests. This history does not grant permissions or change the
original request. Its count and encoded bytes consume the limits above; account
creation or rollover is rejected before changing account state if the required
history cannot fit. Include one identity-history entry per account, in addition
to its enrollment transactions, when sizing capacity. Rollover increases retained
bytes without adding another identity-history entry.
An account retains at most 256 distinct canonical key identities, and its complete
encoded record must fit within 512 KiB. Old exclusion evidence is retained; there
is no account-history pruning operation.

`keyrings` contains dedicated preprovisioned encrypted stores with `id` and `path`
fields. Key references use `keyringId` and `alias`. The existing injected
unlock provider supplies their unlock credential; configuration contains no raw
private keys or shared secrets. These stores must be separate from the signing
keyring and other managed storage roots.

`credentialSets` defines immutable EST, SCEP or CMP credentials by `credentialId`,
`protocol`, `authorityId`, `issuerId` and `chainPathId`. A `signer` references its
`key` and an ordered `certificateChain` of DER file paths, beginning with the
signer certificate and followed by the selected authority path. CMP signature
protection also supplies explicit `requestTrustAnchors`; `authorizedRaKeys`
contains authority-scoped canonical public-key commitments for RA privileges.
Trusting a client certificate alone does not grant those privileges.
An EST set requires the generator signer and its chain, empty `requestTrustAnchors`
and `authorizedRaKeys` arrays, and no `pbm` field. Server-keygen endpoints require an explicit active
EST selection for their authority. SCEP or CMP signers are not selected implicitly.

CMP `pbm` configuration declares allowed `digests` and `macs`, minimum/maximum
iterations and salt bytes, and requester `identities`. Each identity has a
hexadecimal `senderKid`, `identityId`, encrypted `secret` reference and explicit
administrative `ownerAliases` excluded from approving its requests. Provision
32–128 random secret bytes; a password of the same length is not equivalent.

`activeCredentials` selects a `credentialId` for each `(protocol, authorityId)`.
Changing the active selection does not replace credentials retained by an
existing transaction. Use a new ID when changing a credential set; retain old
sets while transactions still reference them. Credential retirement is currently
unavailable: every installed set remains pinned, and removing one from the
configuration prevents startup, even if it has expired. Expired retained sets
cannot protect protocol responses. EST enrollment/renewal and ACME do not require
message credentials; EST server-keygen retains its selected generator signer.

Optional `keygenArtifacts` configures client-encrypted server-keygen delivery:
`directory`, `maximumArtifactBytes`, `maximumRetainedBytes`, `maximumArtifacts`,
`maximumConcurrentGenerations` and `deliveryRetentionSeconds`. It does not permit
persisting plaintext private keys. Capacity is reserved before generation and
ciphertext is durably published before approval/signing. Delivery leases pin files
while in use; unresolved accepted issuance also prevents expiry cleanup. Expired
bytes are reclaimed through ordinary admission and recovery, while terminal replay
records continue to consume retained count/metadata capacity. Delivery retention
does not extend beyond the authenticated recipient or frozen generator-chain
validity. Keep this directory separate from backup transfer storage.

`--validate-config` checks structure and configuration relationships without
opening the realm or decrypting keys. Server startup additionally validates
resolved storage paths, key custody and certificate/authority bindings before
readiness. Offline validation does not prove that provisioned keys are usable.

## ACME listener

Set `{ "enabled": false }` to disable it. When enabled, the block configures a
separately bounded ACME protocol listener: `listenerId`, `address`, `port`,
`tlsProvider`, a `transportMode` (`DIRECT_TLS` or `TRUSTED_REVERSE_PROXY`, with
the same proxy fields as above), the public `externalBaseUri`, independent header
and body bounds, `execution` and `validationExecution` bounds, nonce lifetime and
capacity, presentation limits, rate-admission windows and ceilings, and the
enabled `challengeProviders` and `eabProviders`. See the administrator guide for
directory setup.

## EST listener

Set `{ "enabled": false }` to disable it. When enabled, configures a separately bounded EST
(RFC 7030) protocol listener for automated certificate enrolment. Fields:

| Field | Description |
| --- | --- |
| `enabled` | `true` to activate the listener; `false` (or absent) to disable. |
| `listenerId` | Identifier for log correlation. |
| `address` | Bind address (e.g. `"0.0.0.0"` or `"127.0.0.1"`). |
| `port` | TCP port. |
| `tlsProvider` | TLS configuration block (see Administrative listener). |
| `execution` | Thread-pool and deadline bounds (see Execution). |
| `maximumHeaderBytes` | Request-header size bound. |
| `maximumBodyBytes` | Request-body size bound. |

EST endpoints are managed at runtime via `est.endpoint.register/deregister/inspect/list`.
Their bindings are durable server-control records. Registration requires an
active `enrollmentProfileId` matching the certificate profile and permitted authority.

## SCEP listener

Set `{ "enabled": false }` to disable it. When enabled, configures a separately bounded SCEP
(RFC 8894) protocol listener for network-device and MDM certificate enrolment. Fields:

| Field | Description |
| --- | --- |
| `enabled` | `true` to activate the listener; `false` (or absent) to disable. |
| `listenerId` | Identifier for log correlation. |
| `address` | Bind address. |
| `port` | TCP port. |
| `tlsProvider` | TLS configuration block. |
| `execution` | Thread-pool and deadline bounds. |
| `maximumHeaderBytes` | Request-header size bound. |
| `maximumBodyBytes` | Request-body size bound. |

SCEP endpoints are managed at runtime via `scep.endpoint.register/deregister/inspect/list`.
Their durable bindings require an active `enrollmentProfileId` matching the
certificate profile and permitted authority.
The challenge password hash is a SHA-256 hex string (64 lower-case hex characters).

## CMP listener

Set `{ "enabled": false }` to disable it. When enabled, configures a separately bounded CMP
(RFC 4210 / RFC 9480 Lightweight Profile) listener for telco, automotive, and regulated deployments.
Fields:

| Field | Description |
| --- | --- |
| `enabled` | `true` to activate the listener; `false` (or absent) to disable. |
| `listenerId` | Identifier for log correlation. |
| `address` | Bind address. |
| `port` | TCP port. |
| `tlsProvider` | TLS configuration block. |
| `execution` | Thread-pool and deadline bounds. |
| `maximumHeaderBytes` | Request-header size bound. |
| `maximumBodyBytes` | Request-body size bound. |

CMP endpoints are managed at runtime via `cmp.endpoint.register/deregister/inspect/list`.
Their durable bindings require an active `enrollmentProfileId` matching the
certificate profile and permitted authority.
The `protectionPolicy` field of a CMP endpoint is either `SHARED_SECRET_MAC` or `SIGNATURE_BASED`.

## Runtime

| Field | Description |
| --- | --- |
| `keyUnlockEnvironmentVariable` | Optional name of the environment variable that unlocks the signing keyring. |
| `publisherSecretsStore` | Optional path to the encrypted publisher secrets store file. Required when any publisher provider property uses a `keyring:` reference. |
| `publisherSecretsEnvironmentVariable` | Optional name of the environment variable whose value is used as the password to unlock the publisher secrets store (CLASSIC and HYBRID protection profiles). |
