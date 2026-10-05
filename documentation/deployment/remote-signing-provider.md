# Remote signing provider

The remote signing provider (`zeroecho-remote`) delegates all CA signing operations to an
external HTTP service rather than using a local software keyring. Private keys never leave
the remote side: the PKI server sends only the bytes to sign and receives only the resulting
signature. The server holds no private-key material and needs no keyring unlock variable when
this provider is active.

## When to use

- CA private keys are held in an HSM or HSM-backed signing service that exposes an HTTP API.
- Your security policy requires a separate signing node, an air-gapped process, or a human
  approval step before each CA signature.
- You want to run the PKI server without any private key material on its filesystem.

!!! warning "Mutually exclusive with the local provider"
    `zeroecho-remote` and `zeroecho-lib` register the same signing-capability slot.
    A deployment must use one or the other — never both in the same session.

## Configuration

Inside `realm.pkiSession.signing`, set `provider.id` to `"zeroecho-remote"` and supply the
properties below. The remote provider requires no `unlockEnvironmentVariable`.

```json
"signing": {
  "provider": {
    "id": "zeroecho-remote",
    "properties": {
      "endpoint":               "https://signer.internal:8444",
      "keyRefPrefix":           "zeroecho-remote:",
      "tlsKeystore":            "/etc/zeroecho/tls/signer-client.p12",
      "tlsKeystorePassword":    "REPLACE-WITH-CLIENT-P12-PASSWORD",
      "tlsTruststore":          "/etc/zeroecho/tls/signer-trust.p12",
      "tlsTruststorePassword":  "REPLACE-WITH-TRUST-P12-PASSWORD",
      "connectTimeoutMillis":   "10000",
      "callTimeoutMillis":      "30000"
    }
  },
  "signatureAlgorithm": "ecdsa-with-SHA384",
  "signingTtlMillis": 86400000,
  "topology": {
    "coordinator": {
      "pageSize": 64,
      "claimLeaseMillis": 30000,
      "providerCallTimeoutMillis": 15000,
      "idlePollIntervalMillis": 2000,
      "closeTimeoutMillis": 30000
    },
    "exactGroups": [
      {
        "keyRefs": ["zeroecho-remote:root-ca-key"],
        "lanePool": { "laneCount": 4, "prefetchSize": 8 }
      }
    ],
    "catchAll": { "laneCount": 2, "prefetchSize": 4 }
  }
}
```

!!! danger "TLS passwords are literal values, not environment-variable names"
    Unlike other TLS providers in ZeroEcho, `tlsKeystorePassword` and
    `tlsTruststorePassword` are read as plain strings from the configuration file —
    they are **not** environment-variable name references. Store the configuration file
    with mode `0600` (owner-read only) and treat it as a secret. Do not commit a
    filled-in configuration to a shared repository.

## Provider properties

| Property | Required | Default | Description |
| --- | --- | --- | --- |
| `endpoint` | yes | — | HTTPS URI of the remote signing service (e.g. `https://signer.internal:8444`). |
| `keyRefPrefix` | no | `"zeroecho-remote:"` | String prefix on all `KeyRef` values handled by this provider. The prefix is stripped before the remainder is sent as the opaque key handle to the remote service. |
| `operationHorizon` | no | `P90D` | Operation-identity horizon as an ISO-8601 duration. Must equal `P90D` if present; the value is fixed at 90 days. |
| `tlsKeystore` | yes | — | Path to a PKCS#12 file containing the client certificate and private key used for mutual TLS to the signing service. |
| `tlsKeystorePassword` | yes | — | Password for `tlsKeystore`. Read as a literal string (see note above). |
| `tlsTruststore` | yes | — | Path to a PKCS#12 trust store that verifies the signing service's server certificate. |
| `tlsTruststorePassword` | yes | — | Password for `tlsTruststore`. Read as a literal string (see note above). |
| `tlsProtocol` | no | `"TLSv1.3"` | TLS protocol version passed to the JVM SSL context. `TLSv1.3` is the recommended value. |
| `connectTimeoutMillis` | no | `10000` | TCP connection timeout in milliseconds. Must be a positive integer string. |
| `callTimeoutMillis` | no | `30000` | Per-request call timeout in milliseconds. Must be a positive integer string. |

## Key references

Each CA key managed by the remote service is identified by a `KeyRef` value in the session
configuration (for example in `topology.exactGroups[].keyRefs`). A key reference must start
with the configured `keyRefPrefix`; the suffix after the prefix is sent verbatim to the remote
service as the opaque key handle.

With the default prefix `"zeroecho-remote:"`, a key reference such as
`"zeroecho-remote:root-ca-key"` sends the handle `"root-ca-key"` to the signing service.
The remote service uses this handle to select the correct private key.

## Supported signature algorithms

The `signatureAlgorithm` in the signing block must be one of the algorithms the remote
capability registers. The packaged HTTPS transport supports:

| Algorithm identity | Common name |
| --- | --- |
| `rsa-pkcs1-sha256` | RSA PKCS#1 v1.5 with SHA-256 |
| `rsa-pkcs1-sha384` | RSA PKCS#1 v1.5 with SHA-384 |
| `rsa-pkcs1-sha512` | RSA PKCS#1 v1.5 with SHA-512 |
| `rsa-pss-sha256` | RSA-PSS with SHA-256 |
| `ecdsa-with-SHA256` | ECDSA with SHA-256 |
| `ecdsa-with-SHA384` | ECDSA with SHA-384 |
| `ecdsa-with-SHA512` | ECDSA with SHA-512 |
| `ed25519` | Ed25519 |
| `ed448` | Ed448 |
| `sphincs-plus` | SPHINCS+ |

!!! note "Post-quantum algorithms"
    ML-DSA (Dilithium) and SLH-DSA are not in the default remote capability set. If
    your signing service supports them, a custom transport implementation can extend the
    capability registration to include additional algorithms.

## Security requirements

**Mutual TLS is required.** The packaged transport opens an mTLS connection: the PKI server
authenticates to the signing service with `tlsKeystore`, and the signing service's server
certificate must chain to a CA in `tlsTruststore`. A configuration with no `tlsKeystore` is
rejected at startup with error code `REMOTE_TRANSPORT_UNCONFIGURED`.

**Private keys stay remote.** The transport sends only the bytes to be signed (or their
digest) and an opaque key handle. The response carries only the signature bytes and their
encoding. Private key material must never appear on the wire in either direction.

**No skew is permitted.** The signing domain validation enforces zero clock skew between
the PKI server and the remote service. Ensure NTP is synchronized on both hosts.

## Validating the configuration

Run the preflight check before starting the server:

```bash
zeroecho-pki-server --validate-config --config /etc/zeroecho/server-config.json
```

The preflight opens the remote transport and fetches capabilities from the signing service,
so it requires the service to be reachable and the TLS material to be in place. A non-zero
exit means the server would refuse to start.

## Extending the transport

The packaged transport speaks HTTPS. To attach a different protocol (for example a
vendor-specific HSM SDK, a Unix domain socket, or a gRPC service), extend
`RemoteSigningProviderFactory` and override `openTransport(ProviderConfig)` to return a
custom `RemoteSigningTransport`. Register your subclass as a `SigningProviderFactory` service
in `module-info.java`. See [Extending ZeroEcho](../developer/extending.md#the-remote-signing-transport-seam)
for the transport contract.
