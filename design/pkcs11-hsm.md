# PKCS#11 / HSM Integration — Design Specification

**Status:** Draft — 2026-09-30  
**Author:** ZeroEcho Architecture  
**Scope:** New `Pkcs11SigningProvider` implementation alongside `ZeroEchoLibSigningProvider` and `RemoteSigningProvider`.

---

## 1. Existing Signing Architecture

### SPI contract

`SigningProvider` (`zeroecho.pki.spi.crypto`) is a stateless execution boundary
with three entry points: `dispatch`, `reconcile`, and `cancel`. A `dispatch` call
receives a durably-claimed `SignRequest` and must produce a signature exactly once.
The provider never touches orchestration state; the PKI engine owns that.

`SigningProviderFactory` extends `ConfigurableProvider<SigningProvider>` and is
discovered via `ServiceLoader`. Each factory carries a stable `id()` string that
appears in `ProviderConfig.backendId`. Configuration is passed as a string-property
map (`ProviderConfig`); sensitive values must never be logged.

### Current implementations

| Factory id | Class | Key material |
|---|---|---|
| `zeroecho-lib` | `ZeroEchoLibSigningProvider` | `KeyringStore` on local disk |
| `zeroecho-remote` | `RemoteSigningProvider` | stays on the remote signing service |

`ZeroEchoLibSigningProvider` opens a `KeyringStore` (PKCS#12-like container) and
performs cryptographic operations in-process using the zeroecho.lib JCA wrappers.
`RemoteSigningProvider` delegates via `RemoteSigningTransport` (mTLS-HTTPS by
default) and never touches private key material.

### Per-CA routing

Each CA authority is configured with one provider id. At session startup the PKI
engine resolves the matching `SigningProviderFactory` from the `ServiceLoader` list
and allocates a `SigningProvider` via `allocate(ProviderConfig, SigningProviderRuntimeDependencies)`.
The record namespace in the signing store encodes `storeNamespace + "." + providerId`,
tying every operation record permanently to the provider that dispatched it (used
by `reconcile` and `cancel`).

---

## 2. FIPS 140-3 Implications

FIPS 140-3 Level 3 requires that private key material never leave the hardware
boundary in plaintext. This translates to two constraints:

**Key generation:** Keys must be generated on the HSM with `CKA_EXTRACTABLE = false`
and `CKA_SENSITIVE = true` set at creation time. No software key-generation path
is permitted.

**Cryptographic operations:** Every sign operation must execute on the HSM.
`Signature.initSign` must receive a JCA `PrivateKey` reference obtained from
SunPKCS11; in FIPS mode, `getEncoded()` on such a key returns `null` because the
JCA wrapper does not export key bytes. Code must not call `getEncoded()` on HSM
keys.

**ContentSigner contract:** The existing `Pkix.signer(privateKey, algorithm)` path
calls the JCA `Signature` API, which delegates to the SunPKCS11 provider when
the `PrivateKey` reference originates there. This is transparent and requires no
change to the `zeroecho.pkix` facade, because the facade already calls
`Signature.getInstance(algorithm)` without extracting key bytes.

**Algorithm restrictions:** FIPS 140-3 disallows some algorithms on validated
modules. The provider must declare only the algorithms approved by the target HSM's
FIPS module. Ed25519 and Ed448 are not universally supported by all FIPS 140-3
tokens; the configuration must enumerate which algorithms a specific HSM slot
actually supports.

---

## 3. Module Placement

### Options evaluated

**Option A — inside `pki` module**  
The existing `ZeroEchoLibSigningProvider` lives in `zeroecho.pki.impl.crypto.zeroecholib`.
Placing `Pkcs11SigningProvider` in `zeroecho.pki.impl.crypto.pkcs11` follows that
convention exactly, requires no new module, and needs no changes to
`module-info.java` exports.

**Option B — new `pkcs11` module**  
A separate module (`requires zeroecho.lib; requires zeroecho.pki;`) provides
cleaner isolation and allows the HSM dependency to be optional at the module level.
However, it adds Gradle subproject boilerplate and a new module-info, while the
actual isolation gain is minimal (SunPKCS11 is a JDK built-in, not an external
jar).

**Option C — inside `lib` module**  
`lib` is the generic crypto foundation. PKCS#11 key management (generate on HSM,
list slots, bind to CA) is PKI-specific lifecycle, not generic cryptography.
Placing it in `lib` would violate the module's responsibility boundary.

### Recommendation: Option A

Place `Pkcs11SigningProvider` and `Pkcs11SigningProviderFactory` in:
```
pki/src/main/java/zeroecho/pki/impl/crypto/pkcs11/
```

This follows the identical pattern used by the remote and local providers, requires
no new module, and allows `module-info.java` in `zeroecho.pki` to add one `provides`
line. SunPKCS11 (`java.security.Provider`) is part of the JDK and requires no new
dependency declaration.

The `module-info.java` change:
```java
provides zeroecho.pki.spi.crypto.SigningProviderFactory
        with zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSigningProviderFactory,
             zeroecho.pki.impl.crypto.pkcs11.Pkcs11SigningProviderFactory;  // new
```

---

## 4. SPI Design

### `Pkcs11SigningProviderFactory`

```java
package zeroecho.pki.impl.crypto.pkcs11;

public final class Pkcs11SigningProviderFactory implements SigningProviderFactory {

    @Override
    public String id() { return "pkcs11"; }

    @Override
    public Set<String> supportedKeys() {
        return Set.of("pkcs11ConfigFile", "pinVariable", "slot",
                "keyLabelPattern", "keyRefPrefix", "operationHorizon",
                "supportedAlgorithms");
    }

    @Override
    public void validateConfig(ProviderConfig config) {
        SigningProviderFactory.super.validateConfig(config);
        config.require("pkcs11ConfigFile");
        config.require("pinVariable");
        // slot defaults to 0, keyLabelPattern defaults to "zeroecho-{authorityId}"
    }

    @Override
    public SigningProvider allocate(ProviderConfig config) {
        validateConfig(config);
        // Read PIN from environment, not from config
        String pinVariable = config.require("pinVariable");
        char[] pin = readPin(pinVariable);           // zeroed after login
        Path cfgFile = Path.of(config.require("pkcs11ConfigFile"));
        int slot = Integer.parseInt(config.get("slot").orElse("0"));
        // ...
        return new Pkcs11SigningProvider(id(), provider, slot, pin, config);
    }
}
```

**PIN is read from the environment variable named by `pinVariable`, never from the config value itself.** This keeps the plaintext PIN out of config files, process listings, and log output.

### `Pkcs11SigningProvider`

Implements `SigningProvider`. The `dispatch` method:

1. Calls `control.requireActive(Instant.now())`.
2. Acquires a PKCS#11 `KeyStore` session from the pool.
3. Finds the `PrivateKey` by label matching `request.keyRef().value()`.
4. Calls the zeroecho.pkix JCA signing path (which calls `Signature.initSign`).
5. Returns `OperationObservation` with `ObservationState.SUCCEEDED` and the raw signature bytes.
6. Local providers complete inline; `reconcile` returns `UNRECOVERABLE` if called after a restart (idempotency guarantee: no re-execution).

### Configuration in server config

```yaml
signingProviders:
  - id: hsm-primary
    type: pkcs11
    pkcs11ConfigFile: /etc/zeroecho/hsm.cfg
    pinVariable: ZEROECHO_HSM_PIN
    slot: 0
    keyLabelPattern: "zeroecho-{authorityId}"
    supportedAlgorithms: "ECDSA-SHA256,ECDSA-SHA384,RSA-PSS-SHA256"
```

Per-CA binding in authority configuration:

```yaml
authorities:
  - id: root-ca
    signingProviderId: hsm-primary
    keyRef: "zeroecho-root-ca"
```

The `keyRef` is the PKCS#11 CKA_LABEL of the private key object on the HSM.

---

## 5. Key Management Operations

HSM key lifecycle requires new admin API operations. These integrate with the
existing admin HTTPS contract (already at 99 descriptors) as HIGH_RISK operations.

| Operation ID | Action | Resource Type | HIGH_RISK | Description |
|---|---|---|---|---|
| `hsm.key.generate` | `EXECUTE` | `HSM_KEY` | ✓ | Generate a new key pair on the HSM slot |
| `hsm.key.list` | `READ` | `HSM_KEY` | — | List key objects on a configured HSM provider |
| `hsm.key.bind` | `UPDATE` | `CA` | ✓ | Bind an existing HSM key label to a CA authority |
| `hsm.key.rotate` | `EXECUTE` | `HSM_KEY` | ✓ | Generate a new HSM key and update CA binding atomically |

### Integration with `ca.create`

When `ca.create` is invoked for an authority whose `signingProviderId` refers to a
`pkcs11` provider, the CA creation workflow calls `hsm.key.generate` implicitly
(unless `keyRef` is already specified, which means the key pre-exists on the HSM).
If `keyRef` is specified but the key does not exist, `ca.create` fails with
`KEY_NOT_FOUND`.

### `hsm.key.rotate` and `ca.rotate`

`ca.rotate` (CA key rotation) has an HSM-aware path:

1. Call `hsm.key.generate` to produce a new key pair with a new label on the HSM.
2. Issue the new CA certificate signed by the new HSM key.
3. Update the authority's `keyRef` in the store (atomic, fenced by the store revision).
4. Retire (optionally delete) the old HSM key after the rollover window.

The old key is not deleted immediately; it remains valid during the rollover period
for verifying signatures on certificates issued before rotation.

---

## 6. ContentSigner Bridge

### JCA transparency

The existing `Pkix.signer(PrivateKey, algorithmId)` facade calls:

```java
Signature sig = Signature.getInstance(algorithmId);
sig.initSign(privateKey);         // delegates to SunPKCS11 for HSM keys
sig.update(contentBytes);
byte[] signature = sig.sign();    // operation executes on HSM
```

When `privateKey` is a SunPKCS11 reference, the JCA routes `initSign` to the
PKCS#11 token transparently. No change to `zeroecho.pkix` is required.

### Non-extractable key handling

A SunPKCS11 `PrivateKey` in FIPS mode returns `null` from `getEncoded()`. Any code
path that calls `getEncoded()` on a key obtained from the HSM KeyStore will fail.
The provider must ensure that:

- `keyRef` resolution returns only the `PrivateKey` reference (not the encoded bytes).
- The `Pkix.signer` call uses the reference, not a re-encoded key.
- No diagnostic or audit code serializes the private key object.

### Algorithm identifiers

| Algorithm | JCA name | PKCS#11 mechanism | Notes |
|---|---|---|---|
| ECDSA-SHA256 | `SHA256withECDSA` | `CKM_ECDSA_SHA256` | universally supported |
| ECDSA-SHA384 | `SHA384withECDSA` | `CKM_ECDSA_SHA384` | universally supported |
| ECDSA-SHA512 | `SHA512withECDSA` | `CKM_ECDSA_SHA512` | universally supported |
| RSA-PSS-SHA256 | `RSASSA-PSS` + params | `CKM_RSA_PKCS_PSS` | requires JDK 11+ SunPKCS11 |
| Ed25519 | `Ed25519` | `CKM_EDDSA` | FIPS 140-3 not universal |
| Ed448 | `Ed448` | `CKM_EDDSA` | FIPS 140-3 not universal |

The `supportedAlgorithms` configuration key lists which algorithms the specific HSM
slot supports. The factory validates this list against `BootstrapAlgorithmIdentities`
and fails fast if an unsupported identifier is requested.

---

## 7. PIN Management and Security

### Reading the PIN

```java
private static char[] readPin(String variableName) {
    String value = System.getenv(variableName);
    if (value == null || value.isEmpty()) {
        throw new PkiException("HSM PIN environment variable not set: " + variableName);
    }
    char[] pin = value.toCharArray();
    // The String 'value' cannot be zeroed (immutable), but it will be GC'd.
    // The char[] is returned to the caller, which zeros it after login.
    return pin;
}
```

After `KeyStore.load(null, pin)` (PKCS#11 login), the caller zeros the `pin` array:

```java
try {
    keyStore.load(null, pin);
} finally {
    java.util.Arrays.fill(pin, '\0');
}
```

The HSM session remains logged in for the lifetime of the `Pkcs11SigningProvider`
instance. Individual signing operations do not re-authenticate.

### Session login strategy

**Once per provider instance** (not per operation) is the correct strategy for
production HSMs:

- PKCS#11 sessions are expensive to create and most tokens enforce a session limit.
- FIPS 140-3 tokens allow multiple sign operations under a single SO/User login.
- Re-reading the PIN from the environment on every operation would be wasteful and
  might fail if the environment variable is unset after startup (security hardening).

The `Pkcs11SigningProvider` holds a `KeyStore` reference opened once in the
factory's `allocate` method. The `close()` method calls `keyStore.close()` (or
the underlying PKCS#11 `C_CloseSession`).

### Session pool

For concurrent signing (multiple CA authorities or high throughput), a pool of
PKCS#11 sessions is necessary. A `KeyStore` per session is the standard SunPKCS11
approach. The pool size is configurable:

```yaml
sessionPoolSize: 4   # default: 2
```

Sessions are borrowed via a `Semaphore`; if all sessions are busy, the provider
blocks until the call deadline (checked via `control.requireActive`).

### HSM unavailability

When a network HSM is unreachable, `Signature.sign()` throws a
`ProviderException` (wrapping a `PKCS11Exception`). The provider maps this to:

```java
ObservationState.FAILED, DetailCode.CRYPTO_FAILURE
```

No retry inside the provider — the orchestration layer controls retry via `reconcile`.
For a local HSM (SoftHSM2, PCIe card), unavailability is a process-fatal condition;
the server startup health check must verify HSM connectivity before accepting traffic.

---

## 8. PKCS#11 Configuration

### SunPKCS11 library config file

SunPKCS11 reads a vendor-neutral config file that points to the PKCS#11 shared
library. The format is fixed by the JDK:

```
name = ZeroEchoHSM
library = /usr/lib/softhsm/libsofthsm2.so
slot = 0
```

For a network HSM (Thales Luna, Entrust nShield):

```
name = ZeroEchoHSM
library = /usr/lib/libCryptoki2_64.so
slot = 0
```

The file must be readable by the ZeroEcho process user and must not be world-writable.

### Provider instantiation

```java
Provider provider = Security.getProvider("SunPKCS11");
provider = provider.configure(pkcs11ConfigFile.toString());
Security.addProvider(provider);

KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
keyStore.load(null, pin);    // pin is zeroed immediately after this call
```

`Security.addProvider` is called at most once per configured HSM. If the provider
name already exists (from a previous instantiation), the existing instance is reused.
Provider registration is process-global; a `static` lock guards the registration.

### Server configuration schema

```yaml
# zeroecho-server.yaml
signingProviders:
  - id: hsm-primary
    type: pkcs11
    pkcs11ConfigFile: /etc/zeroecho/softhsm.cfg
    pinVariable: ZEROECHO_HSM_PIN          # env var name, NOT the PIN itself
    slot: 0
    keyLabelPattern: "zeroecho-{authorityId}"
    sessionPoolSize: 4
    supportedAlgorithms:
      - ECDSA-SHA256
      - ECDSA-SHA384
      - RSA-PSS-SHA256
```

---

## 9. Testing Strategy

### Unit tests (no HSM required)

- `Pkcs11SigningProviderFactory.validateConfig` rejects missing `pkcs11ConfigFile`, missing `pinVariable`, invalid algorithm names.
- `Pkcs11SigningProviderFactory.id()` returns `"pkcs11"`.
- PIN reading: null env var → `PkiException`; blank env var → `PkiException`.

### Integration tests (SoftHSM2)

SoftHSM2 is a PKCS#11 software token available on Linux/WSL:

```bash
# WSL Fedora setup
sudo dnf install -y softhsm opensc
softhsm2-util --init-token --slot 0 --label "ZeroEchoTest" \
  --so-pin 1234567890 --pin 1234567890
```

Integration test flow:

1. Initialize SoftHSM2 slot and export `ZEROECHO_HSM_PIN`.
2. Generate a P-256 key pair on SoftHSM2 via `keytool` or direct PKCS#11 API.
3. Configure `Pkcs11SigningProvider` with SoftHSM2 library path.
4. Call `dispatch` with a test `SignRequest` referencing the generated key label.
5. Verify the returned signature with the corresponding public key via `Signature.verify`.

### FIPS compliance test

```java
// Verify key is non-extractable: getEncoded() returns null for PKCS#11 PrivateKey
KeyStore ks = ... // SoftHSM2 or real HSM
PrivateKey key = (PrivateKey) ks.getKey("zeroecho-test-ca", null);
assertNull(key.getEncoded(), "HSM private key must not be exportable");
```

Note: SoftHSM2 is not FIPS-validated; this test verifies non-exportability
in PKCS#11 semantics. Actual FIPS 140-3 validation requires a certified token.

### Unavailability test

Start the provider pointing to a non-existent library path; verify the factory
throws `PkiException` with a diagnostic that does not include the PIN.

### Benchmarks

The existing `SigningOperationEvent` (JFR) already captures per-operation latency.
An HSM benchmark baseline:

- SoftHSM2 ECDSA-SHA256: typically < 1 ms (software token)
- Real HSM network latency: 2–20 ms depending on HSM vendor and network

The benchmark from the existing signing throughput work (1100/s isolated WAL) is
the acceptance floor for the routing layer; HSM throughput depends on the specific
hardware.

---

## 10. Operational Considerations

### HSM redundancy

Two models apply:

**Active-active cluster** (recommended for production): Two HSMs (Thales Luna HA,
Entrust nShield Connect clustered) present as a single logical PKCS#11 token.
SunPKCS11 sees one library endpoint and is unaware of the cluster. Failover is
transparent. ZeroEcho holds one `SigningProvider` instance per logical provider id.

**Active-passive**: Two HSM endpoints configured as two provider ids (`hsm-primary`,
`hsm-secondary`). Routing policy directs each CA to one of them; failover requires
a config update and server restart. This is operationally simpler but has downtime
during failover.

Recommendation: use the HSM vendor's HA mechanism and present a single logical
PKCS#11 library to ZeroEcho.

### Key backup and ceremony

HSM key backup is the operator's responsibility, not ZeroEcho's. The standard
approach:

1. **M-of-N key ceremony**: The HSM master backup key is split into N shares;
   M shares are required to restore (e.g. 3-of-5). ZeroEcho must document that
   operators must complete this ceremony before going to production.
2. **Cross-HSM backup**: CA private keys are encrypted by the HSM's backup key
   and stored offline or on a secondary HSM. ZeroEcho does not participate in this.
3. **Documentation**: The operator guide must include a section on HSM key backup
   that references the specific vendor's ceremony documentation.

ZeroEcho generates no key material for PKCS#11 providers in software — there is
nothing to back up from ZeroEcho's side.

### Monitoring

The existing `SigningOperationEvent` (JFR, in `pki-server`) captures every signing
dispatch with `operationId`, `authorityId`, `succeeded`, and `failureReason`. This
covers HSM operations without change.

Additional JFR event: `HsmSessionEvent` — records session borrow/return times and
pool exhaustion. This is not in scope for the initial implementation but is noted
for the implementation plan.

Key metrics operators should monitor via JFR Mission Control or JFR streaming:

- Signing latency percentiles by authority (already in `SigningOperationEvent`)
- Session pool wait time (new event)
- HSM-specific failure rate (CRYPTO_FAILURE detail code)

---

## 11. Implementation Plan

| # | Task | Complexity | Notes |
|---|---|---|---|
| 1 | `Pkcs11SigningProviderFactory` skeleton and config validation | S | Follows `RemoteSigningProviderFactory` exactly |
| 2 | PIN reading + SunPKCS11 `Provider` registration | S | One static guard; clear char[] after login |
| 3 | PKCS#11 `KeyStore` open + session lifecycle | M | Single session first, pool in step 5 |
| 4 | `Pkcs11SigningProvider.dispatch` — key lookup + JCA sign | M | Key found by label; return inline result |
| 5 | Session pool (`Semaphore` + fixed `KeyStore` array) | M | Required for concurrent CA authorities |
| 6 | `reconcile` returns `UNRECOVERABLE` after restart | S | Same pattern as ZeroEchoLibSigningProvider |
| 7 | `module-info.java` update — add `provides` line | S | One line |
| 8 | Unit tests (config validation, PIN env handling) | S | No HSM required |
| 9 | Integration test with SoftHSM2 (WSL Fedora) | M | WSL setup + SoftHSM2 init in test lifecycle |
| 10 | `hsm.key.generate` admin operation | L | New `PkiSigningOperation` subtype + executor |
| 11 | `hsm.key.list` and `hsm.key.bind` admin operations | M | Read-only + metadata update |
| 12 | `hsm.key.rotate` admin operation | L | Atomic CA binding update + old-key retire window |
| 13 | Operator documentation (admin guide section) | M | Key ceremony, PKCS#11 config, env var |
| 14 | `HsmSessionEvent` JFR event | S | Optional; defer if not needed for initial release |

**Total estimate:** Steps 1–9 are the functional core (~2–3 weeks of focused implementation).
Steps 10–12 (admin API key management) are the PKI workflow integration (~2 weeks).
Steps 13–14 are documentation and observability (1 week).

### Not in scope for initial implementation

- Multiple simultaneous PKCS#11 providers (two HSMs configured under different ids
  are supported by the routing policy already; no special implementation needed).
- HSM vendor-specific management APIs (Thales Luna Management Console, etc.) —
  those are operator tooling, not ZeroEcho scope.
- PKCS#11 v3.0 features (Dilithium, post-quantum on HSM) — deferred until HSM
  vendor support matures.

---

## Appendix: Key Reference Format

The `KeyRef` value for PKCS#11 providers uses the PKCS#11 CKA_LABEL as the key
identifier. The factory validates that the `keyRef` value matches the configured
`keyLabelPattern` (default `zeroecho-{authorityId}`) to catch misconfiguration
early, at `dispatch` validation time.

Example: authority id `root-ca` → key label `zeroecho-root-ca` → `KeyRef("zeroecho-root-ca")`.

The label scheme is operator-configurable. If an operator pre-generates HSM keys
with their own label convention, they set `keyRef` explicitly in the authority
configuration and set `keyLabelPattern` to `""` to disable the default pattern check.

---

## Appendix: SunPKCS11 JPMS Note

`SunPKCS11` is part of `jdk.crypto.cryptoki` (JDK internal module). Under JPMS it
is accessible without any `--add-opens` when using the standard `Security.getProvider`
and `KeyStore.getInstance` APIs. The `zeroecho.pki` module does not need to declare
any special module-path access. This is confirmed by the JDK specification for
`java.security.KeyStore` and `java.security.Provider`.
