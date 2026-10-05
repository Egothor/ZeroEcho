# Extending the platform

The platform is designed to be extended at well-defined seams rather than by
patching the code above them. Backends for persistence, signing, publication, and
the cryptographic toolkit are all reached through service-provider interfaces
(SPIs) and discovered with `java.util.ServiceLoader`. This page describes the main
extension points, the contract each implementation must honour, and how to
register a provider.

## The provider model

Most PKI backends share a common provider shape,
`zeroecho.pki.spi.ConfigurableProvider<T>`:

```java
public interface ConfigurableProvider<T> {
    String id();                          // stable backend id, e.g. "fs"
    Set<String> supportedKeys();          // informational config keys
    default void validateConfig(ProviderConfig config) { /* backend-id check */ }
    T allocate(ProviderConfig config);    // build the configured instance
}
```

The rules every configurable provider must follow:

- **`ServiceLoader`-instantiable.** Provide a public no-arg constructor. The
  provider factory itself carries no state; the configured product is built by
  `allocate`.
- **Stable identity.** `id()` must be unique among providers of the same service
  type and must not change across releases once published — it is how a backend
  is selected deterministically.
- **Validate, then fail fast.** Reject missing or malformed configuration with
  `IllegalArgumentException`. Ignore unknown keys for forward compatibility.
- **Never log secrets.** Configuration values may contain passwords, tokens, or
  endpoints. Log the provider id and configuration *keys* only, never values.

Registration is standard JPMS service declaration. In your module descriptor:

```java
module com.example.pki.backend {
    requires zeroecho.pki;
    provides zeroecho.pki.spi.store.PkiStoreProvider
            with com.example.pki.backend.MyPkiStoreProvider;
}
```

The consuming module already declares the matching `uses` clause (for example
`uses zeroecho.pki.spi.store.PkiStoreProvider;` in `module zeroecho.pki`), so a
provider on the module path is discovered automatically. Where a backend must be
chosen explicitly, selection is by provider `id()`.

## The persistence backend

The persistence seam has two layers.

### `PkiStore` / `PkiStoreProvider`

`zeroecho.pki.spi.store.PkiStore` is the durable boundary for PKI state — CA
records, issuer generations and chain paths, credentials, certification requests,
revocations, status objects, profiles, publications, workflow continuation state,
and policy traces. `zeroecho.pki.spi.store.PkiStoreProvider` is its
`ConfigurableProvider`.

A backend may be a filesystem, a database, or any other store, but it must uphold
the documented contract:

- **Atomicity and determinism.** Record writes must be atomic — a replacement is
  either fully visible or not visible at all — and behaviour must be
  deterministic and suitable for backup/restore.
- **Unchecked, safe failures.** The SPI uses unchecked failures; throw
  `IllegalStateException` when an operation cannot be completed safely.
- **Publication-recovery ownership.** Before an instance is exposed to callers it
  must hold exclusive publication-runtime ownership and validate the complete
  publication namespace in one stable view, reclassifying any abandoned
  `DISPATCH_PREPARED` operation to `OUTCOME_UNKNOWN` **without** invoking a
  publisher. A backend that supports simultaneous runtimes must provide durable
  session or lease fencing with equivalent safety.
- **No secrets at rest in the clear, none in logs.** Private key material must not
  be persisted by the store; sensitive fields must never reach logs or exception
  messages.

`PkiStoreProvider.allocate(ProviderConfig)` opens the store; an overload accepts
explicit process-local `PkiStoreRuntimeDependencies` for backends that need
runtime capabilities beyond textual configuration. The default filesystem backend
is `zeroecho.pki.impl.fs.FilesystemPkiStoreProvider` (id `fs`).

### `TransactionalMetadataStore`

Underneath the domain store sits
`zeroecho.pki.spi.store.TransactionalMetadataStore`, a provider-neutral authority
for finite transactional control metadata. It supports atomic mutations across
namespaces, retained commit outcomes, stable snapshots, and streaming iteration —
and it deliberately holds no aggregate certificate, CRL, or staged-content
payloads and exposes no filesystem, database, or PKI-domain concepts. Its
outcome model is fail-closed: a `resolve` result of `UNKNOWN` implies neither
commit nor rollback and must be resolved through the owning store; an unissued
transaction identity fails closed rather than being read as `NOT_COMMITTED`.

!!! tip "Conformance harness"

    A reusable contract test suite,
    `zeroecho.pki.spi.store.TransactionalMetadataStoreContractTest`, exercises the
    transactional-metadata authority contract (atomic commit, retained outcomes,
    snapshot stability, streaming). Run a new metadata-store implementation
    against it before wiring it into a store backend.

## The remote signing transport seam

Signing keys do not have to live in-process. `zeroecho.pki.spi.crypto.remote.RemoteSigningTransport`
is a technology-neutral wire seam between the PKI's remote signature workflow and
an external signing service. The transport is the only contract an external
signer must speak; a concrete transport (for example authenticated HTTPS) maps
the calls onto the wire, so the remote side stays fully pluggable — including
services that gate each signature behind an external, typically human, approval.

The core operations:

```java
public interface RemoteSigningTransport extends AutoCloseable {
    RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control);
    RemoteSigningStatus status(String operationId, RemoteCallControl control);
    boolean cancel(String operationId, long fencingToken, String reason, RemoteCallControl control);
    byte[] publicKeyInfo(String keyHandle, RemoteCallControl control);
    RemoteCapabilities capabilities();
    // optional push notifications via supportsCallbacks()/subscribe(...)
}
```

The contract an implementation must honour:

- **Key confinement.** A transport carries only an opaque `keyHandle`, the
  algorithm identity, the exact bytes to sign, and the resulting signature or a
  canonical `SubjectPublicKeyInfo`. It must never transport, and the remote
  service must never return, private key material.
- **Authoritative, idempotent remote state.** The remote service is the authority
  on whether a signature occurred. States are `QUEUED` (non-terminal, awaiting the
  service's decision), `SIGNED`, `DENIED`, and `CANCELLED`. `submit` must be
  idempotent on `(submissionId, semanticFingerprint, fencingToken)`.
- **No blind re-submission.** Any delivery uncertainty (timeout, reset, ambiguous
  response) must be raised as `RemoteSigningException`; the caller reconciles by
  polling `status`, never by re-submitting.
- **No secrets in diagnostics.** Exception messages must not contain secrets, key
  material, or payload bytes.

On the PKI side this integrates through
`zeroecho.pki.spi.crypto.SignatureWorkflowProvider`, a `ConfigurableProvider`
whose runtime dependencies (such as a keyring unlock provider) are supplied
explicitly rather than through textual configuration. The default in-process
signer is `ZeroEchoLibSignatureWorkflowProvider`.

## Publishers

`zeroecho.pki.spi.publish.PublisherProvider` (a `ConfigurableProvider<Publisher>`)
supplies explicitly configured publication destinations for issued artifacts and
status objects. A `Publisher` performs an attempt and reports a
`PublicationOutcome`. Because the store owns publication-recovery classification
(see above), a publisher must be safe to re-drive: publication is coordinated by
the store's prepared/outcome model, and a publisher must not be invoked during
store allocation. The default backend is
`zeroecho.pki.impl.publish.FilesystemPublisherProvider`.

## Algorithm bindings

`zeroecho.pki.spi.algorithm.X509AlgorithmBindingProvider` contributes
deployer-owned, immutable X.509 algorithm bindings and role-specific encoding
rules. Its contract is unusually strict because it governs how algorithms are
encoded into certificates:

- **Discovery does not activate.** Being on the module path is not enough; a
  session must explicitly enable the provider by `providerId()` and authorize
  every contributed OID root.
- **Stateless and secret-free.** Implementations must be stateless and must not
  contain secrets.
- **Immutable, versioned sets.** `bindings()` and `rules()` return finite,
  immutable descriptors, and `bindingSetVersion()` is a stable version or
  commitment of the complete contributed set.

## The cryptographic provider seam

At the very bottom, the concrete cryptographic toolkit is confined to `lib`
behind `zeroecho.pkix.spi.PkixProvider`. This is what makes the toolkit an
implementation detail: `PkixProvider` supplies the concrete certificate, CSR,
CRL, and OCSP builders and parsers plus the signing and verification operators
that back the `zeroecho.pkix.Pkix` facade.

Resolution order, performed once by `Pkix`:

1. a `PkixProvider` published via `ServiceLoader`, if any;
2. otherwise the class named by the `zeroecho.pkix.provider` system property;
3. otherwise the built-in provider.

A JDK-only or in-house `PkixProvider` can therefore replace the default without
any change to the public `zeroecho.pkix` API or to code in `pki`, `pki-server`,
`ext`, or `app`. An implementation must:

- return a stable `id()` for diagnostics and selection;
- implement every builder, parser, and signing/verification method in terms of
  standard `java.security` types, honouring exact DER where the contract requires
  it (for example preserving `SubjectPublicKeyInfo` bytes and algorithm
  parameters); and
- be safe to resolve once and share, since the facade caches the resolved
  provider for the lifetime of the process.

!!! note "Confinement is a property, not a workaround"

    The confinement of the cryptographic toolkit inside `lib` is an architectural
    property enforced at the module boundary: the toolkit is required
    non-transitively and only the internal, non-exported implementation package
    reads it. Extending the platform with a different provider is a supported
    operation through this seam — not a modification of the modules above `lib`.

## Related SPIs

Beyond the seams above, `zeroecho.pki.spi` also defines audit sinks
(`AuditSinkProvider` — filesystem, in-memory, and stdout defaults), an async bus
(`AsyncBusProvider`), a credential framework (`CredentialFrameworkProvider`), and
key-possession-proof confirmation providers. The server module adds its own SPIs
for ACME challenges and TLS/trust through the exported
`zeroecho.pki.server.spi.v2` package:

- `AcmeChallengeProvider` validates a bounded challenge attempt. Its nested
  identifier, challenge type, context and result types are the public boundary.
- `AcmeExternalAccountBindingProvider` verifies external account binding without
  exposing HMAC keys. Requests defensively copy the bounded nested JWS.
- `PkiServerTlsProvider` creates an initialized JSSE `SSLContext`.
- `PkiServerClientTrustProvider` creates an administrative-client `X509TrustManager`.

Named-module providers declare `requires zeroecho.pki.server` and a `provides`
directive for each implemented interface. Providers using core types directly
also declare `requires zeroecho.lib`. Classpath providers publish the corresponding
`META-INF/services/zeroecho.pki.server.spi.v2.<Interface>` resource. Every provider
needs a public no-argument constructor. Discovery alone does not activate a
provider: its exact, nonblank `id()` must be selected in server configuration.
Duplicate IDs across the new and legacy provider families are rejected before
selection; a failed selected provider never falls back to another provider.

The original unexported `zeroecho.pki.server.spi` interfaces and their DTOs remain
available for existing classpath provider binaries. New providers should use
`spi.v2`; no command-line exports of server implementation packages are required.
Internal adapters preserve complete challenge timing, attempt and cancellation
inputs, and the server still validates provider results before authorizing or
persisting evidence. Contexts and protocol material must never be logged.

The existing exported `zeroecho.pki.server.ct.CtLogClient` remains an explicitly
composed CT client contract, rather than a ServiceLoader discovery contract.
Server authentication is an internal composition boundary; it is not a public
pluggable provider SPI. The external named-module regression fixture implements
all four provider interfaces and the CT client without `--add-exports`.

Run `:pki-server:test --tests '*ServerSpiCompatibilityTest'` to check module
compilation, service discovery, actual configured selection and legacy source
compatibility. To additionally compile the legacy fixture against an earlier
server binary and run that bytecode against the current server, pass
`-PserverSpiLegacyBaseline=/absolute/path/to/earlier-pki-server.jar`.
