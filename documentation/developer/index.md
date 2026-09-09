# The framework

The framework is the foundation of ZeroEcho: a single library that unifies
classic and post‑quantum cryptography behind one consistent API, together with an
SDK for building cryptographic applications. Everything else — including the
certificate authority — is an application layered on this base.

## What the framework provides

<div class="grid cards" markdown>

-   __A unified algorithm suite__

    Symmetric ciphers (AES, ChaCha), hashes and MACs, classic public‑key
    algorithms (RSA, elliptic‑curve, EdDSA and relatives), and post‑quantum
    families for signatures (ML‑DSA, SLH‑DSA, SPHINCS+) and key establishment
    (ML‑KEM and other KEMs) — all reachable through one API.

-   __An application SDK__

    Algorithm discovery, key generation, streaming sign/verify, key
    encapsulation, hybrid classic + post‑quantum constructions, and authenticated
    content protection.

-   __X.509 building blocks__

    A JCA‑aligned API for constructing and parsing certificates, certification
    requests, CRLs, and OCSP messages.

-   __Keys and extension seams__

    A protected keyring for private keys, and service‑provider seams for storage,
    signing, and the underlying cryptographic provider.

</div>

## Read this section in order

1. [Architecture](../overview/architecture.md) — how the framework and the
   applications on it fit together.
2. [Modules](modules.md) — the module map and dependencies.
3. [The library & SDK](library.md) — the public API, with examples.
4. [Understanding the cryptography](crypto-primer.md) — how the cryptography
   works, and the risks.
5. [Working with cryptography](cryptography.md) — hands‑on classic and
   post‑quantum recipes.
6. [Extending the framework](extending.md) — implement and register providers.

## Where to start by goal

=== "Build on the cryptography"

    Add the library as a dependency and use the SDK and the `zeroecho.pkix` API
    directly. Begin with [The library & SDK](library.md) and
    [Working with cryptography](cryptography.md).

=== "Run the certificate authority"

    Deploy and operate the flagship application built on the framework. Begin with
    [Deployment](../deployment/index.md) and [Administration](../admin/index.md).

=== "Extend or embed"

    Swap the persistence backend, delegate signing to an external signer, or plug
    in a provider. Begin with [Extending the framework](extending.md).

The framework carries applications of any size — see the
[Applications overview](../applications/index.md) for what is built on it.

## Source quality gates

Java changes must keep the module compilation, PMD, and strict Javadoc gates
green. Public and protected APIs document parameter constraints and units,
return semantics, exact exception conditions, and relevant lifecycle,
thread-safety, or persistence effects. Source files retain the complete project
license header and use LF line endings.

Run `./gradlew compileJava pmdMain javadoc` before submitting a Java change.
Module-qualified tasks such as `:pki-server:javadoc` provide a faster feedback
loop while editing.
