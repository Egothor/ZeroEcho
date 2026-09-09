# Introduction

ZeroEcho is, first and foremost, a **cryptographic framework**: a single library
that brings classic and post‑quantum algorithms and primitives together under one
consistent API. Applications are built on that framework. The largest is a full
certificate authority, but it is one application among several — the framework
equally supports smaller utilities such as data‑hiding tools and content
protection.

Read the framework as the base and the applications as things that stand on it —
not the other way round.

## The framework (the foundation)

The library provides, through one coherent surface:

- **A unified algorithm suite** — symmetric ciphers, hashes and MACs, classic
  public‑key algorithms (RSA, elliptic‑curve, EdDSA and relatives), and
  post‑quantum families for both signatures and key establishment.
- **A working SDK** — algorithm discovery, key generation, signing and
  verification, key encapsulation, and hybrid (classic + post‑quantum)
  constructions.
- **Content protection** — authenticated encryption of arbitrary content.
- **X.509 objects** — building and parsing certificates, certification requests,
  CRLs, and OCSP messages.
- **A protected keyring** and service‑provider seams for storage, signing, and
  the underlying cryptographic provider.

Start at [The framework](../developer/index.md), and see
[Understanding the cryptography](../developer/crypto-primer.md) for how it works.

## Applications (built on the framework)

The framework is designed to carry applications of very different sizes:

- **Certificate authority** — the flagship application: a complete, API‑first CA
  for issuing and managing certificates at scale.
- **Data hiding and content protection** — smaller utilities such as
  steganography and covert channels, and content encryption, built on the same
  primitives.

These are peers. A large application and a small utility both draw on the one
framework. See the [Applications overview](../applications/index.md).

## Who should read what

| You are… | Start here |
|---|---|
| A developer building on the framework | [The framework](../developer/index.md) and [Working with cryptography](../developer/cryptography.md) |
| Curious how the cryptography works | [Understanding the cryptography](../developer/crypto-primer.md) |
| Operating the certificate authority | [Deployment](../deployment/index.md) and [Administration](../admin/index.md) |
| Requesting or managing certificates | [Using certificates](../user/index.md) |
| Integrating against the API or CLI | [Reference](../reference/admin-api.md) |

## Design principles

- **Classic and post‑quantum, unified.** Both families are first‑class across key
  generation, signing, verification, and key establishment, including hybrids.
- **One framework, many applications.** Shared primitives and SDK; applications
  layer domain logic on top without re‑implementing cryptography.
- **Secure by construction.** Where applications expose a network surface, access
  is authenticated per request and authorized server‑side; sensitive actions are
  recorded in a verifiable audit trail.
- **Lightweight and modular.** A small, modular Java codebase with minimal
  dependencies.
- **Extensible.** Storage, signing, and the cryptographic provider are
  service‑provider seams.

Continue with the [Architecture](architecture.md) to see how the pieces fit.
