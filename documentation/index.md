---
hide:
  - navigation
  - toc
---

<div class="ze-hero" markdown>

# ZeroEcho

One cryptographic framework that unifies **classic and post‑quantum** algorithms
and primitives — and the applications built on top of it.

[Explore the framework](developer/index.md){ .md-button .md-button--primary }
[Understand the cryptography](developer/crypto-primer.md){ .md-button }
[Browse applications](applications/index.md){ .md-button }

</div>

At its core, ZeroEcho is a **library**: a single, coherent framework for keys,
signatures, key establishment, hashing, content protection, and X.509 — spanning
both classic and post‑quantum algorithms. Applications are built on that
framework. A full certificate authority is the largest of them, but it is one
application among several.

## The framework

<div class="grid cards" markdown>

-   :material-hexagon-multiple-outline:{ .lg .middle } __A unified algorithm suite__

    ---

    Symmetric ciphers, hashes and MACs, classic public‑key algorithms
    (RSA, elliptic‑curve, EdDSA), and post‑quantum families (ML‑KEM, ML‑DSA,
    SLH‑DSA, and more) behind one consistent API.

    [:octicons-arrow-right-24: The library & SDK](developer/library.md)

-   :material-atom-variant:{ .lg .middle } __Classic meets post‑quantum__

    ---

    Discover algorithms, generate keys, sign, verify, and encapsulate — for
    classic and post‑quantum schemes alike, including hybrid combinations.

    [:octicons-arrow-right-24: Working with cryptography](developer/cryptography.md)

-   :material-book-open-variant:{ .lg .middle } __Understand it__

    ---

    A plain‑language primer on how the cryptography works, what it protects, and
    the risks to keep in mind.

    [:octicons-arrow-right-24: Understanding the cryptography](developer/crypto-primer.md)

-   :material-cog-transfer-outline:{ .lg .middle } __Extend it__

    ---

    Storage, signing, and the cryptographic provider are service‑provider seams,
    so the framework can be adapted and embedded.

    [:octicons-arrow-right-24: Extending the framework](developer/extending.md)

</div>

## Applications built on the framework

<div class="grid cards" markdown>

-   :material-certificate:{ .lg .middle } __Certificate authority__ · *flagship*

    ---

    A complete, API‑first certificate authority: authorities, profiles,
    issuance, revocation, CRL/OCSP, publication, ACME, role‑based access,
    approvals, and a tamper‑evident audit trail.

    [:octicons-arrow-right-24: Deploy](deployment/index.md) ·
    [Administer](admin/index.md) ·
    [Use](user/index.md)

-   :material-image-multiple-outline:{ .lg .middle } __Data hiding & content protection__

    ---

    The same framework powers smaller utilities — steganography and covert
    channels, and authenticated content encryption — as peers of the certificate
    authority.

    [:octicons-arrow-right-24: Applications overview](applications/index.md)

</div>

!!! tip "Where to start"
    Building on the cryptography? Begin with [the framework](developer/index.md).
    Running a certificate authority? Jump to the
    [certificate‑authority guides](applications/index.md).
