# Applications

Applications are built **on** the [framework](../developer/index.md). They add
domain logic and interfaces, but they do not re‑implement cryptography — they
draw on the shared algorithm suite, SDK, and primitives.

They differ enormously in size. One is a full platform; others are focused
utilities. They are peers: each is an application of the same framework.

## The certificate authority (flagship)

The largest application is a complete, API‑first **certificate authority** —
issuing and managing X.509 certificates at scale, with authorities and issuer
generations, certificate profiles, requests and issuance, revocation and status
objects (CRL, delta CRL, OCSP), publication, ACME automation, role‑based access
control, approvals, break‑glass, and a verifiable audit trail. It comprises the
PKI domain and persistence, an HTTP server, a command‑line client, and a web
console.

Guides:

- [Concepts](../overview/concepts.md) — the vocabulary of the certificate authority.
- [Deployment](../deployment/index.md) — install and run it in containers.
- [Administration](../admin/index.md) — operate authorities, issuance, and access.
- [Using certificates](../user/index.md) — request and manage certificates.

## Focused utilities

The same framework is well suited to smaller, single‑purpose tools that build
directly on its primitives — for example:

- **Steganography and covert channels** — hiding data within other media (such as
  least‑significant‑bit image steganography and image‑based covert channels).
- **Content protection** — authenticated encryption and packaging of arbitrary
  content, including post‑quantum key establishment for the content key.
- **Key‑management tooling** — generating, storing, and using keys through the
  protected keyring and the SDK.

These utilities are peers of the certificate authority: much smaller in scope,
but built on the same foundation. If you are creating one, the
[framework guide](../developer/index.md) and
[Working with cryptography](../developer/cryptography.md) are the place to start.

!!! note "One framework, many shapes"
    Whether an application issues millions of certificates or hides a few bytes in
    an image, it uses the same underlying cryptography. That shared foundation —
    classic and post‑quantum, under one API — is the point of ZeroEcho.
