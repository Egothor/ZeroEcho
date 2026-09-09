# Understanding the cryptography

This page explains, at a working level, *how* the cryptography behind ZeroEcho
works — what each mechanism does, when to use it, and the risks to keep in mind.
It is background for the hands‑on [Working with cryptography](cryptography.md)
page (which shows the concrete, supported algorithms and code) and for the
[Security model](../reference/security-model.md).

!!! note "Who this is for"
    You do not need to be a cryptographer. If you are choosing algorithms for a
    certificate profile, protecting keys, or building on the library, this gives
    you the mental model to make sound decisions.

## The building blocks

### Hash functions

A hash function turns any input into a fixed‑size fingerprint. Good hashes are
one‑way (you cannot recover the input) and collision‑resistant (you cannot find
two inputs with the same fingerprint). Signatures and certificates hash the data
first, then sign the hash.

!!! warning "Deprecated hashes"
    Older hashes such as MD5 and SHA‑1 are broken for security use — collisions
    are practical. Use SHA‑256 or stronger. Certificate and signature algorithms
    in modern profiles pair keys with a strong hash for exactly this reason.

### Symmetric vs. asymmetric

- **Symmetric** cryptography uses one shared secret for both sides (fast; used
  for bulk encryption). Distributing that secret safely is the hard part.
- **Asymmetric** (public‑key) cryptography uses a *key pair*: a private key kept
  secret and a public key shared freely. This is what makes certificates, digital
  signatures, and key establishment possible, and it is the focus here.

### Digital signatures

A signature is produced with a **private** key and verified with the matching
**public** key. A valid signature demonstrates:

- **Integrity** — the data was not altered.
- **Authenticity** — it came from the holder of the private key.
- **Non‑repudiation** — the signer cannot plausibly deny it.

A certificate authority *is* a signing service: it signs certificates, CRLs, and
OCSP responses.

!!! danger "The private key is everything"
    Anyone who obtains a private key can impersonate its owner and forge
    signatures. Protecting private keys — in ZeroEcho, the [keyring](library.md)
    or an external signer — is the single most important operational control.

### Key establishment and KEMs

To set up a shared secret over an untrusted channel, parties use key
establishment. A **KEM** (key‑encapsulation mechanism) is the modern form: one
side encapsulates a fresh secret to the other's public key. A KEM establishes
secrets — it does **not** produce signatures. This distinction matters when
choosing post‑quantum algorithms (below).

### Certificates and chains of trust

A certificate binds an identity to a public key, signed by an authority. Trust
flows along a **chain**: a leaf certificate is signed by an intermediate
authority, which is signed by a root, which a relying party already trusts. A
certificate is only trustworthy if the whole chain verifies **and** none of it is
expired or revoked — see [Revocation and status](../admin/revocation-and-status.md).

## Classic algorithms

| Family | Use | Notes and risks |
|---|---|---|
| **RSA** | Signatures, encryption | Well understood. Security depends on key size — use 3072‑bit or larger for new keys; 1024‑bit is broken. Large keys are slow. |
| **ECDSA** | Signatures | Small, fast keys on named curves (e.g. P‑256/P‑384). Correctness depends on a unique random value per signature; reuse or bias leaks the private key. The library handles this for you — do not hand‑roll it. |
| **EdDSA** (Ed25519) | Signatures | Modern, fast, deterministic (no risky per‑signature randomness), with strong defaults. A good first choice where supported. |

!!! info "These are safe today — but not forever"
    Classic public‑key algorithms rely on problems (factoring, discrete logs)
    that a large quantum computer could solve. That is what post‑quantum
    cryptography addresses.

## The quantum threat and post‑quantum cryptography

A sufficiently powerful quantum computer running Shor's algorithm would break
RSA and elliptic‑curve cryptography. Two consequences drive adoption now:

- **Harvest‑now, decrypt‑later.** Encrypted data captured today could be
  decrypted once such a machine exists — so confidentiality with long secrecy
  needs post‑quantum key establishment *now*.
- **Long‑lived trust.** Certificates and signatures that must remain valid for
  many years need post‑quantum signatures to stay trustworthy.

**Post‑quantum cryptography (PQC)** uses problems believed to resist quantum
attack. The standardized families are:

| Family | Role | Character |
|---|---|---|
| **ML‑KEM** (Kyber) | Key establishment (KEM) | Establishes shared secrets; not a signature scheme. |
| **ML‑DSA** (Dilithium) | Signatures | General‑purpose PQC signatures; larger keys/signatures than classic. |
| **SLH‑DSA** (SPHINCS+) | Signatures | Hash‑based; conservative security, larger/slower signatures; **stateless**. |
| **FN‑DSA** (Falcon) | Signatures | Compact signatures, more complex to implement. |

!!! tip "Trade‑offs are the point"
    PQC generally means larger keys and signatures and different performance
    profiles. When you select a post‑quantum algorithm in a certificate profile,
    account for the larger certificate size and verification cost in whatever will
    consume the certificates.

### Stateful hash‑based signatures

Some hash‑based signature schemes (such as **LMS** and **XMSS**) are *stateful*:
each private key can sign only a limited number of times, and the signer **must**
advance and persist its state after every signature.

!!! danger "One‑time keys must never be reused"
    Reusing a stateful one‑time key — for example by restoring an old backup of
    the key state — can catastrophically break the scheme and expose forgeries.
    Only use stateful schemes with storage that reliably preserves state, and
    never clone or roll back that state. When in doubt, prefer a stateless
    signature scheme.

### Hybrid and composite approaches

During the transition, it is common to combine a classic and a post‑quantum
algorithm so that the result stays secure as long as **either** remains
unbroken. Designing for **algorithm agility** — the ability to change algorithms
without re‑architecting — is the durable strategy; certificate profiles and the
library's provider seam exist to make that practical.

## Choosing an algorithm

| Your goal | Reasonable choices |
|---|---|
| Signatures, broad compatibility today | ECDSA (P‑256/P‑384) or Ed25519; RSA‑3072 where required |
| Signatures, post‑quantum assurance | ML‑DSA, or SLH‑DSA for a conservative hash‑based option |
| Long‑term confidentiality / key establishment | ML‑KEM (optionally hybrid with a classic KEM) |
| Maximum caution, willing to manage state | A stateful hash‑based scheme — with the state discipline above |

The authoritative list of what this platform actually supports, with runnable
examples, is on the [Working with cryptography](cryptography.md) page.

## How this maps to ZeroEcho

- **Certificate profiles** pin the algorithms an authority uses, so policy is
  enforced consistently at issuance — see
  [Profiles and issuance](../admin/profiles-and-issuance.md).
- **The keyring** protects authority private keys at rest; signing can also be
  delegated to an external signer so keys never leave a hardware boundary — see
  [Extending the platform](extending.md).
- **The library** exposes classic and post‑quantum algorithms through one API and
  confines the underlying provider behind a service seam, which is what makes
  algorithm agility achievable.

## Risk checklist

- Protect private keys above all; prefer an external signer for high‑value CAs.
- Use current algorithms and parameters; avoid deprecated hashes and undersized
  keys.
- Plan for rotation and algorithm change before you need them.
- Consider post‑quantum or hybrid algorithms for anything long‑lived.
- Treat stateful hash‑based keys with extreme care, or avoid them.
- Remember that a valid signature only means the key was used — revocation and
  expiry still decide whether a certificate should be *trusted*.
