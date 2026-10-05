# Hybrid key exchange

The `zeroecho.sdk.hybrid.kex` package provides hybrid key exchange (KEX): a
single handshake that combines a classic (pre-quantum) agreement with a
post-quantum KEM-style agreement. The two shared secrets are combined using
HKDF-SHA256 to produce a single keying material byte sequence.

This API complements the hybrid signature support documented in
[Cryptography](cryptography.md). Where hybrid signatures protect integrity,
hybrid KEX protects confidentiality by establishing shared secrets that are
secure against both classical and quantum adversaries.

## Design

### Two-leg model

| Leg | Algorithm examples | Semantics |
| --- | --- | --- |
| Classic | X25519, ECDH, DH | Peer public key provided out-of-band; no explicit wire message. |
| Post-quantum | ML-KEM (via `KeyUsage.AGREEMENT`) | Message-based: initiator produces KEM ciphertext; responder consumes it. |

The initiator calls `HybridKexContexts.initiator(…)`, which:

1. Creates an `AgreementContext` for the classic leg and binds the peer's classic public key.
2. Creates a `MessageAgreementContext` for the PQC leg and encapsulates against the peer's PQC public key.

The responder calls `HybridKexContexts.responder(…)`, which:

1. Creates a classic `AgreementContext` from the responder's private key and the peer's classic public key.
2. Creates a PQC `MessageAgreementContext` in decapsulation mode.

### HKDF binding

`HybridKexProfile` controls the final key derivation step. It holds an optional
HKDF salt, an optional info/label, and the desired output length in bytes. A
default label (`"ZeroEcho-HybridKEX"`) is used when no explicit info is supplied
so that key material is domain-separated from other protocol uses.

The two leg secrets are concatenated as `classicSecret || pqcSecret` and passed
as HKDF input keying material. The profile's salt and info are forwarded to
HKDF-SHA256. The result is the final shared secret of `outLenBytes` bytes.

## API overview

### `HybridKexContexts` — factory

| Method | Description |
| --- | --- |
| `HybridKexContexts.initiator(session, profile, classicAlgId, initPriv, peerClassicPub, classicSpec, pqcAlgId, peerPqcPub, pqcSpec)` | Build an initiator context. |
| `HybridKexContexts.responder(session, profile, classicAlgId, respPriv, peerClassicPub, classicSpec, pqcAlgId, respPqcPriv, pqcSpec)` | Build a responder context. |

### `HybridKexContext` — context

`HybridKexContext` implements `AutoCloseable` and holds both legs until the shared
secret is derived.

| Method | Description |
| --- | --- |
| `getPeerMessage()` | (Initiator) Returns the hybrid peer message to send to the responder. The PQC part carries the KEM ciphertext; the classic part is empty for standard DH-style classic algorithms. |
| `setPeerMessage(byte[])` | (Responder) Consumes the initiator's hybrid peer message. |
| `setPeerPublic(PublicKey)` | (Responder) Provides the initiator's classic public key when it is not available at construction time. |
| `deriveSecret()` | Derives and returns the final shared secret (a `byte[]`). Call once; the context is closed automatically. |

### `HybridKexProfile` — record

| Constructor parameter | Description |
| --- | --- |
| `hkdfSalt` | Optional HKDF salt bytes; `null` uses the zero-filled default (RFC 5869). |
| `hkdfInfo` | Optional HKDF info label; `null` uses the default domain separator. |
| `outLenBytes` | Output length in bytes (1..8160). |

Convenience factory: `HybridKexProfile.defaultProfile(outLenBytes)` creates a profile with
the default domain-separator label (`"ZeroEcho-HybridKEX"`) and no explicit salt.

### `HybridKexExporter` — key schedule

`HybridKexExporter` derives multiple independent sub-keys from a single root
secret (typically the output of `HybridKexContext.deriveSecret()`). Each export
call takes a label and an optional context binding.

| Method | Description |
| --- | --- |
| `HybridKexExporter(rootSecret, salt)` | Seed the exporter. |
| `export(label, outputLen)` | Derive `outputLen` bytes bound to `label`. |
| `export(label, context, outputLen)` | Derive bytes bound to both `label` and a transcript/context. |
| `close()` | Zero the root secret. |

Use distinct labels per purpose: `"app/tx"`, `"app/rx"`, `"confirm"`, and so on.

## Example

```java
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.hybrid.kex.HybridKexContext;
import zeroecho.sdk.hybrid.kex.HybridKexContexts;
import zeroecho.sdk.hybrid.kex.HybridKexExporter;
import zeroecho.sdk.hybrid.kex.HybridKexProfile;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.sdk.util.BouncyCastleActivator;

BouncyCastleActivator.init();               // register PQC provider once at start-up
ZeroEchoSession session = new ZeroEchoSession();

// Generate classic (X25519) and PQC (ML-KEM) key pairs for both parties.
// Classic keys can be generated via the JDK directly or through the session key builder.
KeyPairGenerator x25519Gen = KeyPairGenerator.getInstance("X25519");
KeyPair initClassic = x25519Gen.generateKeyPair();
KeyPair respClassic = x25519Gen.generateKeyPair();
KeyPair respPqc = session.keyBuilders().asymmetric()
        .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

HybridKexProfile profile = HybridKexProfile.defaultProfile(32); // 256-bit shared secret

// --- Initiator side ---
// "Xdh" is the ZeroEcho algorithm id for XDH; XdhSpec.X25519 selects the X25519 curve.
try (HybridKexContext initCtx = HybridKexContexts.initiator(
        session, profile,
        "Xdh", initClassic.getPrivate(), respClassic.getPublic(), XdhSpec.X25519,
        "ML-KEM", respPqc.getPublic(), null)) {

    byte[] peerMessage = initCtx.getPeerMessage(); // send to responder

    // --- Responder side ---
    try (HybridKexContext respCtx = HybridKexContexts.responder(
            session, profile,
            "Xdh", respClassic.getPrivate(), initClassic.getPublic(), XdhSpec.X25519,
            "ML-KEM", respPqc.getPrivate(), null)) {

        respCtx.setPeerMessage(peerMessage);

        byte[] respSecret = respCtx.deriveSecret();
        byte[] initSecret = initCtx.deriveSecret();

        // initSecret and respSecret are equal.
        // Derive sub-keys with distinct labels:
        try (HybridKexExporter exporter = new HybridKexExporter(initSecret, null)) {
            byte[] txKey = exporter.export("app/tx", 32);
            byte[] rxKey = exporter.export("app/rx", 32);
            // use txKey / rxKey for AES-GCM or ChaCha20-Poly1305
        }
    }
}
```

## Thread safety

`HybridKexContext` and `HybridKexExporter` are not thread-safe. `HybridKexContexts`
and `HybridKexProfile` are stateless and thread-safe.

## Security notes

- Always call `close()` (or use try-with-resources) on `HybridKexContext` and
  `HybridKexExporter`; both zero their internal secrets when closed.
- `deriveSecret()` closes the context automatically. Do not call it more than once.
- Bind protocol context (transcript hash, session identifiers) in the `HybridKexExporter`
  export calls via the `context` parameter to prevent cross-context key reuse.
