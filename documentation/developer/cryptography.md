# Working with cryptography (classic and post-quantum)

The `lib` module carries ZeroEcho's cryptographic capabilities, and it treats
classic and post-quantum algorithms as first-class citizens of the same toolbox.
This page is a practical, code-first guide to using them: discovering what is
available, generating key pairs, signing and verifying, encapsulating keys, and
combining a classic and a post-quantum algorithm into a single hybrid signature.

Two complementary surfaces live in `lib`, and this page uses both:

- **`zeroecho.pkix`** — the standards-facing PKIX API. It builds and parses
  X.509 certificates, PKCS#10 certification requests, CRLs, and OCSP messages,
  and it signs and verifies content, all expressed purely in `java.security`
  types (`PublicKey`, `PrivateKey`, `X509Certificate`, …). The concrete
  cryptographic toolkit stays confined behind this facade. See
  [The library](library.md) for the broader tour of this API.
- **The SDK cryptographic engine** (`zeroecho.sdk` and `zeroecho.core`) — the
  full classic-and-post-quantum primitive set: signatures (RSA, ECDSA, EdDSA,
  ML-DSA, SLH-DSA, SPHINCS+), key encapsulation (ML-KEM and other KEMs),
  streaming AEAD encryption, hybrid signatures, and hybrid key exchange.

The runnable snippets below mirror the module's own automated test suite, so they
reflect intended, working usage rather than aspirational API shapes.

!!! note "Register the cryptographic provider once at start-up"

    Elliptic-curve EdDSA and every post-quantum algorithm are supplied by the
    bundled provider. Activate it once, early in your process, before generating
    keys or creating contexts:

    ```java
    import zeroecho.sdk.util.BouncyCastleActivator;

    BouncyCastleActivator.init(); // idempotent; safe to call more than once
    ```

    Plain RSA and ECDSA also work through the JDK's built-in providers without
    this call.

## Discovering the available algorithms

Every algorithm the runtime can perform is registered under a stable canonical
identifier. Enumerate them with `CryptoAlgorithms`:

```java
import java.util.Set;
import zeroecho.core.CryptoAlgorithms;

Set<String> ids = CryptoAlgorithms.available(); // deterministic, sorted order
boolean haveMlDsa = ids.contains("ML-DSA");
boolean haveMlKem = ids.contains("ML-KEM");

// Resolve a specific one (throws IllegalArgumentException if absent):
var mldsa = CryptoAlgorithms.require("ML-DSA");
```

The canonical identifier is the string you pass to the key builders and signing
contexts shown below — for example `"RSA"`, `"ECDSA"`, `"Ed25519"`, `"ML-DSA"`,
`"SLH-DSA"`, `"SPHINCS+"`, and `"ML-KEM"`. Because the set is discovered at
runtime, guard optional algorithms with `available().contains(id)` rather than
assuming a fixed list.

On the PKIX side, algorithms are named the way X.509 names them: by object
identifier. The value type is `zeroecho.pkix.AlgorithmIdentifier`, an OID plus an
exactly-typed parameter form (`ABSENT`, `DER_NULL`, or exact DER):

```java
import zeroecho.pkix.AlgorithmIdentifier;

// RSA PKCS#1 v1.5 with SHA-256 carries a DER NULL parameters field.
AlgorithmIdentifier rsaSha256 = AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");

// ECDSA with SHA-256 has no parameters field at all.
AlgorithmIdentifier ecdsaSha256 = AlgorithmIdentifier.absent("1.2.840.10045.4.3.2");

// Ed25519 likewise omits the parameters field.
AlgorithmIdentifier ed25519 = AlgorithmIdentifier.absent("1.3.101.112");
```

The facade can also read algorithm identifiers back out of encoded material —
`Pkix.parseAlgorithmIdentifier(der)`, and `Pkix.subjectPublicKeyAlgorithm(spki)`
to recover the algorithm of a `SubjectPublicKeyInfo`.

### Supported algorithm families

| Family | Canonical id(s) | Kind | Class | Typical use |
| --- | --- | --- | --- | --- |
| RSA | `RSA` | Signature (and legacy encryption) | Classic | X.509 signing, certificate authorities |
| ECDSA | `ECDSA` | Signature | Classic | X.509 signing, compact keys |
| EdDSA | `Ed25519`, `Ed448` | Signature | Classic | Fast, misuse-resistant signing |
| ECDH / XDH | (see `available()`) | Key agreement | Classic | Ephemeral key establishment |
| ML-DSA (Dilithium) | `ML-DSA` | Signature | Post-quantum | General-purpose PQ signing (FIPS 204) |
| SLH-DSA | `SLH-DSA` | Signature (hash-based, **stateless**) | Post-quantum | Conservative PQ signing (FIPS 205) |
| SPHINCS+ | `SPHINCS+` | Signature (hash-based, **stateless**) | Post-quantum | Conservative PQ signing |
| ML-KEM (Kyber) | `ML-KEM` | Key encapsulation | Post-quantum | PQ key establishment (FIPS 203) |
| Other PQ KEMs | FrodoKEM, BIKE, Classic McEliece, HQC, NTRU, NTRU Prime, SABER (see `available()`) | Key encapsulation | Post-quantum | Alternative / experimental key establishment |
| Symmetric & digests | AES, ChaCha20 / ChaCha20-Poly1305, HMAC, SHA-2 / SHA-3 | AEAD / MAC / digest | Classic | Bulk encryption, integrity, KDF inputs |

Signature families produce and verify signatures; KEM families establish a shared
secret between a public/private key pair and are used with an AEAD cipher (for
example AES-GCM) to encrypt the actual payload. Query `CryptoAlgorithms.available()`
at runtime for the exact identifiers present in your build.

## Generating key pairs

Key generation always yields a standard `java.security.KeyPair`, whether you go
through the JDK directly or through the ZeroEcho key builders. That means the same
keys flow unchanged into the `zeroecho.pkix` API.

=== "Classic (e.g. ECDSA)"

    Classic algorithms can be generated with the plain JDK API:

    ```java
    import java.security.KeyPair;
    import java.security.KeyPairGenerator;
    import java.security.spec.ECGenParameterSpec;

    // ECDSA over NIST P-256
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    ec.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ecdsa = ec.generateKeyPair();

    // RSA-2048
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
    rsaGen.initialize(2048);
    KeyPair rsa = rsaGen.generateKeyPair();

    // Ed25519 (requires the activated provider)
    KeyPair ed25519 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    ```

=== "Post-quantum (e.g. ML-DSA)"

    Post-quantum algorithms are generated through the ZeroEcho key builders, which
    take the canonical id and an algorithm-specific specification and return an
    ordinary `KeyPair`:

    ```java
    import java.security.KeyPair;
    import zeroecho.sdk.ZeroEchoSession;
    import zeroecho.core.alg.mldsa.MldsaKeyGenSpec;
    import zeroecho.core.alg.slhdsa.SlhDsaKeyGenSpec;
    import zeroecho.core.alg.kyber.KyberKeyGenSpec;

    ZeroEchoSession session = new ZeroEchoSession();

    // ML-DSA-65 (FIPS 204), pure (no pre-hash):
    KeyPair mldsa = session.keyBuilders().asymmetric().generateKeyPair(
            "ML-DSA",
            MldsaKeyGenSpec.of("BC", MldsaKeyGenSpec.ParameterSet.ML_DSA_65,
                    MldsaKeyGenSpec.PreHash.NONE));

    // SLH-DSA (FIPS 205), library default parameter set:
    KeyPair slhdsa = session.keyBuilders().asymmetric().generateKeyPair(
            "SLH-DSA", SlhDsaKeyGenSpec.defaultSpec());

    // ML-KEM (Kyber-1024) for key encapsulation:
    KeyPair mlkem = session.keyBuilders().asymmetric().generateKeyPair(
            "ML-KEM", KyberKeyGenSpec.kyber1024());
    ```

    Each specification exposes its strength choices — `MldsaKeyGenSpec` offers
    parameter sets `ML_DSA_44`, `ML_DSA_65`, and `ML_DSA_87` (≈128/192/256-bit);
    `SlhDsaKeyGenSpec` selects the hash family (SHA-2 or SHAKE), the security
    level (`L1_128`, `L3_192`, `L5_256`), and a size-vs-speed variant; and
    `KyberKeyGenSpec` offers `kyber512()`, `kyber768()`, and `kyber1024()`.

## Signing and verifying

### Certificates and CSRs through the PKIX API

The `zeroecho.pkix` facade builds signed X.509 objects from a `ContentSigner`
created over a private key and a signature `AlgorithmIdentifier`. The following
self-signs a CA certificate and then parses and cryptographically verifies it —
using ECDSA, though RSA works identically by swapping the key and the algorithm
identifier:

```java
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.sign.ContentSigner;

X500Principal name = new X500Principal("CN=Example Root CA");
AlgorithmIdentifier ecdsaSha256 = AlgorithmIdentifier.absent("1.2.840.10045.4.3.2");
ContentSigner signer = Pkix.signer(ecdsa.getPrivate(), ecdsaSha256);

Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
X509Certificate cert = Pkix.certificateBuilder()
        .serialNumber(BigInteger.ONE)
        .subject(name)
        .issuer(name)
        .validity(now, now.plus(365, ChronoUnit.DAYS))
        .publicKey(ecdsa.getPublic())
        .basicConstraints(BasicConstraints.ca(1), true)
        .keyUsage(EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
        .subjectKeyIdentifier()
        .build(signer);

X509Certificate parsed = Pkix.parseCertificate(cert.getEncoded());
parsed.verify(ecdsa.getPublic()); // throws if the signature does not check out
```

A certification request is built the same way and self-verifies its proof of
possession:

```java
import java.util.List;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.csr.CertificationRequest;

CertificationRequest csr = Pkix.certificationRequestBuilder()
        .subject(new X500Principal("CN=leaf.example.com"))
        .publicKey(ecdsa.getPublic())
        .subjectAlternativeNames(List.of(new GeneralName.DnsName("leaf.example.com")), false)
        .build(signer);

CertificationRequest reparsed = Pkix.parseCertificationRequest(csr.encoded());
boolean popOk = reparsed.verifySelfSignature(); // false if key and signature disagree
```

For raw content that is not an X.509 object, use the streaming `ContentSigner`
and `ContentVerifier` directly. Write the to-be-signed bytes to the signer's
`contentStream()`, take the `signature()`, then check it with a verifier over the
public key:

```java
import zeroecho.pkix.sign.ContentVerifier;

byte[] payload = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);

ContentSigner cs = Pkix.signer(ecdsa.getPrivate(), ecdsaSha256);
cs.contentStream().write(payload);
byte[] signature = cs.signature();

ContentVerifier cv = Pkix.verifier(ecdsa.getPublic(), ecdsaSha256);
cv.contentStream().write(payload);
boolean valid = cv.verify(signature);
```

Because the signer is fed through an `OutputStream` and never sees the key beyond
its `PrivateKey` reference, the same builder code works whether the key lives in
memory, in a keystore, or behind a remote signing service.

### Post-quantum signatures

Post-quantum signatures are produced and verified through the SDK's streaming
signature context, which handles ML-DSA, SLH-DSA, and SPHINCS+ uniformly. In
sign mode, wrapping a stream emits the original bytes followed by the signature
as a trailer; in verify mode, you supply the detached signature and the context
checks it at end-of-stream.

=== "Classic (e.g. Ed25519)"

    ```java
    import java.io.ByteArrayInputStream;
    import java.io.ByteArrayOutputStream;
    import java.io.InputStream;
    import java.io.OutputStream;
    import java.util.Arrays;
    import zeroecho.core.KeyUsage;
    import zeroecho.core.context.SignatureContext;
    import zeroecho.sdk.ZeroEchoSession;

    ZeroEchoSession session = new ZeroEchoSession();
    byte[] message = "attach and sign".getBytes();

    // Sign: the wrapped stream yields message || signature-trailer.
    SignatureContext signer = session.createContext("Ed25519", KeyUsage.SIGN, ed25519.getPrivate());
    int sigLen = signer.tagLength();
    ByteArrayOutputStream framed = new ByteArrayOutputStream();
    try (InputStream in = signer.wrap(new ByteArrayInputStream(message))) {
        in.transferTo(framed);
    }
    byte[] out = framed.toByteArray();
    byte[] signature = Arrays.copyOfRange(out, out.length - sigLen, out.length);

    // Verify: supply the detached signature; throw on mismatch at EOF.
    SignatureContext verifier = session.createContext("Ed25519", KeyUsage.VERIFY, ed25519.getPublic());
    verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
    verifier.setExpectedTag(signature);
    try (InputStream in = verifier.wrap(new ByteArrayInputStream(message))) {
        in.transferTo(OutputStream.nullOutputStream()); // IOException here means invalid
    }
    ```

=== "Post-quantum (e.g. ML-DSA)"

    The code is identical apart from the algorithm identifier — post-quantum keys
    flow through the same streaming contract:

    ```java
    import java.io.ByteArrayInputStream;
    import java.io.ByteArrayOutputStream;
    import java.io.InputStream;
    import java.io.OutputStream;
    import java.util.Arrays;
    import zeroecho.core.KeyUsage;
    import zeroecho.core.context.SignatureContext;
    import zeroecho.sdk.ZeroEchoSession;

    ZeroEchoSession session = new ZeroEchoSession();
    byte[] message = "attach and sign".getBytes();

    SignatureContext signer = session.createContext("ML-DSA", KeyUsage.SIGN, mldsa.getPrivate());
    int sigLen = signer.tagLength();
    ByteArrayOutputStream framed = new ByteArrayOutputStream();
    try (InputStream in = signer.wrap(new ByteArrayInputStream(message))) {
        in.transferTo(framed);
    }
    byte[] out = framed.toByteArray();
    byte[] signature = Arrays.copyOfRange(out, out.length - sigLen, out.length);

    SignatureContext verifier = session.createContext("ML-DSA", KeyUsage.VERIFY, mldsa.getPublic());
    verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
    verifier.setExpectedTag(signature);
    try (InputStream in = verifier.wrap(new ByteArrayInputStream(message))) {
        in.transferTo(OutputStream.nullOutputStream());
    }
    ```

    Substitute `"SLH-DSA"` or `"SPHINCS+"` for `"ML-DSA"` to use a hash-based
    scheme instead; the surrounding code does not change.

!!! warning "Hash-based signatures here are stateless — and stateful schemes are deliberately absent"

    SLH-DSA (FIPS 205) and SPHINCS+ are **stateless** hash-based signature
    schemes: there is no per-signature secret state to advance, so an operator
    cannot destroy a key's security by reusing it, and signing keys can be
    treated like any other private key.

    The library intentionally does **not** provide *stateful* hash-based schemes
    such as LMS or XMSS. Those require rigorous, durable tracking of a one-time
    key index across every signature and every process restart; a single reused
    index catastrophically breaks the scheme. If you have a genuine requirement
    for a stateful scheme, treat its state management as a dedicated, audited
    subsystem — do not approximate it with the APIs on this page.

## Key encapsulation with ML-KEM

For confidentiality rather than authenticity, use a KEM to derive a shared secret
to a recipient's public key, then encrypt the payload with an AEAD cipher. The
data-content chain builder wires ML-KEM to HKDF-SHA-256 and AES-GCM in one
pipeline:

```java
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.KemDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;

byte[] info = "KEM-demo".getBytes(StandardCharsets.US_ASCII);

DataContent encrypting = DataContentChainBuilder.encrypt()
        .add(PlainBytesBuilder.builder().bytes(plaintext))
        .add(KemDataContentBuilder.builder(new ZeroEchoSession())
                .kem("ML-KEM")
                .recipientPublic(mlkem.getPublic())     // encapsulate to the recipient
                .hkdfSha256(info)                        // expand the shared secret
                .withAes(AesDataContentBuilder.builder(new ZeroEchoSession())
                        .modeGcm(128)
                        .withHeader()))
        .build();

byte[] ciphertext;
try (InputStream in = encrypting.getStream()) {
    ciphertext = in.readAllBytes();
}
```

Decryption mirrors the chain with `DataContentChainBuilder.decrypt()`, the same
KEM id and HKDF `info`, and `recipientPrivate(mlkem.getPrivate())` for
decapsulation.

## Hybrid signatures and algorithm selection

During the transition to post-quantum cryptography, a common and prudent choice
is a **hybrid** signature that combines a classic algorithm and a post-quantum
one, so that a break in either one alone does not forge a signature. A
`HybridSignatureProfile` names the two component algorithms and the verification
rule, and `HybridSignatureContexts` produces signing and verifying contexts that
share the same streaming contract as the single-algorithm contexts above:

```java
import zeroecho.sdk.hybrid.signature.HybridSignatureContexts;
import zeroecho.sdk.hybrid.signature.HybridSignatureProfile;
import zeroecho.core.context.SignatureContext;

// Both components must verify (defence in depth). Use OR only when you
// deliberately want either algorithm alone to be sufficient.
HybridSignatureProfile profile = new HybridSignatureProfile(
        "Ed25519", "ML-DSA", null, null, HybridSignatureProfile.VerifyRule.AND);

SignatureContext signer = HybridSignatureContexts.sign(
        new ZeroEchoSession(), profile,
        ed25519.getPrivate(), mldsa.getPrivate(), 2 * 1024 * 1024);

SignatureContext verifier = HybridSignatureContexts.verify(
        new ZeroEchoSession(), profile,
        ed25519.getPublic(), mldsa.getPublic(), 2 * 1024 * 1024);
```

The final argument is a buffering bound that caps how much of the wrapped stream
is held in memory (a denial-of-service guard). The produced trailer is simply the
classic signature followed by the post-quantum signature, in the fixed order the
profile declares; no algorithm metadata is embedded, so both sides must agree on
the profile out of band.

- **`VerifyRule.AND`** — both component signatures must verify. This is the
  conservative default for migration: an adversary must break *both* algorithms.
- **`VerifyRule.OR`** — at least one component must verify. This favours
  availability (for example, tolerating a peer that can only check one of the two
  algorithms) at the cost of the weaker guarantee.

### Choosing an algorithm

- For **general-purpose post-quantum signing**, prefer **ML-DSA** — it offers
  small signatures and fast operations across three strength levels
  (`ML_DSA_44`/`65`/`87`).
- For a **conservative, hash-based** signature whose security rests only on the
  underlying hash, use **SLH-DSA** (or SPHINCS+). Expect larger signatures and
  slower signing; tune the size-vs-speed variant to your workload.
- For **key establishment**, use the **ML-KEM** KEM with an AEAD cipher rather
  than a signature algorithm.
- For **standards-interoperable X.509**, sign certificates and CRLs with a
  classic algorithm (RSA, ECDSA, or EdDSA) through the `zeroecho.pkix` API, and
  reach for hybrid or pure post-quantum signatures on the data plane where you
  control both ends.
- When in doubt during migration, **combine** a classic and a post-quantum
  signature with `VerifyRule.AND`.

Match strengths across a hybrid pair — for example Ed25519 or P-256 alongside
ML-DSA-65 — so that neither component is the obvious weak link. The policy
implications of these choices, including which algorithms are acceptable for a
given assurance level, are discussed in the
[Security model](../reference/security-model.md).

## See also

- [The library](library.md) — the full tour of the `zeroecho.pkix` API and the
  encrypted keyring.
- [Security model](../reference/security-model.md) — trust boundaries, key
  handling, and algorithm policy.
