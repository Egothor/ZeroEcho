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
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;

Set<String> ids = CryptoAlgorithms.available(); // deterministic, sorted order
boolean haveMlDsa = ids.contains("ML-DSA");
boolean haveMlKem = ids.contains("ML-KEM");

// Resolve a specific one (throws IllegalArgumentException if absent):
CryptoAlgorithm mldsa = CryptoAlgorithms.require("ML-DSA");
```

The canonical identifier is the string you pass to the key builders and signing
contexts shown below — for example `"RSA"`, `"ECDSA"`, `"Ed25519"`, `"ML-DSA"`,
`"SLH-DSA"`, `"SPHINCS+"`, `"ML-KEM"`, `"X-Wing"`, `"LMS"`, and `"XMSS"`.
Because the set is discovered at runtime, guard optional algorithms with
`available().contains(id)` rather than assuming a fixed list.

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

### Enumerating parameter sets

Each algorithm exposes the key-generation configurations it supports through
`CryptoAlgorithm.parameterSets()`. A `ParameterSetDescriptor` is either:

- **`Concrete`** — a fully pre-built, named configuration. The enclosed
  `AlgorithmKeySpec` can be passed directly to a key builder.
- **`Template`** — a parameterised family. The descriptor lists the named
  inputs a caller must supply; a factory then produces the spec.

Both carry a `SecurityLevel` that expresses NIST PQC category (1–5) and
classical-bit equivalence.

Templates expose ordered, immutable `constraints()` for required flags, defaults,
value kinds, choices and numeric bounds. Invoke `factory().apply(arguments)` to
apply centralized validation; invalid maps throw `IllegalArgumentException`.
Do not infer constraints from display descriptions. The compatibility behavior
of older template constructors and algorithm migrations is documented in
[BouncyCastle migration notes](../reference/bc-migration.md).

```java
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

CryptoAlgorithm mldsa = CryptoAlgorithms.require("ML-DSA");

for (ParameterSetDescriptor<?> d : mldsa.parameterSets()) {
    SecurityLevel level = d.securityLevel();
    String levelStr = level.nistLevel().isPresent()
            ? "L" + level.nistLevel().getAsInt() + " / " + level.classicalBits() + "-bit"
            : level.classicalBits() + "-bit";

    if (d instanceof ParameterSetDescriptor.Concrete<?> c) {
        // c.spec() is the ready-to-use AlgorithmKeySpec.
        System.out.println(c.id() + "  " + levelStr + "  → " + c.spec().getClass().getSimpleName());
    } else if (d instanceof ParameterSetDescriptor.Template<?> t) {
        // List the required inputs: name → Java type.
        String params = t.parameters().stream()
                .map(p -> p.name() + ": " + p.type().getSimpleName())
                .collect(java.util.stream.Collectors.joining(", "));
        System.out.println(t.id() + "  template(" + params + ")");
    }
}
```

The complete catalog — all algorithms with their parameter sets, families, and
security levels — is rendered in the `lib` module's Javadoc overview page, which
is generated at build time by `GenerateCryptoCatalogTable`.

### Supported algorithm families

| Family | Canonical id(s) | Kind | Class | Typical use |
| --- | --- | --- | --- | --- |
| RSA | `RSA` | Signature (and legacy encryption) | Classic | X.509 signing, certificate authorities |
| ECDSA | `ECDSA` | Signature | Classic | X.509 signing, compact keys |
| EdDSA | `Ed25519`, `Ed448` | Signature | Classic | Fast, misuse-resistant signing |
| ECDH / XDH | (see `available()`) | Key agreement | Classic | Ephemeral key establishment |
| ML-DSA (Dilithium) | `ML-DSA` | Signature | Post-quantum | General-purpose PQ signing (FIPS 204) |
| SLH-DSA | `SLH-DSA` | Signature (hash-based, **stateless**) | Post-quantum | Conservative PQ signing (FIPS 205) |
| SPHINCS+ | `SPHINCS+` | Signature (hash-based, **stateless**) | Post-quantum | Conservative PQ signing; maps to SLH-DSA internally as of BC 1.86 |
| LMS | `LMS` | Hash-based, **stateful** signatures | Post-quantum | RFC 8554; signing requires an explicit durable authority |
| XMSS | `XMSS` | Hash-based, **stateful** signatures | Post-quantum | RFC 8391; signing requires an explicit durable authority |
| ML-KEM (Kyber) | `ML-KEM` | Key encapsulation | Post-quantum | PQ key establishment (FIPS 203) |
| X-Wing | `X-Wing` | Key encapsulation (hybrid) | Classic + post-quantum | Hybrid PQ key establishment (X25519 + ML-KEM-768; draft-connolly-cfrg-xwing-kem) |
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

    !!! note "KyberKeyGenSpec and the ML-KEM canonical identifier"
        The specification class is named `KyberKeyGenSpec` after the algorithm's
        pre-standardisation name. Pass `"ML-KEM"` as the canonical algorithm
        identifier to `generateKeyPair` (not `"KYBER"`). The class name reflects
        the implementation lineage; the identifier follows the NIST FIPS 203
        designation.

=== "Hybrid KEM (X-Wing)"

    X-Wing has no selectable parameters. Pass `XWingKeyGenSpec.DEFAULT` as the
    specification:

    ```java
    import java.security.KeyPair;
    import zeroecho.core.alg.xwing.XWingKeyGenSpec;
    import zeroecho.sdk.ZeroEchoSession;

    ZeroEchoSession session = new ZeroEchoSession();

    KeyPair xwing = session.keyBuilders().asymmetric().generateKeyPair(
            "X-Wing", XWingKeyGenSpec.DEFAULT);
    ```

    The key pair embeds both an X25519 component and an ML-KEM-768 component.
    Key sizes are fixed by the X-Wing specification and cannot be tuned.

=== "Stateful hash-based (LMS / XMSS)"

    LMS and XMSS use singleton specifications for the default parameter sets.
    Ordinary key generation, import, and verification remain available. Signing
    requires fresh enrollment through `generateStatefulKey` and a `StatefulSigner`
    with the durable local authority described in [Stateful signing](stateful-signing.md).
    Ordinary generated or imported keys cannot sign through a stateless executor.

    ```java
    import java.security.KeyPair;
    import zeroecho.core.alg.lms.LmsKeyGenSpec;
    import zeroecho.core.alg.xmss.XmssKeyGenSpec;
    import zeroecho.sdk.ZeroEchoSession;

    ZeroEchoSession session = new ZeroEchoSession();

    // LMS default: lms_sha256_n32_h5 / sha256_n32_w8 (32 one-time leaves)
    KeyPair lms = session.keyBuilders().asymmetric().generateKeyPair(
            "LMS", LmsKeyGenSpec.DEFAULT);

    // XMSS default: SHA2_10_256 (SHA-256, height 10, 1024 leaves)
    KeyPair xmss = session.keyBuilders().asymmetric().generateKeyPair(
            "XMSS", XmssKeyGenSpec.DEFAULT);
    ```

    These defaults describe key generation only and do not enable signing.

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
    byte[] signature;
    try (SignatureContext signer = session.createContext("Ed25519", KeyUsage.SIGN, ed25519.getPrivate())) {
        int sigLen = signer.tagLength();
        ByteArrayOutputStream framed = new ByteArrayOutputStream();
        try (InputStream in = signer.wrap(new ByteArrayInputStream(message))) {
            in.transferTo(framed);
        }
        byte[] out = framed.toByteArray();
        signature = Arrays.copyOfRange(out, out.length - sigLen, out.length);
    }

    // Verify: supply the detached signature; throw on mismatch at EOF.
    try (SignatureContext verifier = session.createContext("Ed25519", KeyUsage.VERIFY, ed25519.getPublic())) {
        verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
        verifier.setExpectedTag(signature);
        try (InputStream in = verifier.wrap(new ByteArrayInputStream(message))) {
            in.transferTo(OutputStream.nullOutputStream()); // IOException here means invalid
        }
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

    byte[] signature;
    try (SignatureContext signer = session.createContext("ML-DSA", KeyUsage.SIGN, mldsa.getPrivate())) {
        int sigLen = signer.tagLength();
        ByteArrayOutputStream framed = new ByteArrayOutputStream();
        try (InputStream in = signer.wrap(new ByteArrayInputStream(message))) {
            in.transferTo(framed);
        }
        byte[] out = framed.toByteArray();
        signature = Arrays.copyOfRange(out, out.length - sigLen, out.length);
    }

    try (SignatureContext verifier = session.createContext("ML-DSA", KeyUsage.VERIFY, mldsa.getPublic())) {
        verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
        verifier.setExpectedTag(signature);
        try (InputStream in = verifier.wrap(new ByteArrayInputStream(message))) {
            in.transferTo(OutputStream.nullOutputStream());
        }
    }
    ```

    Substitute `"SLH-DSA"` or `"SPHINCS+"` for `"ML-DSA"` to use a hash-based
    scheme instead; the surrounding code does not change.

!!! note "SLH-DSA and SPHINCS+ are stateless"

    SLH-DSA (FIPS 205) and SPHINCS+ are **stateless** hash-based signature
    schemes: there is no per-signature secret state to advance, so an operator
    cannot destroy the key's security by reusing a signing invocation, and the
    private key can be treated like any other private key.

### Stateful hash-based signatures (LMS and XMSS)

LMS (RFC 8554) and XMSS (RFC 8391) retain key generation, parsing, import,
and streaming verification. Signing is available only through the explicit
`StatefulSigner` capability for freshly generated keyring keys and a separately
preserved local authority. See [durable stateful signing](stateful-signing.md)
for enrollment, failure handling and the mandatory backup/restore contract.

The algorithms do not advertise `SIGN`. Direct signing constructors and generic
signing helpers throw `UnsupportedRoleException` before initializing a provider
or probing signature length. `KeyringSignatureExecutor` rejects stored LMS/XMSS
keys with the existing `Failure(ALGORITHM_MISMATCH)` category. Verification
contexts derive signature length from public parameters without advancing state.

Persisting a private key after signing is insufficient: a crash or restoration
of an older key can reuse a leaf already exposed in a signature. Applications
requiring hash-based signing without that operational discipline can use
stateless SLH-DSA.

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

## Hybrid key encapsulation with X-Wing

X-Wing (draft-connolly-cfrg-xwing-kem) is a hybrid KEM that combines X25519 and
ML-KEM-768 in a single encapsulation. The combined shared secret provides 128-bit
classical security from the X25519 component and post-quantum security from the
ML-KEM-768 component. A break in either component alone does not compromise the
shared secret.

X-Wing uses the same `KemContext` API as ML-KEM:

```java
import java.security.KeyPair;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.xwing.XWingKeyGenSpec;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.KemContext.KemResult;
import zeroecho.sdk.ZeroEchoSession;

ZeroEchoSession session = new ZeroEchoSession();

// Generate a key pair (no parameter choices — X-Wing has fixed parameters).
KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair(
        "X-Wing", XWingKeyGenSpec.DEFAULT);

// Encapsulate (sender side): produces a ciphertext and the sender's shared secret.
KemContext encCtx = session.createContext("X-Wing", KeyUsage.ENCAPSULATE, kp.getPublic());
KemResult result = encCtx.encapsulate();
byte[] ciphertext   = result.ciphertext();
byte[] sharedSecret = result.sharedSecret();

// Decapsulate (recipient side): recovers the same shared secret.
KemContext decCtx = session.createContext("X-Wing", KeyUsage.DECAPSULATE, kp.getPrivate());
byte[] recovered = decCtx.decapsulate(ciphertext);
```

Both sides obtain an identical shared secret that can be passed to a KDF
(for example `Kdf.hkdfSha256`) before use with an AEAD cipher. X-Wing is the
recommended default KEM for new deployments where both classical and post-quantum
resilience is required. Use ML-KEM alone only when integration with an existing
system that does not support X-Wing is required.

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
- For a **conservative, stateless hash-based** signature whose security rests
  only on the underlying hash, use **SLH-DSA** (or SPHINCS+). Expect larger
  signatures and slower signing; tune the size-vs-speed variant to your workload.
- **LMS** and **XMSS** signing requires the explicit durable capability and
  independently preserved authority described above.
- For **key establishment with post-quantum resilience**, prefer **X-Wing** —
  it provides both classical (X25519) and post-quantum (ML-KEM-768) protection
  in a single encapsulation and is the recommended default for new deployments.
  Use **ML-KEM** alone only when interoperating with a system that does not
  support X-Wing.
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

## Hybrid X.509 certificates (Alt Signature Extensions)

The hybrid signature mechanism above operates outside X.509 and is typically
used on application-level data. For X.509 certificates themselves, ZeroEcho
supports a standards-track alternative: the **Alternative Signature Extensions**
defined in X.509 2019 Amendment 2 (and mirrored in IETF
draft-lamps-pq-composite-certs). This is referred to as hybrid certificate
variant B.

A certificate issued under this scheme carries three non-critical extensions in
addition to the primary signature:

| Extension | OID | Content |
|---|---|---|
| SubjectAltPublicKeyInfo | 2.5.29.72 | Post-quantum public key |
| AltSignatureAlgorithm | 2.5.29.73 | Post-quantum signature algorithm identifier |
| AltSignatureValue | 2.5.29.74 | Post-quantum signature over the pre-TBS structure |

Classical verifiers that do not recognise these OIDs ignore them and verify only
the primary (classical) signature. Post-quantum-aware verifiers additionally
check the alternative signature, gaining protection against a break of the
primary algorithm.

### How it works

The signing service uses a three-phase protocol:

1. Build a **pre-TBS** carrying SubjectAltPublicKeyInfo and AltSignatureAlgorithm,
   omitting the entire AltSignatureValue extension and the TBSCertificate
   `signature` field. `CertificateBuilder.buildAlternativeSignatureTbs()` performs
   this standardized transform without signing or requiring a signature-size estimate.
2. Sign the pre-TBS with the alternative key and verify the returned signature
   before staging any primary-signing work.
3. Build the **final TBS** with the real AltSignatureValue extension and primary
   signature algorithm, then sign it with the primary key. Publication verifies
   both signatures. `Pkix.verifyAlternativeSignature(certificate, issuerAlternativeKey)`
   uses the explicitly supplied issuer key; it does not establish trust or validate
   the primary signature, validity interval or certification path.

The resulting certificate is structurally a normal X.509 certificate — it has
one primary signature in the `signatureValue` field and three extension values
that carry the alternative-signature material.

Alternative-signature algorithm bindings currently support absent or DER-NULL
parameters. Bindings requiring structured DER parameters, such as RSA-PSS,
are rejected for this alternative-signature path.

### Issuing a hybrid certificate

Enable hybrid issuance by activating a profile that includes `hybridMode`. The
built-in `hybrid-root-ca` profile uses ECDSA as the primary algorithm and
ML-DSA-65 as the alternative. Operators who activate this profile must provision
an ML-DSA-65 key under the reference `zeroecho-lib:root-alt.prv` in the signing
provider's keyring alongside the primary ECDSA key.

To create a custom hybrid profile, add the `hybridMode` object to a `ROOT_CA` profile
document:

```json
"hybridMode": {
  "type": "ALT_SIGNATURE",
  "altSignatureAlgorithmId": "zealg:2:9:signature8:zeroecho9:ml-dsa-6516:zeroecho.builtin6:bm9uZQ",
  "altKeyRef": "zeroecho-lib:root-alt.prv"
}
```

The `altSignatureAlgorithmId` is the canonical form of the ZeroEcho algorithm
identity. Obtain it programmatically in code that may run against a known
runtime:

```java
import zeroecho.core.alg.BootstrapAlgorithmIdentities;

String altAlgoId = BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm();
```

The canonical form for common ML-DSA parameter sets:

| Parameter set | Security level | Signature bytes | Canonical form |
|---|---|---|---|
| ML-DSA-44 | 2 (≈ 128-bit) | 2 420 | `zealg:2:9:signature8:zeroecho9:ml-dsa-4416:zeroecho.builtin6:bm9uZQ` |
| ML-DSA-65 | 3 (≈ 192-bit) | 3 309 | `zealg:2:9:signature8:zeroecho9:ml-dsa-6516:zeroecho.builtin6:bm9uZQ` |
| ML-DSA-87 | 5 (≈ 256-bit) | 4 627 | `zealg:2:9:signature8:zeroecho9:ml-dsa-8716:zeroecho.builtin6:bm9uZQ` |

### Variants A, B, and C

ZeroEcho is architecturally prepared for three hybrid certificate variants.
Variants A and B are implemented; C is a reserved stub:

| Variant | Description | Status |
|---|---|---|
| A — Twin certificates | Two independent CA hierarchies, one classical and one PQC, coordinated at the deployment level | **Implemented** |
| B — Alt Signature Extensions | Root certificate with embedded alternative signature (X.509 2019 Amd 2) | **Implemented for root lifecycle** |
| C — Composite signatures | Single certificate with a composite key and composite signature (draft-ounsworth-pq-composite-sigs) | Reserved |

The `HybridCertificateMode` sealed interface (`None`, `AltSignature`,
`TwinCertificate`, `Composite`) is the exhaustive switch target at the profile
layer. `Composite` is the only remaining stub; adding it will not break existing
code.

### Variant A: twin certificate deployment

Variant A uses `TwinCertificate` mode as a semantic profile marker. Each
individual certificate in a twin deployment is a standard, single-algorithm
X.509 certificate — there are no extra extensions. The classical and PQC CA
hierarchies are separate, and the relationship between them is a deployment-level
configuration, not a per-certificate property.

Built-in profiles for variant A are `pqc-root-ca` (root CA, ML-DSA-65 primary,
10-year validity) and `pqc-intermediate-ca` (intermediate CA, ML-DSA-65 primary,
5-year validity). Both allow any registered PQC or classical algorithm as the
subject public-key type.

Egothor OIDs (IANA PEN 31424, arc `1.3.6.1.4.1.31424`) are used for
non-standardised PQC algorithms such as SPHINCS+. These OIDs are registered in
`EgothorAlgorithmOids` and are recognised by the signing and verification
infrastructure within the ZeroEcho ecosystem.

## See also

- [The library](library.md) — the full tour of the `zeroecho.pkix` API and the
  encrypted keyring.
- [Security model](../reference/security-model.md) — trust boundaries, key
  handling, and algorithm policy.
- [Certificate profile schema](../reference/certificate-profile-schema.md#hybrid-mode) — `hybridMode` field reference.
- [BouncyCastle 1.86 migration notes](../reference/bc-migration.md) — breaking
  changes to algorithm parameter sets and provider names introduced in the
  BC 1.86 upgrade.
