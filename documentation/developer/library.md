# The library

The `lib` module (`module zeroecho.lib`) is the foundation of the platform. This
page covers the two parts of `lib` you are most likely to program against
directly: the `zeroecho.pkix` PKIX API for X.509 work, and the
`zeroecho.core.storage` encrypted keyring. Both return or accept standard
`java.security` types wherever possible and keep the concrete cryptographic
toolkit out of your compile-time dependencies.

!!! note "Activating EdDSA and post-quantum algorithms"
    Ed25519, Ed448, ML-DSA, ML-KEM, and all post-quantum algorithm families require
    BouncyCastle to be registered as a JCA provider. Call `BouncyCastleActivator.init()`
    once at application startup — see [Cryptography](cryptography.md) for
    the one-liner and the activation contract.

## The `zeroecho.pkix` API

`zeroecho.pkix` is a JCA-aligned facade for building and parsing X.509
certificates, PKCS#10 certification requests (CSRs), CRLs, and OCSP messages, and
for signing and verifying content. Its design principles are:

- **Standard return types.** Parsing yields `java.security.cert.X509Certificate`,
  `X509CRL`, and `javax.security.auth.x500.X500Principal` where such a type
  exists, so results interoperate with the rest of the JDK.
- **Provider confinement.** Every operation is delegated to a single
  `PkixProvider`. The concrete cryptographic toolkit that backs the default
  provider is confined to `lib` behind that seam, so callers never depend on it.
- **Keys stay with the caller.** The builders sign through a `ContentSigner` you
  supply; the private key never enters a builder. This is what lets a key live in
  a local keystore, an HSM, or a remote signer without changing the building code.

### Entry point: `Pkix`

`zeroecho.pkix.Pkix` is a `final` class of static factory and parse methods. It
resolves its `PkixProvider` once — a `ServiceLoader`-published provider if
present, otherwise the class named by the `zeroecho.pkix.provider` system
property, otherwise the built-in provider — and delegates every call to it.

| Method | Purpose |
| --- | --- |
| `Pkix.certificateBuilder()` | Start a `CertificateBuilder` for an X.509 v3 certificate. |
| `Pkix.parseCertificate(byte[])` | Parse DER into an `X509Certificate`. |
| `Pkix.certificationRequestBuilder()` | Start a `CertificationRequestBuilder` for a PKCS#10 CSR. |
| `Pkix.parseCertificationRequest(byte[])` | Parse DER into a `CertificationRequest`. |
| `Pkix.crlBuilder()` | Start a `CrlBuilder`. |
| `Pkix.parseCrl(byte[])` | Parse DER into an `X509CRL`. |
| `Pkix.ocspResponseBuilder()` | Start an `OcspResponseBuilder`. |
| `Pkix.parseOcspRequest(byte[])` / `Pkix.parseOcspResponse(byte[])` | Parse OCSP messages. |
| `Pkix.signer(PrivateKey, AlgorithmIdentifier)` | Create a `ContentSigner` over a local key. |
| `Pkix.verifier(PublicKey, AlgorithmIdentifier)` | Create a `ContentVerifier`. |
| `Pkix.subjectKeyIdentifier(PublicKey)` | Compute the standard subject key identifier. |
| `Pkix.distinguishedName(List<RelativeDistinguishedName>)` | Build a byte-exact `X500Principal`. |
| `Pkix.provider()` | The resolved `PkixProvider` (for diagnostics). |

The facade also exposes lower-level helpers for exact DER handling —
`subjectPublicKeyInfo`, `buildSubjectPublicKeyInfo`, `parseExtensions`,
`parseGeneralNames`, `assembleCertificateOrCrl`, `assembleOcspResponse`, and
others — which are useful when a signer works over pre-computed to-be-signed
bytes.

### Algorithm identifiers

Signature and algorithm identifiers are canonical value objects
(`zeroecho.pkix.AlgorithmIdentifier`), constructed from an OID and an explicit
parameter form so the exact DER can be reproduced:

```java
import zeroecho.pkix.AlgorithmIdentifier;

// Ed25519: no parameters field (RFC 8410).
AlgorithmIdentifier ed25519 = AlgorithmIdentifier.absent("1.3.101.112");

// sha256WithRSAEncryption: parameters present as DER NULL (RFC 8017).
AlgorithmIdentifier rsaSha256 = AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");
```

Use `AlgorithmIdentifier.exact(oid, derParameters)` when the parameters carry
canonical DER (for example RSASSA-PSS parameters).

### Building a certificate

The builder collects the fields and extensions, then streams the
`tbsCertificate` through a `ContentSigner` you supply. The example builds a
self-signed CA certificate with an Ed25519 key generated through the standard
JDK `KeyPairGenerator`.

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.sign.ContentSigner;
import java.security.cert.X509Certificate;

KeyPair caKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

AlgorithmIdentifier sigAlg = AlgorithmIdentifier.absent("1.3.101.112"); // Ed25519
ContentSigner signer = Pkix.signer(caKeyPair.getPrivate(), sigAlg);      // (1)

X500Principal name = new X500Principal("CN=Example Root CA, O=Example");
Instant now = Instant.now();

X509Certificate caCertificate = Pkix.certificateBuilder()
        .serialNumber(BigInteger.ONE)
        .subject(name)
        .issuer(name)                                                    // (2)
        .validity(now, now.plus(3650, ChronoUnit.DAYS))
        .publicKey(caKeyPair.getPublic())
        .basicConstraints(BasicConstraints.ca(), true)
        .keyUsage(EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
        .subjectKeyIdentifier()
        .build(signer);                                                  // (3)
```

1. The signer holds the key; the builder only receives the signer, never the key.
2. Self-signed: issuer equals subject. For a subordinate certificate, set the
   issuer to the signing CA's subject and sign with the CA's key.
3. `build(ContentSigner)` streams the `tbsCertificate` to the signer and returns
   a standard `X509Certificate`.

### Parsing a certification request

`Pkix.parseCertificationRequest(byte[])` returns a `CertificationRequest` that
exposes the request in PKIX terms and gives access to the exact signed bytes.
Proof of possession can be checked with the request's own key, or re-verified by
a signing service that holds no key locally, using a `ContentVerifier` over
`certificationRequestInfo()`.

```java
import java.util.List;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.csr.CertificationRequest;

CertificationRequest csr = Pkix.parseCertificationRequest(csrDer);

X500Principal subject = csr.subject();
List<GeneralName> requestedSans = csr.requestedSubjectAlternativeNames();

if (!csr.verifySelfSignature()) {                    // (1)
    throw new IllegalStateException("CSR self-signature is invalid");
}
```

1. `verifySelfSignature()` checks the self-signature against the request's own
   public key. To verify with an externally supplied key instead, build a
   `ContentVerifier` and feed it `csr.certificationRequestInfo()`, then
   `verify(csr.signature())`.

You can also generate a CSR natively with `Pkix.certificationRequestBuilder()`,
which mirrors the certificate builder: set `subject(...)` and `publicKey(...)`,
optionally request extensions, and finish with `build(ContentSigner)`.

### Signing and verifying content

`ContentSigner` and `ContentVerifier` are minimal, toolkit-independent, streaming
contracts. A signer declares the signature `AlgorithmIdentifier`, exposes an
`OutputStream` for the to-be-signed bytes, and yields the raw signature; a
verifier consumes the same bytes and checks a signature. Both are single-use.

```java
import java.io.OutputStream;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.sign.ContentSigner;
import zeroecho.pkix.sign.ContentVerifier;

ContentSigner signer = Pkix.signer(privateKey, sigAlg);
try (OutputStream out = signer.contentStream()) {
    out.write(toBeSigned);
}
byte[] signature = signer.signature();

ContentVerifier verifier = Pkix.verifier(publicKey, sigAlg);
try (OutputStream out = verifier.contentStream()) {
    out.write(toBeSigned);
}
boolean valid = verifier.verify(signature);
```

This is exactly the seam that keeps private keys out of the builders and lets the
same building code drive a local key, an HSM, or a remote signer. The
platform's own remote-signing path implements `ContentSigner` over a network
transport; see [Extending the platform](extending.md#the-remote-signing-transport-seam).

## The keyring (`zeroecho.core.storage`)

`zeroecho.core.storage.KeyringStore` is a path-bound, encrypted, local software
keystore for public, private, and secret keys. It wraps a single random 256-bit
store master key with PBKDF2-HMAC-SHA-256, encrypts every entry and the ordered
manifest independently with AES-256-GCM, and persists mutations with owner-only
temporary files and atomic replacement.

Key properties to design around:

- **Exclusive ownership.** An open store owns its filesystem path from
  `create`/`open` until `close`. It requires a POSIX filesystem on which
  owner-only permissions and ownership can be verified.
- **Standard encodings only.** Entries store standard key encodings (`X.509`
  SPKI, `PKCS#8`, or raw secret bytes). Java class names and JCA provider
  identities are neither persisted nor resolved; keys are reconstructed by the
  current runtime's canonical importer. Non-exportable/provider-bound keys must
  stay behind an external provider reference.
- **Secret hygiene.** Closing (or `destroy()`) clears the master key and derived
  MAC key. The store is `AutoCloseable` and `Destroyable`.

```java
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import zeroecho.core.storage.KeyringStore;
import zeroecho.core.storage.KeyringPassword;

// create() and open() throw IOException and GeneralSecurityException
Path path = Path.of("/var/lib/zeroecho/keyring/ca.zek");

try (KeyringStore keyring = KeyringStore.create(path, password)) {   // (1)
    keyring.putPrivate("ca-signing", "Ed25519", caKeyPair.getPrivate());
    keyring.putPublic("ca-signing", "Ed25519", caKeyPair.getPublic());
}

try (KeyringStore keyring = KeyringStore.open(path, password)) {      // (2)
    KeyringStore.PrivateWithId entry = keyring.getPrivateWithId("ca-signing");
    // entry.algorithm() is the canonical registered algorithm id;
    // entry.key() is the imported PrivateKey.
}
```

1. `create(Path, KeyringPassword)` provisions a new store; the password is
   borrowed and remains the caller's responsibility to destroy.
2. `open(Path, KeyringPassword)` unlocks an existing store. `getPrivate`,
   `getPublic`, and `getSecret` return keys directly; the `*WithId` variants also
   return the canonical algorithm identifier. `aliases()` lists entries and
   `contains(alias)` probes for presence.

!!! warning "Passwords and lifecycle"

    `KeyringPassword` is destroyable and is consumed to unwrap the master key.
    Always use the store inside try-with-resources so the master key is cleared
    on close, and destroy the password once you no longer need it.

## Cryptographic contexts

`zeroecho.core.context` provides lightweight wrappers around JCA operations. The
session produces them; callers never touch provider-specific types directly.

### `EncryptionContext` — symmetric encryption

`EncryptionContext` wraps a JCA `Cipher` in a streamable form.

```java
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.alg.aes.AesSpec;
import java.io.InputStream;

ZeroEchoSession session = /* … */;
// The canonical algorithm ID is "AES"; AesSpec selects mode and IV handling.
AesSpec spec = AesSpec.gcm128(null); // GCM-128 without in-band IV header

try (EncryptionContext enc = session.createContext("AES",
        zeroecho.core.KeyUsage.ENCRYPT, secretKey, spec)) {
    try (InputStream cipher = enc.attach(plaintext)) {
        byte[] ciphertext = cipher.readAllBytes();
    }
}

try (EncryptionContext dec = session.createContext("AES",
        zeroecho.core.KeyUsage.DECRYPT, secretKey, spec)) {
    try (InputStream plain = dec.attach(ciphertextStream)) {
        byte[] recovered = plain.readAllBytes();
    }
}
```

`attach(InputStream)` wraps the source stream and processes it lazily; close the
returned stream to flush any trailing bytes.

### `AgreementContext` — key agreement

`AgreementContext` performs Diffie-Hellman-style key agreement (ECDH, X25519, …).
Supply the local private key when constructing the context via
`session.createContext(…)`, then provide the peer's public key before derivation.

```java
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.core.context.AgreementContext;
import zeroecho.sdk.util.Kdf;
import java.security.PublicKey;
import java.util.Arrays;

// "Xdh" is the ZeroEcho registry id for XDH; XdhSpec.X25519 selects the X25519 curve.
byte[] derived;
try (AgreementContext agreement = session.createContext("Xdh",
        zeroecho.core.KeyUsage.AGREEMENT, myPrivateKey, XdhSpec.X25519)) {
    agreement.setPeerPublic(peerPublicKey);
    byte[] secret = agreement.deriveSecret();
    try {
        derived = Kdf.hkdfSha256(secret, null, new byte[0], 32);
    } finally {
        Arrays.fill(secret, (byte) 0); // zero the raw secret immediately after KDF
    }
}
```

The raw shared secret should be fed into a KDF and zeroed immediately (as shown
above). Pass the KDF output to your cipher or key store — never use the raw
secret directly. See [SDK utilities](sdk-utilities.md) for `Kdf.hkdfSha256`.

### `MacContext` — HMAC

`MacContext` is a `TagEngine<byte[]>` specialised for keyed MAC computation. The
`TagEngineBuilder` factory methods cover the common cases:

```java
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.core.tag.TagEngine;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import javax.crypto.SecretKey;

byte[] data = "data to authenticate".getBytes(java.nio.charset.StandardCharsets.UTF_8);

// Produce: wrap stream; tag is appended as trailer of tagLength() bytes.
TagEngine<byte[]> mac = TagEngineBuilder.hmac(session, hmacKey, null).get();
byte[] dataAndTag;
try (InputStream out = mac.wrap(new ByteArrayInputStream(data))) {
    dataAndTag = out.readAllBytes();
}
int tLen = mac.tagLength();
byte[] tag = Arrays.copyOfRange(dataAndTag, dataAndTag.length - tLen, dataAndTag.length);

// Verify: supply body without trailer and set expected tag.
TagEngine<byte[]> verifier = TagEngineBuilder.hmac(session, hmacKey, null).get();
verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
verifier.setExpectedTag(tag);
try (InputStream in = verifier.wrap(new ByteArrayInputStream(data))) {
    in.transferTo(java.io.OutputStream.nullOutputStream()); // throws VerificationException on mismatch
}
```

`TagEngineBuilder` also covers digest (`digest`), signature (`signature`), and
the Ed25519 convenience factory (`ed25519Sign`).

## Production session configuration

`new ZeroEchoSession()` creates a permissive session that accepts any algorithm
and does not audit context creation. In production, apply a policy and an audit
mode before your first `createContext` call:

```java
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.core.policy.CryptoPolicy;
import zeroecho.core.audit.AuditMode;

// Require at least 128-bit security and log every context creation.
ZeroEchoSession session = new ZeroEchoSession()
        .withPolicy(CryptoPolicy.minStrength(128))
        .withAuditMode(AuditMode.WRAP);
```

`CryptoPolicy.minStrength(128)` rejects algorithms below 128-bit equivalent
strength (e.g., DES, 1024-bit RSA). `AuditMode.WRAP` records every `createContext`
call to the session's registered `AuditListener` — useful for compliance logging.
The session is immutable-by-reassignment: each `with…` call returns a new instance,
leaving the original unchanged.

## Adding the dependency

`lib` is a JPMS module named `zeroecho.lib`. Its Gradle coordinates are
`org.egothor:lib`. Add it to your build and declare the module in your own
`module-info.java`:

=== "Gradle"

    ```groovy
    dependencies {
        implementation 'org.egothor:lib:<version>'
    }
    ```

=== "module-info.java"

    ```java
    module com.example.app {
        requires zeroecho.lib;
    }
    ```

Because the cryptographic toolkit is confined to `lib` with non-transitive
`requires`, you do not (and should not) depend on it yourself — program against
`zeroecho.pkix` and standard `java.security` types. If you consume the PKI domain
as well, depend on `zeroecho.pki` (`org.egothor:pki`), which re-exports `lib`
transitively.

!!! note "Provider activation"
    Elliptic-curve EdDSA and all post-quantum algorithms require the bundled
    provider to be registered at start-up. Call this once before any key generation
    or context creation:

    ```java
    import zeroecho.sdk.util.BouncyCastleActivator;

    BouncyCastleActivator.init(); // idempotent; safe to call more than once
    ```

    Plain RSA and ECDSA work without this call through the JDK's built-in providers.
