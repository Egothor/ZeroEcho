# Tag engine

The `zeroecho.core.tag` package provides a streaming authentication-tag layer
that can be plugged into any byte-stream pipeline. A `TagEngine` wraps an
`InputStream` and either appends a trailer tag on write (produce mode) or verifies
a supplied tag at EOF on read (verify mode), without buffering the full payload.

The `TagEngineBuilder` factory wires a `ZeroEchoSession` context to a fresh
engine on each call, so that session policy and auditing apply consistently to
every tag operation.

## Modes

| Mode | Description |
| --- | --- |
| **Produce** | `TagEngine.wrap(upstream)` returns a passthrough stream. Bytes flow unchanged; when the upstream reaches EOF, the computed tag bytes are appended as a trailer. |
| **Verify** | The caller supplies the expected tag via `setExpectedTag(byte[])` and strips the trailer from the upstream before passing it to `wrap`. At EOF the engine compares the computed tag to the expected one. |

Verification outcome handling is delegated to a `VerificationBiPredicate`. The
default predicate returns a boolean; `getThrowOnMismatch()` converts it to one that
throws `VerificationException` on mismatch, which is the typical choice for
pipeline use.

## `TagEngineBuilder`

`TagEngineBuilder<T>` is a `Supplier<TagEngine<T>>` that creates fresh engine
instances. Calling `get()` on the same builder multiple times is safe; each call
produces an independent engine.

| Factory method | Tag algorithm | T type |
| --- | --- | --- |
| `TagEngineBuilder.digest(session, spec)` | Unkeyed digest (SHA-256 by default) | `byte[]` |
| `TagEngineBuilder.hmac(session, key, spec)` | Keyed HMAC (HMAC-SHA-256 by default) | `byte[]` |
| `TagEngineBuilder.signature(session, algId, key, spec)` | JCA signature (auto-detects SIGN/VERIFY from key type) | `Signature` |
| `TagEngineBuilder.ed25519Sign(session, privateKey)` | Ed25519 signing | `Signature` |
| `TagEngineBuilder.ed25519Verify(session, publicKey)` | Ed25519 verification | `Signature` |
| `TagEngineBuilder.rsaSign(session, privateKey, spec)` | RSA-PSS or PKCS#1 v1.5 signing | `Signature` |
| `TagEngineBuilder.rsaVerify(session, publicKey, spec)` | RSA-PSS or PKCS#1 v1.5 verification | `Signature` |
| `TagEngineBuilder.ecdsaSign(session, privateKey, spec)` | ECDSA signing | `Signature` |
| `TagEngineBuilder.ecdsaVerify(session, publicKey, spec)` | ECDSA verification | `Signature` |

Pass `null` for `spec` to use the algorithm-specific default.

## `TagEngine<T>` — interface

| Method | Description |
| --- | --- |
| `wrap(InputStream upstream)` | Return a filtered stream that applies tag computation or verification. |
| `tagLength()` | Fixed tag length in bytes (used to strip or append trailers). |
| `setExpectedTag(byte[])` | Set the expected tag for verify mode. |
| `setVerificationApproach(VerificationBiPredicate)` | Override the outcome handler. |
| `getVerificationCore()` | Return the default predicate (for wrapping with `getThrowOnMismatch()`). |

## Produce example

```java
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.core.alg.digest.DigestSpec;
import java.io.InputStream;

ZeroEchoSession session = new ZeroEchoSession(); // or .withPolicy(…) / .withAuditMode(…)
TagEngineBuilder<byte[]> digestBuilder = TagEngineBuilder.digest(session, DigestSpec.sha256());

TagEngine<byte[]> engine = digestBuilder.get();
try (InputStream tagged = engine.wrap(plaintextStream)) {
    byte[] output = tagged.readAllBytes();
    // Separate body from trailer: last tagLength() bytes are the SHA-256 digest.
    int tLen = engine.tagLength();
    byte[] body = java.util.Arrays.copyOfRange(output, 0, output.length - tLen);
    byte[] tag  = java.util.Arrays.copyOfRange(output, output.length - tLen, output.length);
}
```

## Verify example

```java
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.TagEngineBuilder;
import java.security.PublicKey;

PublicKey verificationKey = /* load from certificate */;
TagEngineBuilder<java.security.Signature> verifyBuilder =
        TagEngineBuilder.ed25519Verify(session, verificationKey);

TagEngine<java.security.Signature> engine = verifyBuilder.get();
engine.setVerificationApproach(engine.getVerificationCore().getThrowOnMismatch());
engine.setExpectedTag(expectedTag); // stripped from the stream externally

try (InputStream verified = engine.wrap(bodyWithoutTrailer)) {
    byte[] body = verified.readAllBytes();
    // If the tag is invalid, readAllBytes() throws VerificationException at EOF.
}
```

## CLI integration

The `zeroecho` CLI accepts a `-T <algorithm>` flag on streaming operations to
attach or verify a tag trailer. The flag selects the algorithm registered with
the session. See [Command-line application](application.md) for flag syntax.

## Thread safety

`TagEngineBuilder` is immutable and thread-safe. Each `TagEngine` instance is
stateful and not thread-safe; use one instance per pipeline run.
