# Multi-recipient encryption (Guard)

The `zeroecho.sdk.guard` package provides multi-recipient data encryption. A single
payload is encrypted once under a fresh content-encryption key (CEK); the CEK is
wrapped independently for each recipient. Any recipient with suitable material can
open the envelope, recover the CEK, and decrypt the payload.

This pattern is suitable for:

- Encrypting files or messages for a group of public-key holders.
- Adding password-based recovery alongside asymmetric recipients.
- Plausibly deniable envelopes with decoy recipients that authenticate without revealing which entry succeeded.

## Concepts

### Envelope structure

The binary envelope contains a recipient table followed by the ciphertext produced
by a symmetric builder (AES-GCM or ChaCha20-Poly1305). The table stores one entry
per recipient; each entry holds an identifier and the wrapped CEK. On decryption,
openers scan the table in order and stop at the first entry they can unwrap.

```
pack7(recipientCount)
for each recipient:
  UTF-8 entryId
  length-prefixed entryBlob
[symmetric header + ciphertext]
```

### Recipients and openers

A `Recipient` (encryption side) writes one entry to the table. A `RecipientOpener`
(decryption side) attempts to read and unwrap that entry. The default opener set
installed by the builder covers:

| Recipient type | Entry id pattern | Opener |
| --- | --- | --- |
| `KemCtxRecipient` | `KEM:<algId>:GCM-WRAP` | `KemCtxOpener` |
| `EncCtxRecipient` | `ENC:<algId>` | `EncCtxOpener` |
| `PasswordRecipient` | `PBKDF2:HMAC-SHA256` | `PasswordOpener` |

### Decoy recipients

Each recipient type has a decoy variant (`addRecipientDecoy`, `addPasswordRecipientDecoy`).
Decoy entries are structurally indistinguishable from genuine entries. They are
discarded silently when no opener succeeds on them. This allows a sender to add
cover traffic so that an observer cannot count genuine recipients.

## API overview

### `MultiRecipientDataSourceBuilder`

The builder constructs either an encrypting or a decrypting `MultiRecipientContent`
depending on the boolean argument to `build(boolean)`.

| Method | Description |
| --- | --- |
| `MultiRecipientDataSourceBuilder.builder(session)` | Create a fresh builder. |
| `withAes(AesDataContentBuilder)` | Select AES-GCM as the symmetric cipher. |
| `withChaCha(ChaChaDataContentBuilder)` | Select ChaCha20-Poly1305 as the symmetric cipher. |
| `payloadKeyBytes(int)` | CEK length (16 or 32 for AES, 32 for ChaCha). |
| `addPasswordRecipient(char[], iterations, saltLen, kekBytes)` | PBKDF2-derived KEK recipient. |
| `addRecipient(KemContext, kekBytes, saltLen)` | KEM-based recipient. |
| `addRecipient(EncryptionContext)` | Asymmetric-encryption recipient (RSA-OAEP, ECIES, …). |
| `addPasswordRecipientDecoy(…)` / `addRecipientDecoy(…)` | Matching decoy variants. |
| `unlockWith(UnlockMaterial)` | Provide the key or password for decryption. |
| `addOpener(RecipientOpener)` | Override the default opener set. |
| `headerLimits(maxRecipients, maxEntryLen)` | Bound parsing to guard against resource exhaustion. |
| `build(true)` | Build an encrypting content wrapper. |
| `build(false)` | Build a decrypting content wrapper. |

The builder implements `AutoCloseable`. It zeros recipient secrets that have not
been transferred to a successfully built content object.

### `RecipientOpener`

An `AutoCloseable` that attempts to recover the CEK from one recipient entry. The
default set is installed automatically by `build(false)` unless custom openers are
added. Custom openers are useful when the private key material lives in an HSM or
remote service.

## Encryption example

```java
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.guard.MultiRecipientDataSourceBuilder;
import zeroecho.sdk.guard.MultiRecipientContent;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.PlainContent;
import java.io.InputStream;
import java.security.PublicKey;

ZeroEchoSession session = new ZeroEchoSession(); // or withPolicy/withAuditMode for custom configuration
PublicKey recipientPublicKey = /* load from certificate */;
byte[] plaintext = /* data to encrypt */;

try (MultiRecipientDataSourceBuilder builder =
        MultiRecipientDataSourceBuilder.builder(session)) {

    AesDataContentBuilder aes = AesDataContentBuilder.builder(session)
            .generateKey(256).modeGcm(128).withHeader();
    builder.withAes(aes)
           .payloadKeyBytes(32)
           .addRecipient(
               session.createContext("ML-KEM", zeroecho.core.KeyUsage.ENCAPSULATE,
                                     recipientPublicKey, null),
               32, 32);

    MultiRecipientContent content = builder.build(true);
    PlainContent input = PlainBytesBuilder.builder().bytes(plaintext).build(false);
    content.setInput(input);
    byte[] ciphertext;
    try (InputStream out = content.getStream()) {
        ciphertext = out.readAllBytes();
    }
}
```

## Decryption example

```java
import zeroecho.sdk.guard.MultiRecipientDataSourceBuilder;
import zeroecho.sdk.guard.MultiRecipientContent;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.guard.UnlockMaterial;
import java.io.InputStream;
import java.security.PrivateKey;

PrivateKey recipientPrivateKey = /* loaded from keyring */;
byte[] ciphertextBytes = /* ciphertext produced during encryption */;

try (MultiRecipientDataSourceBuilder builder =
        MultiRecipientDataSourceBuilder.builder(session)) {

    AesDataContentBuilder aes = AesDataContentBuilder.builder(session)
            .generateKey(256).modeGcm(128).withHeader();
    builder.withAes(aes)
           .payloadKeyBytes(32)
           .unlockWith(new UnlockMaterial.Private(recipientPrivateKey));

    MultiRecipientContent content = builder.build(false);
    PlainContent input = PlainBytesBuilder.builder().bytes(ciphertextBytes).build(false);
    content.setInput(input);
    byte[] decrypted;
    try (InputStream out = content.getStream()) {
        decrypted = out.readAllBytes();
    }
}
```

## Thread safety

`MultiRecipientDataSourceBuilder` and the built `MultiRecipientContent` are not
thread-safe. Each encrypt or decrypt operation requires its own builder and content
instance.

## Security notes

- Call `builder.close()` (or use try-with-resources) so that recipient password
  buffers and intermediate key material are zeroed promptly.
- The CEK is generated freshly for every `build(true)` call; never reuse a content
  object across separate plaintexts.
- PBKDF2 iteration counts below `Pbkdf2Limits#MINIMUM` are rejected. Use the
  session's `pbkdf2Limits()` to obtain the operator-configured floor for trusted
  internal use.
