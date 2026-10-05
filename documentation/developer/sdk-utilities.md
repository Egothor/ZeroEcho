# SDK utilities

The `zeroecho.sdk.util` package provides small, focused utilities for key
derivation and password generation. Both classes are stateless and thread-safe.

## `Kdf` — key derivation

`Kdf` exposes a single static method for HKDF-SHA256 key derivation, suitable
for expanding a shared secret (such as the output of an `AgreementContext` or
`HybridKexContext`) into keying material of any required length.

```
Kdf.hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    throws GeneralSecurityException
```

| Parameter | Meaning |
| --- | --- |
| `ikm` | Input keying material (e.g. a raw DH shared secret). |
| `salt` | Optional HMAC salt; `null` uses the RFC 5869 zero-filled default (length of the hash output). |
| `info` | Optional application-specific context label (`null` is accepted). |
| `length` | Output length in bytes; must be positive and at most 255 × hash-output-length (8 160 bytes for SHA-256). |

The call throws `GeneralSecurityException` if the required JCA algorithm is
unavailable or `length` is out of range.

### Example

```java
import zeroecho.sdk.util.Kdf;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.core.context.AgreementContext;

// "Xdh" is the ZeroEcho registry id for XDH; XdhSpec.X25519 selects the X25519 curve.
AgreementContext agreement = session.createContext("Xdh",
        zeroecho.core.KeyUsage.AGREEMENT, myPrivateKey, XdhSpec.X25519);
agreement.setPeerPublic(peerPublicKey);
byte[] rawSecret = agreement.deriveSecret();

byte[] keyMaterial = Kdf.hkdfSha256(
        rawSecret,
        null,                                          // default salt
        "MyProtocol/v1/session-key".getBytes(),        // domain separator
        32);                                           // 256-bit output
```

Zero the `rawSecret` array promptly after calling `hkdfSha256`.

## `Password` — random password generation

`Password` generates random passwords suitable for use as keyring passwords or
one-time credentials. It does not handle storage or verification.

| Method | Description |
| --- | --- |
| `generateRandom(byte[] dest)` | Fills `dest` with cryptographically random bytes. |
| `generatePrintablePasswordChars(int length)` | Returns a `char[]` of `length` printable ASCII characters (printable range 33–126). |

```java
import zeroecho.sdk.util.Password;
import zeroecho.core.storage.KeyringPassword;
import java.util.Arrays;

// Generate a 32-character printable password and hand it to a KeyringPassword.
char[] raw = Password.generatePrintablePasswordChars(32);
try (KeyringPassword password = new KeyringPassword(raw)) {
    Arrays.fill(raw, '\0');         // caller clears its copy; KeyringPassword owns its own
    // use password …
}
// password.destroy() is called automatically by try-with-resources
```

Both methods use a `SecureRandom` source. Always zero the returned `char[]` after
handing it to the consumer; `KeyringPassword` makes its own defensive copy and
clears it when destroyed.
