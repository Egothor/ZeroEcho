# Ext module

The `ext` module (`module zeroecho.ext`) contains experimental integrations that
sit outside the core library. Everything in this module should be treated as
**provisional**: APIs may change without notice between releases.

!!! warning "Experimental"
    The `ext` module is **not** covered by the library's API stability guarantees.
    Production use requires independent review of the specific component.

## Steganography

Package: `zeroecho.ext.integrations.stegano`

### `LSBSteganographyMethod`

Embeds and extracts arbitrary payloads in raster images using the least-significant-bit
(LSB) spatial technique.

| Property | Value |
| --- | --- |
| Technique | LSB, spatial domain, 1 bit per channel |
| Framing | 4-byte big-endian length prefix, then raw payload bytes |
| Capacity | width × height − 32 bits (the prefix consumes 32 pixels worth of LSBs) |
| Output format | Lossless only (PNG, BMP). JPEG is rejected — lossy compression destroys the hidden bits. |
| Colour output | Grayscale (identical R, G, B values). The cover image is converted to grayscale during embedding. |

```java
import zeroecho.ext.integrations.stegano.LSBSteganographyMethod;
import zeroecho.ext.integrations.stegano.SteganographyMethod;
import zeroecho.ext.integrations.stegano.ImageFormat;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

SteganographyMethod method = new LSBSteganographyMethod();

// Embed
try (InputStream cover  = Files.newInputStream(Path.of("cover.png"));
     InputStream secret = new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8));
     InputStream stego  = method.embed(cover, ImageFormat.PNG, secret)) {
    Files.write(Path.of("stego.png"), stego.readAllBytes());
}

// Extract
try (InputStream stego   = Files.newInputStream(Path.of("stego.png"));
     InputStream payload = method.extract(stego)) {
    String recovered = new String(payload.readAllBytes(), StandardCharsets.UTF_8);
}
```

`embed` and `extract` throw `IOException` if the image cannot be decoded, the
cover is too small to hold the payload, or the length prefix in the stego image
is implausible.

## Covert JPEG EXIF channel

Package: `zeroecho.ext.integrations.covert.jpeg`

### `JpegExifEmbedder`

Stores a payload in one or more EXIF tag slots inside a JPEG file without altering
the pixel data or visible metadata.

| Property | Value |
| --- | --- |
| Carrier format | JPEG |
| Framing | Pack7 length framing spread across EXIF tag slots |
| Maximum payload | 1 MiB |
| Dependency | Apache Commons Imaging (must be on the module path) |

Because JPEG is a lossy format, the pixel data is unchanged by this technique —
only EXIF metadata slots are used.

```java
import zeroecho.ext.integrations.covert.jpeg.JpegExifEmbedder;
import zeroecho.ext.integrations.covert.jpeg.Slot;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

JpegExifEmbedder embedder = new JpegExifEmbedder();
// setSlots must be called before embed or extract; use Slot.defaults() for standard EXIF slots.
embedder.setSlots(Slot.defaults());

// Embed: Path carrier, InputStream payload → OutputStream receives output JPEG
try (InputStream payload = new ByteArrayInputStream(
         "secret message".getBytes(StandardCharsets.UTF_8));
     OutputStream out = Files.newOutputStream(Path.of("output.jpg"))) {
    embedder.embed(Path.of("carrier.jpg"), payload, out);
}

// Extract: Path source, OutputStream receives recovered payload bytes
try (ByteArrayOutputStream buf = new ByteArrayOutputStream()) {
    embedder.extract(Path.of("output.jpg"), buf);
    byte[] recovered = buf.toByteArray();
}
```

The payload must not exceed 1 MiB. `embed` and `extract` throw `IOException` on
format errors or capacity overflow.

## Textual codec

Package: `zeroecho.ext.integrations.covert`

### `TextualCodec.Generator`

Generates pseudo-random text that matches a configurable character-frequency
distribution. This is useful for producing natural-looking cover text when hiding
data in text media.

The `Generator` is initialised with a `Map<Character, Double>` that maps characters
to their relative frequency (e.g. English letter frequencies). `getText(int length)`
produces a string of `length` characters drawn from that distribution.

!!! warning "Not thread-safe — create one `Generator` per thread"
    `Generator` carries mutable state. The built-in `ENGLISH` constant and the
    convenience field `EN` are not safe for concurrent use. Always create a new
    instance per thread or confine access.

```java
import zeroecho.ext.integrations.covert.TextualCodec;
import java.util.Map;

// Built-in English distribution — factory creates a fresh (non-shared) instance
TextualCodec.Generator gen = TextualCodec.Generator.english();
String coverText = gen.getText(256);

// Custom distribution: Map<Character, Double> (character → relative frequency)
TextualCodec.Generator custom = new TextualCodec.Generator(
    Map.of('e', 12.7, 't', 9.1, 'a', 8.2, ' ', 25.4));
String cover = custom.getText(128);
```
