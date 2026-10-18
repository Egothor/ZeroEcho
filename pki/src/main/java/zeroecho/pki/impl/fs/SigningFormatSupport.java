/* *****************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.Arrays;

/** Shared bounded I/O and canonical-encoding operations for signing formats. */
final class SigningFormatSupport {

    /* default */ static final int SHA_256_BYTES = 32;
    /* default */ static final int TRANSFER_BYTES = 16 * 1024;

    private SigningFormatSupport() {
        // utility class
    }

    /* default */ static void writeFully(WritableByteChannel channel, ByteBuffer source)
            throws IOException {
        while (source.hasRemaining()) {
            if (channel.write(source) == 0) {
                throw new IOException("signing format I/O made no write progress");
            }
        }
    }

    /**
     * Forces one directory's entry updates to durable storage on platforms that
     * permit opening a directory as a channel.
     *
     * <p>
     * POSIX platforms allow opening a directory for {@code fsync}; there the
     * force is strict and a genuine {@code force} failure propagates so that the
     * caller can treat the publication as durability-uncertain. Platforms that
     * forbid opening a directory as a channel, notably Windows, cannot fsync a
     * directory through the standard file API, so directory durability is a
     * no-op there rather than a hard failure. The open itself is the only
     * platform-capability probe: on POSIX it always succeeds for an owned
     * directory, so this method never hides a real fsync error there.
     * </p>
     *
     * @param directory existing directory whose entry updates must be durable
     * @throws IOException if the directory can be opened but forcing it fails
     */
    // Delegates to the resolved platform strategy: a genuine directory fsync on
    // POSIX (a real force failure propagates), a correct no-op on Windows where
    // directory durability is carried by the write-through atomic publish.
    /* default */ static void forceDirectory(Path directory) throws IOException {
        PlatformFs.forceDirectory(directory);
    }

    /* default */ static int readAvailable(ReadableByteChannel channel, ByteBuffer target)
            throws IOException {
        int total = 0;
        while (target.hasRemaining()) {
            int read = channel.read(target);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                throw new IOException("signing format I/O made no read progress");
            }
            total = Math.addExact(total, read);
        }
        return total;
    }

    /* default */ static void readFully(ReadableByteChannel channel, ByteBuffer target,
            String diagnostic) throws IOException {
        int expected = target.remaining();
        if (readAvailable(channel, target) != expected) {
            throw invalid(diagnostic);
        }
    }

    // Encoder diagnostics are deliberately replaced with a stable redacted message.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static byte[] strictUtf8(String value, int maximumBytes) {
        if (maximumBytes < 0) {
            throw new IllegalArgumentException("signing format text bound is invalid");
        }
        if (value == null || value.isEmpty() || value.length() > maximumBytes
                || !Normalizer.isNormalized(value, Normalizer.Form.NFC)) {
            throw new IllegalArgumentException("signing format text is not canonical");
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) {
                throw new IllegalArgumentException("signing format text is not canonical");
            }
        }
        try {
            CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            ByteBuffer encoded = encoder.encode(CharBuffer.wrap(value));
            if (encoded.remaining() > maximumBytes) {
                throw new IllegalArgumentException("signing format text exceeds its bound");
            }
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            String roundTrip = decodeUtf8(bytes);
            if (!value.equals(roundTrip)) {
                throw new IllegalArgumentException("signing format text is not canonical");
            }
            return bytes;
        } catch (IOException failure) {
            throw new IllegalArgumentException("signing format text is invalid");
        }
    }

    // Decoder diagnostics are deliberately replaced with a stable redacted message.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static String decodeUtf8(byte[] bytes) throws IOException {
        try {
            CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            String value = decoded.toString();
            if (!Normalizer.isNormalized(value, Normalizer.Form.NFC)) {
                throw invalid("signing format text is not canonical");
            }
            return value;
        } catch (CharacterCodingException failure) {
            throw invalid("signing format text is invalid");
        }
    }

    /** Decodes one bounded canonical nonempty text field without re-encoding it. */
    /* default */ static String decodeCanonicalUtf8(byte[] bytes, int maximumBytes)
            throws IOException {
        if (bytes == null || bytes.length == 0 || bytes.length > maximumBytes) {
            throw invalid("signing format text length is invalid");
        }
        String value = decodeUtf8(bytes);
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) {
                throw invalid("signing format text is not canonical");
            }
        }
        return value;
    }

    /* default */ static int compareUnsigned(byte[] first, byte[] second) {
        return Arrays.compareUnsigned(first, second);
    }

    /* default */ static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    /* default */ static IOException invalid(String diagnostic) {
        return new IOException(diagnostic);
    }
}
