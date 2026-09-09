/*******************************************************************************
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
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

/** Independently integrity-checked version-one signing WAL container preamble. */
final class SigningWalContainerCodec {

    /* default */ static final int MAGIC = 0x5A455743;
    /* default */ static final short VERSION = 1;
    /* default */ static final int HEADER_BYTES = 64;

    private static final short FLAGS = 0;
    private static final int FIELDS_BYTES = HEADER_BYTES - SigningFormatSupport.SHA_256_BYTES;

    private SigningWalContainerCodec() {
        // utility class
    }

    /* default */ static byte[] encode(Header header) {
        requireHeader(header);
        ByteBuffer output = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        output.putInt(MAGIC);
        output.putShort(VERSION);
        output.putShort(FLAGS);
        output.putLong(header.identity());
        output.putLong(header.firstSequence());
        output.putLong(header.baselineRevision());
        MessageDigest digest = SigningFormatSupport.sha256();
        digest.update(output.array(), 0, FIELDS_BYTES);
        output.put(digest.digest());
        return output.array();
    }

    /* default */ static Header decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length != HEADER_BYTES) {
            throw invalid("signing WAL container header is truncated");
        }
        MessageDigest digest = SigningFormatSupport.sha256();
        digest.update(encoded, 0, FIELDS_BYTES);
        byte[] supplied = Arrays.copyOfRange(encoded, FIELDS_BYTES, HEADER_BYTES);
        if (!MessageDigest.isEqual(digest.digest(), supplied)) {
            throw invalid("signing WAL container integrity check failed");
        }
        ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        int magic = input.getInt();
        short version = input.getShort();
        short flags = input.getShort();
        Header header = new Header(input.getLong(), input.getLong(), input.getLong());
        if (magic != MAGIC) {
            throw invalid("signing WAL container magic is invalid");
        }
        if (version != VERSION) {
            throw invalid("signing WAL container version is unsupported");
        }
        if (flags != FLAGS || header.identity() < 0L || header.firstSequence() < 0L
                || header.baselineRevision() < 0L) {
            throw invalid("signing WAL container header is invalid");
        }
        return header;
    }

    private static void requireHeader(Header header) {
        if (header == null || header.identity() < 0L || header.firstSequence() < 0L
                || header.baselineRevision() < 0L) {
            throw new IllegalArgumentException("signing WAL container header is invalid");
        }
    }

    private static IOException invalid(String diagnostic) {
        return SigningFormatSupport.invalid(diagnostic);
    }

    /* default */ record Header(long identity, long firstSequence, long baselineRevision) {
    }
}
