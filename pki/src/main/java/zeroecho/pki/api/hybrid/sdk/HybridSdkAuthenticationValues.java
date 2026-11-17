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
package zeroecho.pki.api.hybrid.sdk;



import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 * Checks direct/proxied administrative identity binding values.
 */
final class HybridSdkAuthenticationValues {
    private static final String LIMIT_DIRECT_MTLS_V1 = "direct-mtls-v1";
    private static final String LIMIT_TRANSPORTPRINCIPALID = "transportPrincipalId";
    private static final int LIMIT_6 = 6;
    private final HybridSdkFrame frame;

    /* default */ HybridSdkAuthenticationValues(HybridSdkFrame frame) {
        this.frame = frame;
    }

    private byte[] field(int tag) {
        return frame.field(tag);
    }

    private String text(int tag) {
        return HybridSdkValue.text(field(tag));
    }

    // Preserve the finite safe parser failure without exposing untrusted causes.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ void validate() {
        byte[] encoded = HybridSdkValue.decode(field(5)).encode();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readUnsignedByte() != LIMIT_6 || input.readInt() != 3) {
                throw invalid();
            }
            for (String expected :
                    new String[] {
                        "canonicalKeySha256", "issuerSerialSha256", LIMIT_TRANSPORTPRINCIPALID
                    }) {
                int length = input.readUnsignedShort();
                if (length > 128
                        || !expected.equals(HybridSdkValue.text(input.readNBytes(length)))
                        || input.readUnsignedByte() != 1) {
                    throw invalid();
                }
                int bytes = input.readInt();
                if (bytes < 0 || bytes > 128 || bytes > input.available()) {
                    throw invalid();
                }
                String value = HybridSdkValue.text(input.readNBytes(bytes));
                requireAuthenticationValue(expected, value);
            }
            if (input.available() != 0) {
                throw invalid();
            }
        } catch (IOException malformed) {
            throw invalid();
        }
    }

    private void requireAuthenticationValue(String expected, String value) {
        if (LIMIT_TRANSPORTPRINCIPALID.equals(expected)) {
            requireTransportPrincipal(value);
        } else if (!value.matches("[0-9a-f]{64}")) {
            throw invalid();
        }
    }

    private void requireTransportPrincipal(String value) {
        if (LIMIT_DIRECT_MTLS_V1.equals(text(2))) {
            if (!value.isEmpty()) { throw invalid(); }
        } else { HybridSdkValue.requireIdentifier(value); }
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }
}
