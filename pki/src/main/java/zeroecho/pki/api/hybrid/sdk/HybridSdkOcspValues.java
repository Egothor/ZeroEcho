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


import zeroecho.core.spec.AlgorithmIdentity;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Validates the syntax of SDK OCSP evidence fields.
 */
final class HybridSdkOcspValues {

    private static final byte[] PRIMARY_ALGORITHM = HybridSdkFrame.primaryAlgorithm();
    private static final byte[] ALTERNATIVE_ALGORITHM = HybridSdkFrame.alternativeAlgorithm();

    private final HybridSdkFrame frame;

    /* default */ HybridSdkOcspValues(HybridSdkFrame frame) {
        this.frame = frame;
    }

    private byte[] field(int tag) {
        return frame.field(tag);
    }

    private String text(int tag) {
        return HybridSdkValue.text(field(tag));
    }

    private void length(int tag, int required) {
        if (field(tag).length != required) {
            throw invalid();
        }
    }

    private void identifier(int tag) {
        HybridSdkValue.requireIdentifier(text(tag));
    }

    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private long time(int tag) {
        long value = unsignedLong(tag);
        try {
            Instant.ofEpochSecond(value);
        } catch (java.time.DateTimeException unsupported) {
            throw invalid();
        }
        return value;
    }

    private long unsignedLong(int tag) {
        length(tag, 8);
        long value = ByteBuffer.wrap(field(tag)).getLong();
        if (value < 0) {
            throw invalid();
        }
        return value;
    }

    private void requireOcspEvidenceValues() {
        if (!"zeroecho-hybrid-sdk-v1".equals(text(1))) {
            throw invalid();
        }
        identifier(2);
        HybridSdkFrame.requireOrigin(text(3));
        length(4, 32);
        for (int tag = 5; tag <= 8; tag++) {
            length(tag, 64);
        }
        for (int tag = 9; tag <= 11; tag++) {
            identifier(tag);
        }
        if (!text(12).matches("(?:sha256:)?[0-9a-f]{64}") || !text(13).matches("[0-9a-f]{64}")) {
            throw invalid();
        }
        Map<String, HybridSdkValue> roles = HybridSdkValue.decode(field(14)).objectFields();
        if (!roles.keySet().equals(java.util.Set.of("primary", "alternative"))) {
            throw invalid();
        }
        requireOcspRole(roles.get("primary"), PRIMARY_ALGORITHM);
        requireOcspRole(roles.get("alternative"), ALTERNATIVE_ALGORITHM);
        requireOcspTimesAndNonce();
        HybridSdkOcspStatusValues.requireStatuses(HybridSdkValue.decode(field(21)));
    }

    private void requireOcspTimesAndNonce() {
        long produced = time(15);
        long update = time(16);
        long next = time(17);
        long issued = time(18);
        long expires = time(19);
        if (update > produced
                || next <= update
                || issued < produced
                || expires <= issued
                || expires > next
                || issued > Long.MAX_VALUE - 120
                || expires > issued + 120) {
            throw invalid();
        }
        Map<String, HybridSdkValue> nonce = HybridSdkValue.decode(field(20)).objectFields();
        if (!nonce.keySet().equals(java.util.Set.of("present", "value"))) {
            throw invalid();
        }
        byte[] present = nonce.get("present").encode();
        byte[] value = nonce.get("value").encode();
        if ((!Arrays.equals(present, HybridSdkValue.bool(true).encode())
                        && !Arrays.equals(present, HybridSdkValue.bool(false).encode()))
                || value[0] != 4
                || Arrays.equals(present, HybridSdkValue.bool(false).encode())
                        && value.length != 5) {
            throw invalid();
        }
    }

    /* default */ static void requireOcspRole(HybridSdkValue value, byte[] algorithm) {
        Map<String, HybridSdkValue> role = value.objectFields();
        if (!role.keySet()
                .equals(
                        java.util.Set.of(
                                "spki",
                                "publicKeyAlgorithm",
                                "signatureAlgorithm",
                                "algorithmIdentifier"))) {
            throw invalid();
        }
        if (AlgorithmIdentity.parse(role.get("publicKeyAlgorithm").textValue(), List.of()).kind()
                        != AlgorithmIdentity.Kind.PUBLIC_KEY
                || AlgorithmIdentity.parse(role.get("signatureAlgorithm").textValue(), List.of())
                                .kind()
                        != AlgorithmIdentity.Kind.SIGNATURE) {
            throw invalid();
        }
        if (!Arrays.equals(
                role.get("algorithmIdentifier").encode(),
                HybridSdkValue.bytes(algorithm).encode())) {
            throw invalid();
        }
        byte[] spki = role.get("spki").encode();
        if (spki[0] != 4 || spki.length <= 5) {
            throw invalid();
        }
    }

    /* default */ void validate() {
        requireOcspEvidenceValues();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }
}
