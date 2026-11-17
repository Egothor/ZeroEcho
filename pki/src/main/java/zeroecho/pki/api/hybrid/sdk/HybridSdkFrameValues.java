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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import zeroecho.core.spec.AlgorithmIdentity;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Checks non-OCSP SDK frame value registries after immutable framing validation.
 */
final class HybridSdkFrameValues {
    private static final int LIMIT_6 = 6;
    private static final String LIMIT_DIRECT_MTLS_V1 = "direct-mtls-v1";

    private static final byte[] PRIMARY_ALGORITHM = HybridSdkFrame.primaryAlgorithm();
    private static final byte[] ALTERNATIVE_ALGORITHM = HybridSdkFrame.alternativeAlgorithm();
    private static final int DOMAIN_LENGTH = "ZeroEcho-Hybrid-SDK".length();

    private final HybridSdkFrame frame;

    /* default */ HybridSdkFrameValues(HybridSdkFrame frame) {
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

    /* default */ void validate() {
        switch (frame.kind()) {
            case 1, 2 -> requireChallengeValues();
            case 4, 5 -> new HybridSdkOcspValues(frame).validate();
            case 3 -> {
                length(1, 64);
                length(2, 64);
                length(5, 64);
                HybridSdkFrame.requirePrimaryProofSyntax(field(3));
                length(4, 4_627);
            }
            case LIMIT_6 -> requireIdentityValues();
            case 7 -> requireTargetValues();
            case 8, 9 -> requireSigningRoleValues();
            default -> throw invalid();
        }
    }

    private void requireChallengeValues() {
        if (!"zeroecho-hybrid-sdk-v1".equals(text(1))) {
            throw invalid();
        }
        identifier(2);
        for (int tag = 3; tag <= LIMIT_6; tag++) {
            length(tag, 32);
        }
        long issued = time(7);
        long expires = time(8);
        if (issued > Long.MAX_VALUE - 300 || expires != issued + 300) {
            throw invalid();
        }
        HybridSdkFrame.requireOrigin(text(9));
        if (!java.util.Set.of("admin-http-v1", "acme-v1", "est-v1", "scep-v1", "cmp-v1")
                .contains(text(10))) {
            throw invalid();
        }
        for (int tag = 11; tag <= 14; tag++) {
            length(tag, 64);
        }
        length(17, 64);
        if (!Arrays.equals(field(15), PRIMARY_ALGORITHM)
                || !Arrays.equals(field(16), ALTERNATIVE_ALGORITHM)) {
            throw invalid();
        }
    }

    private void requireIdentityValues() {
        identifier(1);
        length(3, 64);
        if (java.util.Set.of(LIMIT_DIRECT_MTLS_V1, "trusted-proxy-mtls-v1").contains(text(2))) {
            if (!"admin-http-v1".equals(text(4))) {
                throw invalid();
            }
            new HybridSdkAuthenticationValues(frame).validate();
        } else {
            new HybridSdkEnrollmentValues(frame).validate();
        }
    }

    private void requireTargetValues() {
        for (int tag : new int[] {1, 3, 4, 5, LIMIT_6, 10}) {
            identifier(tag);
        }
        for (int tag : new int[] {2, 15, 16, 17}) {
            byte[] value = HybridSdkValue.decode(field(tag)).encode();
            if (value[0] != LIMIT_6) {
                throw invalid();
            }
        }
        if (!text(7).matches("sha512:[0-9a-f]{128}") || unsignedLong(11) == 0) {
            throw invalid();
        }
        requireNested(8, 8);
        if (field(9).length != 0) {
            requireNested(9, 9);
        }
        for (int tag = 12; tag <= 14; tag++) {
            if (!text(tag).matches("sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128}")) {
                throw invalid();
            }
        }
    }

    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private void requireSigningRoleValues() {
        new zeroecho.pki.api.KeyRef(text(1));
        if (AlgorithmIdentity.parse(text(2), List.of()).kind() != AlgorithmIdentity.Kind.PUBLIC_KEY
                || AlgorithmIdentity.parse(text(3), List.of()).kind()
                        != AlgorithmIdentity.Kind.SIGNATURE) {
            throw invalid();
        }
        try {
            new zeroecho.pki.impl.framework.x509.StreamingDerReader().validate(field(4), 1_024);
            AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(field(4));
            if (!Arrays.equals(algorithm.getEncoded("DER"), field(4))) {
                throw invalid();
            }
        } catch (IOException malformed) {
            throw invalid();
        }
        length(5, 64);
    }

    private void requireNested(int tag, int expectedKind) {
        byte[] value = field(tag);
        int offset = DOMAIN_LENGTH + 3;
        if (value.length < offset + 2
                || Short.toUnsignedInt(ByteBuffer.wrap(value, offset, 2).getShort())
                        != expectedKind) {
            throw invalid();
        }
        if (HybridSdkFrame.decode(value).kind() != expectedKind) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }
}
