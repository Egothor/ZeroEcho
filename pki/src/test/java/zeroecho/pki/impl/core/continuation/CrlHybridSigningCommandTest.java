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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.store.DomainContinuationStore;

/**
 * Contract and regression tests for CRL hybrid signing command.
 */
class CrlHybridSigningCommandTest {
    private static final PkiId PARENT = new PkiId("zsign:v1:c036:1767225600000:0123456789abcdef0123456789abcdef");
    private static final PkiId CHILD = new PkiId("zsign:v1:c036:1767225600000:2e07573efce49cc18d99204619063f57");

    /**
     * Native child identity has independent golden nonce and preserves namespace and time.
     */
    @Test void nativeChildIdentityHasIndependentGoldenNonceAndPreservesNamespaceAndTime() {
        assertEquals(CHILD, CrlHybridSigningCommand.nativeChildId(PARENT));
        assertEquals(SigningSubmissionId.parse(PARENT).namespace(), SigningSubmissionId.parse(CHILD).namespace());
        assertEquals(SigningSubmissionId.parse(PARENT).createdAt(), SigningSubmissionId.parse(CHILD).createdAt());
        for (PkiId other : List.of(
                new PkiId("zsign:v1:other:1767225600000:0123456789abcdef0123456789abcdef"),
                new PkiId("zsign:v1:c036:1767225600001:0123456789abcdef0123456789abcdef"),
                new PkiId("zsign:v1:c036:1767225600000:1123456789abcdef0123456789abcdef"))) {
            assertNotEquals(CHILD, CrlHybridSigningCommand.nativeChildId(other));
        }
        assertThrows(IllegalArgumentException.class, () -> CrlHybridSigningCommand.nativeChildId(new PkiId("signing:unsupported")));
    }

    /**
     * Full and delta variants retain native algorithm and require the nine field descriptor.
     */
    @Test void fullAndDeltaVariantsRetainNativeAlgorithmAndRequireTheNineFieldDescriptor() {
        var descriptor = descriptor(4627, 104);
        for (boolean delta : new boolean[] {false, true}) {
            String[] fields = fields(delta, descriptor.encode());
            var command = decode(delta, fields);
            assertTrue(CrlHybridSigningCommand.isHybrid(command));
            assertEquals(descriptor, CrlHybridSigningCommand.descriptor(command));
            FullCrlSigningCommand.validate(command);
            assertEquals(BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(), command.field(8));
            String[] classical = Arrays.copyOf(fields, fields.length - 1);
            classical[5] = "managed:native";
            var old = decode(delta, classical);
            assertFalse(CrlHybridSigningCommand.isHybrid(old));
            FullCrlSigningCommand.validate(old);
            assertThrows(IllegalArgumentException.class, () -> CrlHybridSigningCommand.descriptor(old));
            fields[5] = "managed:unexpected-hybrid-key";
            assertThrows(IllegalArgumentException.class, () -> CrlHybridSigningCommand.descriptor(decode(delta, fields)));
        }
    }

    /**
     * Rejects noncanonical versions roles bounds and descriptor encodings.
     */
    @Test void rejectsNoncanonicalVersionsRolesBoundsAndDescriptorEncodings() {
        for (int[] bounds : new int[][] {{1, 1_048_576}, {1_048_576, 1}}) {
            var value = descriptor(bounds[0], bounds[1]);
            assertEquals(value, CrlHybridSigningCommand.descriptor(decode(false, fields(false, value.encode()))));
        }
        for (int invalid : new int[] {0, -1, 1_048_577}) {
            assertThrows(IllegalArgumentException.class, () -> descriptor(invalid, 104));
            assertThrows(IllegalArgumentException.class, () -> descriptor(4627, invalid));
        }
        String[] valid = {"1", CrlHybridSigningCommand.PROFILE, "a".repeat(64), "b".repeat(64), CHILD.value(),
                "c".repeat(64), "d".repeat(64), "4627", "104"};
        for (String[] replacement : new String[][] {{"0", "2"}, {"1", "unknown-profile"}, {"2", "A".repeat(64)},
                {"3", "not-a-tuple"}, {"4", "signing:wrong-child"}, {"5", "e".repeat(63)},
                {"6", "unknown-plan"}, {"7", "04627"}, {"8", "+104"}, {"8", "1048577"}}) {
            String[] changed = valid.clone(); changed[Integer.parseInt(replacement[0])] = replacement[1];
            assertThrows(IllegalArgumentException.class, () -> CrlHybridSigningCommand.descriptor(decode(false, fields(false, encoded(changed)))));
        }
        for (String malformed : List.of(descriptor(4627, 104).encode() + "=", "!", "A".repeat(16_385),
                encoded(Arrays.copyOf(valid, 8)), encoded(Arrays.copyOf(valid, 10)))) {
            assertThrows(IllegalArgumentException.class, () -> CrlHybridSigningCommand.descriptor(decode(false, fields(false, malformed))));
        }
    }

    private static CrlHybridSigningCommand.Descriptor descriptor(int alternative, int primary) {
        return new CrlHybridSigningCommand.Descriptor("a".repeat(64), "b".repeat(64), CHILD,
                "c".repeat(64), "d".repeat(64), alternative, primary);
    }

    private static String encoded(String[] fields) {
        // A missing suffix is encoded as an extra empty scalar, never a Java null.
        String[] values = fields.clone();
        for (int index = 0; index < values.length; index++) if (values[index] == null) values[index] = "";
        return Base64.getUrlEncoder().withoutPadding().encodeToString(DomainCommandEncoding.template(
                DomainContinuationStore.Kind.STATUS, "CRL_HYBRID_V1", values).command().bytes());
    }

    private static DomainCommandEncoding.Decoded decode(boolean delta, String[] fields) {
        return DomainCommandEncoding.decode(DomainCommandEncoding.template(DomainContinuationStore.Kind.STATUS,
                delta ? FullCrlSigningCommand.DELTA_OPERATION : FullCrlSigningCommand.OPERATION, fields).command());
    }

    private static String[] fields(boolean delta, String descriptor) {
        String[] fields = new String[delta ? 37 : 32];
        Arrays.fill(fields, "");
        fields[0] = "ca:fixture"; fields[1] = delta ? "DELTA_CRL" : "CRL"; fields[2] = "x509";
        fields[3] = "2026-01-01T00:00:00Z"; fields[4] = "2026-01-02T00:00:00Z";
        fields[6] = "issuer:" + "a".repeat(32); fields[7] = "x509:" + "a".repeat(64);
        fields[8] = BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm();
        fields[9] = "300a06082a8648ce3d040303"; fields[10] = "7";
        for (int index : new int[] {11, 14, 15, 16, 22, 26, 28}) fields[index] = "a".repeat(64);
        fields[12] = "root"; fields[13] = "1"; fields[17] = "zeroecho.signature.ecdsa-sha384";
        fields[18] = "binding-v1"; fields[19] = "snapshot:fixture";
        fields[20] = "2"; fields[21] = "3"; fields[23] = "0"; fields[24] = "0";
        fields[25] = "1"; fields[27] = "1"; fields[29] = fields[3]; fields[30] = "a".repeat(32);
        if (delta) {
            fields[31] = "crl:" + "b".repeat(64); fields[32] = "6";
            fields[33] = "1"; fields[34] = "2"; fields[35] = "b".repeat(64);
        }
        fields[fields.length - 1] = descriptor;
        return fields;
    }
}
