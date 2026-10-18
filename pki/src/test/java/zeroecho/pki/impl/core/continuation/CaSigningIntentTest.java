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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

final class CaSigningIntentTest {
    private static final String HASH = "1".repeat(64);
    private static final String EMPTY_ATTRIBUTES = DomainAttributeEncoding.encode(new SimpleAttributeSet());

    @ParameterizedTest
    @ValueSource(strings = {IntermediateSigningCommand.CREATE, IntermediateSigningCommand.ISSUE, IntermediateSigningCommand.ROLLOVER})
    void everyNonproofCoordinateChangesTheCommitment(String operation) {
        DomainCommandEncoding.Decoded command = command(operation);
        String original = commit(command);
        assertTrue(original.matches("ca-intent:v1:[0-9a-f]{64}"));
        assertEquals(original, commit(new DomainCommandEncoding.Decoded(operation, new ArrayList<>(command.fields()))));
        for (int index = 0; index < 23; index++) {
            if (index == 18 || index == 19) { continue; }
            String value = switch (index) {
                case 5, 9, 16, 17, 22 -> "2".repeat(64);
                case 8, 13, 21 -> "2";
                case 11 -> "1970-01-01T00:00:01Z";
                case 12 -> "1970-01-01T00:02:00Z";
                case 20 -> DomainAttributeEncoding.encode(new SimpleAttributeSet(List.of(new SimpleAttributeSet.Entry(
                        new AttributeId("urn:test:intent"), List.of(new AttributeValue.StringValue("changed"))))));
                default -> "changed";
            };
            assertNotEquals(original, commit(changed(command, index, value)), "Unbound field " + index);
        }
        assertNotEquals(original, CaSigningIntent.commitment(command, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256));
    }

    @Test
    void proofReferenceAndCommandRemainExcludedAndOperationIsBound() {
        DomainCommandEncoding.Decoded original = command(IntermediateSigningCommand.CREATE);
        String commitment = commit(original);
        assertEquals(commitment, CaSigningIntent.commitmentOfCanonicalAlgorithm(original,
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm()));
        assertEquals(commitment, commit(changed(original, 18, "future-proof-step")));
        assertEquals(commitment, commit(changed(original, 19, "future-proof-command")));
        assertNotEquals(commitment, commit(command(IntermediateSigningCommand.ISSUE)));
        assertNotEquals(commitment, commit(command(IntermediateSigningCommand.ROLLOVER)));
        // Framing must distinguish coordinate boundaries, not only concatenated bytes.
        DomainCommandEncoding.Decoded left = changed(changed(original, 3, "ab"), 4, "c");
        DomainCommandEncoding.Decoded right = changed(changed(original, 3, "a"), 4, "bc");
        assertNotEquals(commit(left), commit(right));
    }

    @Test
    void rejectsMalformedNonproofValuesAndWrongSchema() {
        DomainCommandEncoding.Decoded original = command(IntermediateSigningCommand.CREATE);
        for (int index : new int[] {0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 20, 21, 22}) {
            assertThrows(IllegalArgumentException.class, () -> commit(changed(original, index, "")), "Invalid field " + index);
        }
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 8, "01")));
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 11, "1970-01-01T00:00:00.000Z")));
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 13, "+1")));
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 17, "A".repeat(64))));
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 21, "1048577")));
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 10, "\uD800")));
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 7, "x".repeat(257))));
        assertThrows(IllegalArgumentException.class, () -> commit(new DomainCommandEncoding.Decoded("CREATE_ROOT", original.fields())));
        assertThrows(IllegalArgumentException.class, () -> commit(new DomainCommandEncoding.Decoded(original.operation(), original.fields().subList(0, 21))));
        assertThrows(IllegalArgumentException.class, () -> CaSigningIntent.commitment(original, BootstrapAlgorithmIdentities.SHA256));
        assertThrows(NullPointerException.class, () -> CaSigningIntent.commitment(null, BootstrapAlgorithmIdentities.ED25519_SIGNATURE));
        assertThrows(NullPointerException.class, () -> CaSigningIntent.commitment(original, null));
    }

    @Test
    void exactAggregateBoundCountsDomainAlgorithmAndFraming() {
        DomainCommandEncoding.Decoded original = command(IntermediateSigningCommand.CREATE);
        int size = 4 + "zeroecho.ca-signing-intent:v1".length() + 4 + original.operation().length()
                + 4 + BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm().length() + 4;
        for (int index = 0; index < 23; index++) {
            if (index != 18 && index != 19) { size += 4 + original.field(index).length(); }
        }
        String exact = original.field(10) + "x".repeat(ManagedKeyProofCommand.MAX_COMMAND_BYTES - size);
        assertTrue(commit(changed(original, 10, exact)).startsWith("ca-intent:v1:"));
        assertThrows(IllegalArgumentException.class, () -> commit(changed(original, 10, exact + 'x')));
    }

    @Test
    void existingOperationsAllowTheSameSubjectAndParentKeyButCreationDoesNot() {
        DomainCommandEncoding.Decoded create = changed(command(IntermediateSigningCommand.CREATE), 14, "subject-key");
        assertThrows(IllegalArgumentException.class, () -> commit(create));
        assertTrue(commit(new DomainCommandEncoding.Decoded(IntermediateSigningCommand.ISSUE, create.fields())).startsWith("ca-intent:v1:"));
        assertTrue(commit(new DomainCommandEncoding.Decoded(IntermediateSigningCommand.ROLLOVER, create.fields())).startsWith("ca-intent:v1:"));
    }

    private static String commit(DomainCommandEncoding.Decoded command) {
        return CaSigningIntent.commitment(command, BootstrapAlgorithmIdentities.ED25519_SIGNATURE);
    }
    private static DomainCommandEncoding.Decoded changed(DomainCommandEncoding.Decoded command, int index, String value) {
        List<String> fields = new ArrayList<>(command.fields());
        fields.set(index, value);
        return new DomainCommandEncoding.Decoded(command.operation(), fields);
    }
    private static DomainCommandEncoding.Decoded command(String operation) {
        return new DomainCommandEncoding.Decoded(operation, List.of("x509", "parent", "subject", "generation", "path",
                HASH, "subject-key", "profile", "1", HASH, "CN=Child", "1970-01-01T00:00:00Z", "1970-01-01T00:01:00Z",
                "1", "parent-key", "issuer-content", HASH, HASH, "", "", EMPTY_ATTRIBUTES, "1", HASH));
    }
}
