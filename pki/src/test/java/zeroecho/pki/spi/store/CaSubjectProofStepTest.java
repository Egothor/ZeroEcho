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

package zeroecho.pki.spi.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.DetailCode;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;

final class CaSubjectProofStepTest {
    private static final PkiId STEP = id("provider", "1");
    private static final KeyRef KEY = new KeyRef("private-key-coordinate");
    private static final String HASH = "a".repeat(64);

    @Test
    void descriptorIsStructuralAndRequiresADistinctCanonicalParentInTheSameNamespace() {
        DurableContentReference challenge = reference(Encoding.BINARY, 32, HASH, DurableContentReference.Lifecycle.OPERATION);
        SignWorkflowStore.CaSubjectProofStep step = step(challenge);
        step.requireParent(id("provider", "2"));
        assertEquals(STEP, step.operationId());
        assertEquals(KEY, step.subjectKeyRef());
        assertEquals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), step.algorithmId());
        assertEquals(challenge, step.challenge());
        assertFalse(step.toString().contains(KEY.value()));
        assertFalse(step.toString().contains(STEP.value()));
        assertFalse(step.toString().contains(HASH));
        assertThrows(IllegalArgumentException.class, () -> step.requireParent(STEP));
        assertThrows(IllegalArgumentException.class, () -> step.requireParent(id("other", "2")));
        assertThrows(IllegalArgumentException.class, () -> step.requireParent(new PkiId("zsign:v1:provider:00:" + "2".repeat(32))));
        assertThrows(NullPointerException.class, () -> step.requireParent(null));
    }

    @Test
    void descriptorRejectsMalformedIdentityAlgorithmAndChallengeBounds() {
        DurableContentReference valid = reference(Encoding.BINARY, 1, HASH, DurableContentReference.Lifecycle.OPERATION);
        assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofStep(
                new PkiId("ordinary-id"), KEY, BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), valid));
        assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofStep(
                id("provider", "A"), KEY, BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), valid));
        assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofStep(
                STEP, new KeyRef("\uD800"), BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), valid));
        assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofStep(
                STEP, new KeyRef("x".repeat(1_048_577)), BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), valid));
        assertThrows(NullPointerException.class, () -> step(null));
        for (long invalidLength : new long[] {-1, 0, SignWorkflowStore.CaSubjectProofStep.MAXIMUM_CHALLENGE_BYTES + 1L}) {
            assertThrows(IllegalArgumentException.class, () -> step(reference(Encoding.BINARY, invalidLength, HASH,
                    DurableContentReference.Lifecycle.OPERATION)));
        }
        step(reference(Encoding.BINARY, SignWorkflowStore.CaSubjectProofStep.MAXIMUM_CHALLENGE_BYTES, HASH,
                DurableContentReference.Lifecycle.OPERATION));
        assertThrows(IllegalArgumentException.class, () -> step(reference(Encoding.DER, 1, HASH, DurableContentReference.Lifecycle.OPERATION)));
        assertThrows(IllegalArgumentException.class, () -> step(reference(Encoding.BINARY, 1, HASH, DurableContentReference.Lifecycle.PERSISTED)));
        assertThrows(IllegalArgumentException.class, () -> step(reference(Encoding.BINARY, 1, HASH.toUpperCase(java.util.Locale.ROOT),
                DurableContentReference.Lifecycle.OPERATION)));
    }

    @Test
    void algorithmTextRetainsExactValueAndRequiresOnlyBoundedStrictUtf8() {
        DurableContentReference valid = reference(Encoding.BINARY, 1, HASH, DurableContentReference.Lifecycle.OPERATION);
        for (String exact : new String[] {"installed-extension-identity", "x".repeat(8192), "é".repeat(4096)}) {
            assertEquals(exact, new SignWorkflowStore.CaSubjectProofStep(STEP, KEY, exact, valid).algorithmId());
        }
        // Storage shape does not perform the selected authority's semantic kind check.
        String digest = BootstrapAlgorithmIdentities.SHA256.canonicalForm();
        assertEquals(digest, new SignWorkflowStore.CaSubjectProofStep(STEP, KEY, digest, valid).algorithmId());
        for (String malformed : new String[] {"", " ", "x".repeat(8193), "é".repeat(4097), "\uD800", "\uDC00"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new SignWorkflowStore.CaSubjectProofStep(STEP, KEY, malformed, valid));
        }
        assertThrows(NullPointerException.class, () -> new SignWorkflowStore.CaSubjectProofStep(STEP, KEY, null, valid));
    }

    @Test
    void retainedOutcomeAcceptsExactlyTerminalProviderDetailCombinationsWithoutASignature() {
        for (ObservationState disposition : ObservationState.values()) {
            for (DetailCode detail : DetailCode.values()) {
                boolean validProvider;
                try {
                    new SigningProvider.OperationObservation(STEP, disposition, Instant.EPOCH, detail,
                            disposition == ObservationState.SUCCEEDED
                                    ? Optional.of(new EncodedObject(Encoding.BINARY, new byte[] {1})) : Optional.empty());
                    validProvider = true;
                } catch (IllegalArgumentException mismatch) {
                    validProvider = false;
                }
                if (validProvider && disposition.isTerminal()) {
                    SignWorkflowStore.CaSubjectProofOutcome outcome = new SignWorkflowStore.CaSubjectProofOutcome(
                            disposition, detail, Optional.of(Instant.EPOCH));
                    assertEquals(disposition, outcome.disposition());
                    assertEquals(detail, outcome.detailCode());
                    assertEquals(Optional.of(Instant.EPOCH), outcome.providerUpdatedAt());
                } else {
                    assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofOutcome(
                            disposition, detail, Optional.of(Instant.EPOCH)), disposition + "/" + detail);
                }
            }
        }
        assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofOutcome(
                ObservationState.SUCCEEDED, DetailCode.SIGNED, Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofOutcome(
                ObservationState.CANCELLED, DetailCode.CANCELLED, Optional.empty()));
        SignWorkflowStore.CaSubjectProofOutcome local = new SignWorkflowStore.CaSubjectProofOutcome(
                ObservationState.FAILED, DetailCode.PROVIDER_RESULT_INVALID, Optional.empty());
        assertEquals(Optional.empty(), local.providerUpdatedAt());
        assertThrows(NullPointerException.class, () -> new SignWorkflowStore.CaSubjectProofOutcome(
                ObservationState.FAILED, DetailCode.PROVIDER_RESULT_INVALID, null));
    }

    private static SignWorkflowStore.CaSubjectProofStep step(DurableContentReference challenge) {
        return new SignWorkflowStore.CaSubjectProofStep(STEP, KEY, BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), challenge);
    }
    private static PkiId id(String namespace, String random) {
        return new PkiId("zsign:v1:" + namespace + ":0:" + random.repeat(32));
    }
    private static DurableContentReference reference(Encoding encoding, long length, String hash, DurableContentReference.Lifecycle lifecycle) {
        return new DurableContentReference() {
            @Override public String storeId() { return "store"; }
            @Override public String contentId() { return "challenge"; }
            @Override public Encoding encoding() { return encoding; }
            @Override public long length() { return length; }
            @Override public String sha256() { return hash; }
            @Override public Lifecycle lifecycle() { return lifecycle; }
        };
    }
}
