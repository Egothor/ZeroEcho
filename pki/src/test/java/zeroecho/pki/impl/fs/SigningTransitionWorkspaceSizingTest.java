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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

final class SigningTransitionWorkspaceSizingTest {

    @Test
    void derivesAvlHeightFromMinimumPopulationBoundary() {
        assertEquals(28, SigningTransitionWorkspaceSizing.maximumAvlHeight(832_039));
        assertEquals(28, SigningTransitionWorkspaceSizing.maximumAvlHeight(1_346_267));
        assertEquals(29, SigningTransitionWorkspaceSizing.maximumAvlHeight(1_346_268));
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransitionWorkspaceSizing.maximumAvlHeight(0));
    }

    @Test
    void enumeratesAcceptedAndPostInvocationSemanticMutationBounds() {
        assertEquals(4, SigningTransitionWorkspaceSizing.Transition.CREATE_INTENT
                .semanticMutations());
        assertEquals(5, SigningTransitionWorkspaceSizing.Transition.CREATE_INTENT_WITH_DOMAIN
                .semanticMutations());
        assertEquals(6, SigningTransitionWorkspaceSizing.Transition
                .CREATE_INTENT_WITH_CORRELATED_DOMAIN.semanticMutations());
        assertEquals(3, SigningTransitionWorkspaceSizing.Transition.ATOMIC_LOCAL_ACCEPTANCE
                .semanticMutations());
        assertEquals(3, SigningTransitionWorkspaceSizing.Transition.DOMAIN_CONTINUATION
                .semanticMutations());
        assertEquals(3, SigningTransitionWorkspaceSizing.Transition
                .CLAIM_RENEW_OR_RECONCILE.semanticMutations());
        assertEquals(2, SigningTransitionWorkspaceSizing.Transition.DIRECT_CANCEL
                .semanticMutations());
        assertEquals(2, SigningTransitionWorkspaceSizing.Transition.TERMINAL_PRIMARY
                .semanticMutations());
        assertEquals(3, SigningTransitionWorkspaceSizing.Transition.TERMINAL_EXPIRY_FALLBACK
                .semanticMutations());
        assertEquals(4, SigningTransitionWorkspaceSizing.Transition.DEADLINE_EXPIRY
                .semanticMutations());
        assertEquals(4, SigningTransitionWorkspaceSizing.Transition.RETIREMENT
                .semanticMutations());
        for (SigningTransitionWorkspaceSizing.Transition transition
                : SigningTransitionWorkspaceSizing.Transition.values()) {
            assertEquals(SigningTransitionWorkspaceSizing.AdmissionClass
                    .PROTECTED_ACCEPTED_SIGNING, transition.admissionClass());
        }
    }

    @Test
    void derivesDefaultFloorFromLifecycleAdmissionBound() {
        SigningActiveWal.Configuration configuration = SigningActiveWal.Configuration.defaults();
        SigningTransitionWorkspaceSizing.Derivation derived =
                SigningTransitionWorkspaceSizing.derive(
                        SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                        configuration.queueCapacity());

        assertEquals(SigningTransitionWorkspaceSizing.AdmissionClass
                .PROTECTED_ACCEPTED_SIGNING, derived.admissionClass());
        assertEquals(28, derived.maximumAvlHeight());
        assertEquals(34, derived.maximumInsertionNodes());
        assertEquals(28, derived.maximumReplacementNodes());
        assertEquals(162, derived.maximumDeletionNodes());
        assertEquals(SigningActiveWal.MAXIMUM_QUEUE_CAPACITY,
                derived.maximumConcurrentPreparedTransitions());
        assertEquals(SigningTransitionWorkspaceSizing.Transition.DEADLINE_EXPIRY,
                derived.maximumTransition());
        assertEquals(246L, derived.maximumNodesPerTransition());
        assertEquals(15_744L, derived.maximumBytesPerTransition());
        assertEquals(4_030_464L, derived.workspaceFloorBytes());
    }

    @Test
    void ordinaryWorkCannotConsumeProtectedAcceptedSigningFloor() {
        for (SigningTransitionWorkspaceSizing.OrdinaryOperation operation
                : SigningTransitionWorkspaceSizing.OrdinaryOperation.values()) {
            assertEquals(SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY,
                    operation.admissionClass());
            assertFalse(operation.admissionClass()
                    == SigningTransitionWorkspaceSizing.AdmissionClass
                            .PROTECTED_ACCEPTED_SIGNING);
        }

        SigningTransitionWorkspaceSizing.OrdinaryDerivation purge =
                SigningTransitionWorkspaceSizing.deriveRetentionPurge(
                        SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS);
        assertEquals(SigningTransitionWorkspaceSizing.OrdinaryOperation.RETENTION_PURGE,
                purge.operation());
        assertEquals(SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY,
                purge.admissionClass());
        assertEquals(10, purge.maximumRecords());
        assertEquals(30, purge.deletes());
        assertEquals(1, purge.replacements());
        assertEquals(4_888L, purge.maximumNodes());
        assertEquals(312_832L, purge.maximumBytes());
    }

    @Test
    void rejectsConcurrencyBeyondSharedLifecycleGateCapacity() {
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransitionWorkspaceSizing.derive(
                        SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS, 0));
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransitionWorkspaceSizing.derive(
                        SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                        SigningActiveWal.MAXIMUM_QUEUE_CAPACITY + 1));
    }
}
