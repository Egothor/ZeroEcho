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

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Internal atomic extension of the provider-facing local signing participant.
 *
 * <p>The filesystem store implements this port directly. Orchestration borrows
 * the same exact object that is supplied through the public provider port; no
 * adapter or independent projection is created.</p>
 */
public interface AtomicLocalSigningLedgerParticipant extends LocalSigningLedgerParticipant {
    /** Idempotent registration owned by one signing session. */
    @FunctionalInterface
    interface HeadroomRegistration extends AutoCloseable {
        @Override
        void close();
    }

    /** Session-wide advisory for restored headroom or terminal store failure. */
    interface HeadroomListener {
        /**
         * Signals a monotonically increasing successful restoration epoch.
         *
         * @param epoch new epoch
         */
        void restored(long epoch);

        /** Signals that the authoritative store entered fail-closed recovery. */
        void recoveryRequired();
    }

    /**
     * Durable atomic acceptance outcome and its optional one-shot execution authority.
     *
     * @param outcome durable disposition
     * @param executionPermit permit present exactly for execution
     */
    record AtomicAcceptance(Outcome outcome, Optional<LocalExecutionPermit> executionPermit) {
        /** Atomic admission outcome. */
        public enum Outcome {
            /** A durable admission minted exactly one execution permit. */
            EXECUTE,
            /** The request is already known and no execution permit was minted. */
            ATTACHED
        }

        /** Validates that execution outcomes carry exactly one permit. */
        public AtomicAcceptance {
            Objects.requireNonNull(outcome, "outcome");
            Objects.requireNonNull(executionPermit, "executionPermit");
            if (outcome == Outcome.EXECUTE != executionPermit.isPresent()) {
                throw new IllegalArgumentException("Atomic acceptance permit mismatch");
            }
        }

        /**
         * Returns an attached outcome without execution authority.
         *
         * @return immutable attached outcome
         */
        public static AtomicAcceptance attached() {
            return new AtomicAcceptance(Outcome.ATTACHED, Optional.empty());
        }

        /**
         * Returns an execution outcome carrying the newly minted authority.
         *
         * @param permit one-shot execution authority
         * @return immutable execution outcome
         */
        public static AtomicAcceptance execute(LocalExecutionPermit permit) {
            return new AtomicAcceptance(Outcome.EXECUTE, Optional.of(Objects.requireNonNull(permit, "permit")));
        }
    }

    /**
     * Atomically creates orchestrator intent and accepts local provider dispatch.
     *
     * @param request exact provider request
     * @param configurationCommitment exact effective workflow configuration
     * @param intent orchestrator intent to commit
     * @param content durable content owned by the intent
     * @return local acceptance outcome
     */
    AtomicAcceptance acceptLocalSign(SignatureWorkflow.SignRequest request,
            SignatureWorkflow.ConfigurationCommitment configurationCommitment,
            SignWorkflowStore.Record intent, DurableContentReference content);

    /**
     * Atomically accepts local execution using one store-owned signing admission.
     *
     * @param admission reserved store admission
     * @param request exact provider request
     * @param configurationCommitment exact effective workflow configuration
     * @param intent orchestrator intent to commit
     * @param content durable content owned by the intent
     * @return local acceptance outcome
     */
    AtomicAcceptance acceptLocalSign(SignWorkflowStore.SignAdmission admission,
            SignatureWorkflow.SignRequest request,
            SignatureWorkflow.ConfigurationCommitment configurationCommitment,
            SignWorkflowStore.Record intent, DurableContentReference content);

    /**
     * Fails interrupted local work only after orchestration has read-only
     * preflighted every active record owned by this exact workflow configuration.
     * No provider execution is resumed by this operation.
     *
     * @param namespace exact store/provider signing namespace
     * @param configurationCommitment exact immutable workflow configuration
     */
    void recoverMatchedLocalSigning(String namespace,
            SignatureWorkflow.ConfigurationCommitment configurationCommitment);

    /**
     * Returns the latest successful metadata-headroom restoration epoch.
     *
     * @return monotonic epoch
     */
    long signingHeadroomEpoch();

    /**
     * Registers the one session-wide advisory for restored metadata headroom.
     *
     * @param listener session listener
     * @return idempotent registration
     */
    HeadroomRegistration registerSigningHeadroomRestored(HeadroomListener listener);
}
