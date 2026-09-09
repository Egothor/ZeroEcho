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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * Non-persistent one-shot authority to execute one durably admitted local sign.
 *
 * <p>Only the filesystem participant package can mint permits. A permit is
 * process-local, is not serializable, contains no recoverable representation,
 * and cannot be reset. Its string representation is always redacted.</p>
 */
public final class LocalExecutionPermit {
    private static final String DC_BINDING_MISMATCH =
            "Local execution permit mismatch: code=LOCAL_EXECUTION_PERMIT_MISMATCH";

    private final LocalSigningLedgerParticipant participant;
    private final PkiId submissionId;
    private final String signFingerprint;
    private final SignatureWorkflow.ConfigurationCommitment configurationCommitment;
    private final long fence;
    private final CancellationSignal cancellation;
    private final AtomicBoolean consumed;

    /* default */ LocalExecutionPermit(LocalSigningLedgerParticipant participant, PkiId submissionId,
            String signFingerprint, SignatureWorkflow.ConfigurationCommitment configurationCommitment,
            long fence, CancellationSignal cancellation) {
        this.participant = Objects.requireNonNull(participant, "participant");
        this.submissionId = Objects.requireNonNull(submissionId, "submissionId");
        this.signFingerprint = Objects.requireNonNull(signFingerprint, "signFingerprint");
        this.configurationCommitment = Objects.requireNonNull(configurationCommitment,
                "configurationCommitment");
        this.fence = fence;
        this.cancellation = Objects.requireNonNull(cancellation, "cancellation");
        this.consumed = new AtomicBoolean();
    }

    /**
     * Validates all bindings and atomically consumes this permit once.
     *
     * @param exactParticipant participant receiving the durable admission
     * @param request exact admitted request
     * @param exactConfiguration exact workflow configuration commitment
     * @return store cancellation when this invocation consumed the permit, or an
     *         empty optional when it was already consumed
     * @throws IllegalStateException if any binding differs
     */
    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Participant identity is a permit binding.
    public Optional<CancellationSignal> consume(LocalSigningLedgerParticipant exactParticipant,
            SignatureWorkflow.SignRequest request,
            SignatureWorkflow.ConfigurationCommitment exactConfiguration) {
        Objects.requireNonNull(exactParticipant, "exactParticipant");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(exactConfiguration, "exactConfiguration");
        if (participant != exactParticipant
                || !submissionId.equals(request.submissionId())
                || !constantTimeEquals(signFingerprint, request.semanticFingerprint())
                || !configurationCommitment.matches(exactConfiguration)
                || fence != request.fencingToken()) {
            throw new IllegalStateException(DC_BINDING_MISMATCH);
        }
        return consumed.compareAndSet(false, true) ? Optional.of(cancellation) : Optional.empty();
    }

    @Override
    public String toString() {
        return "LocalExecutionPermit[redacted]";
    }

    private static boolean constantTimeEquals(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8),
                right.getBytes(StandardCharsets.UTF_8));
    }
}
