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
package zeroecho.pki.application;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationHistory;

/** Explicit non-reflective executor used by one backend session. */
final class DefaultPkiOperationExecutor implements PkiOperationExecutor {

    private final PkiSessionConfiguration configuration;
    private final PkiStore store;
    private final RevocationService revocations;
    private final Runnable openCheck;

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            RevocationService revocations, Runnable openCheck) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.store = Objects.requireNonNull(store, "store");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.openCheck = Objects.requireNonNull(openCheck, "openCheck");
    }

    @Override
    public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
        openCheck.run();
        PkiOperation exact = Objects.requireNonNull(operation, "operation");
        CancellationSignal signal = Objects.requireNonNull(cancellation, "cancellation");
        try {
            signal.throwIfCancelled();
            PkiOperationResult result = switch (exact) {
                case PkiOperation.ValidateConfiguration ignored -> validateConfiguration();
                case PkiOperation.ValidateProfile request -> validateProfile(request);
                case PkiOperation.InspectCredential request -> inspectCredential(request);
                case PkiOperation.RevokeCredential request -> revokeCredential(request);
                case PkiOperation.ReadRevocationHistory request -> readHistory(request, signal);
                case PkiOperation.InspectPublication request -> inspectPublication(request);
            };
            return new PkiOperationOutcome.Success(result);
        } catch (InterruptedIOException failure) {
            return failure(exact.name(), PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
        } catch (IOException failure) {
            return failure(exact.name(), PkiOperationFailure.RESOURCE_FAILURE, "OPERATION_RESOURCE_FAILED");
        } catch (RuntimeException failure) { // NOPMD - normalize provider failures at the application boundary.
            return classify(exact.name(), failure);
        }
    }

    private PkiOperationResult validateConfiguration() {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("version", integer(configuration.version()));
        fields.put("storeProvider", text(configuration.store().backendId()));
        fields.put("auditProvider", text(configuration.audit().backendId()));
        return result(PkiOperation.ValidateConfiguration.NAME, fields);
    }

    private static PkiOperationResult validateProfile(PkiOperation.ValidateProfile request) {
        CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(request.document());
        Map<String, PkiOperationValue> fields = fields();
        fields.put("profileId", text(definition.profileId()));
        fields.put("profileVersion", integer(definition.profileVersion()));
        fields.put("certificateType", text(definition.certificateType().name()));
        fields.put("formatId", text(definition.formatId().value()));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectCredential(PkiOperation.InspectCredential request) {
        Credential credential = store.getCredential(request.credentialId())
                .orElseThrow(() -> new MissingObjectException());
        CertificateProfileRef profile = profileReference(credential);
        Map<String, PkiOperationValue> fields = fields();
        fields.put("credentialId", text(credential.credentialId().value()));
        fields.put("formatId", text(credential.formatId().value()));
        fields.put("issuerId", text(credential.issuerRef().caId().value()));
        fields.put("publicKeyId", text(credential.publicKeyId().value()));
        fields.put("profileId", text(profile.profileId()));
        fields.put("profileVersion", integer(profile.profileVersion()));
        fields.put("status", text(credential.status().name()));
        fields.put("notBefore", text(credential.validity().notBefore().toString()));
        fields.put("notAfter", text(credential.validity().notAfter().toString()));
        return result(request.name(), fields);
    }

    private PkiOperationResult revokeCredential(PkiOperation.RevokeCredential request) {
        RevocationCommand.RevokePermanently command = new RevocationCommand.RevokePermanently(request.credentialId(),
                request.reason(), new SimpleAttributeSet());
        RevocationRecord record = revocations.revokePermanently(command);
        return revocationResult(request.name(), record);
    }

    private PkiOperationResult readHistory(PkiOperation.ReadRevocationHistory request, CancellationSignal signal)
            throws IOException {
        List<PkiOperationValue> transitions = new ArrayList<>();
        boolean truncated;
        try (RevocationHistory history = revocations.history(request.credentialId())) {
            while (transitions.size() < request.limit() && history.next(signal)) {
                transitions.add(transitionValue(history.current()));
            }
            truncated = transitions.size() == request.limit() && history.next(signal);
        }
        Map<String, PkiOperationValue> fields = fields();
        fields.put("credentialId", text(request.credentialId().value()));
        fields.put("count", integer(transitions.size()));
        fields.put("truncated", bool(truncated));
        fields.put("transitions", new PkiOperationValue.ListValue(transitions));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectPublication(PkiOperation.InspectPublication request) {
        PublicationRecord record = store.getPublicationRecord(request.publicationId())
                .orElseThrow(() -> new MissingObjectException());
        Map<String, PkiOperationValue> fields = fields();
        fields.put("publicationId", text(record.publicationId().value()));
        fields.put("sourceType", text(record.sourceType().name()));
        fields.put("sourceId", text(record.sourceId().value()));
        fields.put("status", text(record.status().name()));
        fields.put("attemptNumber", integer(record.attemptNumber()));
        fields.put("createdAt", text(record.createdAt().toString()));
        fields.put("updatedAt", text(record.updatedAt().toString()));
        record.failure().ifPresent(value -> fields.put("failure", text(value.name())));
        record.evidence().ifPresent(value -> fields.put("evidence", text(value.name())));
        return result(request.name(), fields);
    }

    private static PkiOperationResult revocationResult(String operation, RevocationRecord record) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("credentialId", text(record.credentialId().value()));
        appendTransition(fields, record.transition());
        return result(operation, fields);
    }

    private static PkiOperationValue transitionValue(RevocationTransition transition) {
        Map<String, PkiOperationValue> fields = fields();
        appendTransition(fields, transition);
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static void appendTransition(Map<String, PkiOperationValue> fields, RevocationTransition transition) {
        fields.put("revision", integer(transition.revision()));
        fields.put("state", text(transition.state().name()));
        fields.put("time", text(transition.time().toString()));
        transition.permanentReason().ifPresent(reason -> fields.put("reason", text(reason.name())));
    }

    private static CertificateProfileRef profileReference(Credential credential) {
        if (credential.profileBinding() instanceof EndEntityProfileBinding binding) {
            return binding.reference();
        }
        if (credential.profileBinding() instanceof CaProfileBinding binding) {
            return binding.reference();
        }
        throw new IllegalStateException("Credential profile binding is unsupported");
    }

    private static PkiOperationOutcome classify(String operation, RuntimeException failure) {
        if (failure instanceof MissingObjectException) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        }
        String message = Optional.ofNullable(failure.getMessage()).orElse("");
        if (message.contains("RECOVERY_REQUIRED") || message.contains("DURABILITY_UNCONFIRMED")) {
            return failure(operation, PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
        }
        if (message.contains("OUTCOME_UNKNOWN") || message.contains("RESULT_UNCONFIRMED")) {
            return failure(operation, PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "EXTERNAL_OUTCOME_UNKNOWN");
        }
        if (message.contains("CREDENTIAL_NOT_FOUND")) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        }
        if (message.contains("CONFLICT") || message.contains("changed concurrently")) {
            return failure(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
        }
        if (message.contains("TRANSITION_ILLEGAL") || message.contains("REVOCATION_TERMINAL")) {
            return failure(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
        }
        if (failure instanceof IllegalArgumentException) {
            return failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
        }
        if (failure instanceof PkiException) {
            return failure(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
        }
        if (failure instanceof IllegalStateException) {
            return failure(operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
        }
        return failure(operation, PkiOperationFailure.INTERNAL_FAILURE, "INTERNAL_FAILURE");
    }

    private static PkiOperationOutcome failure(String operation, PkiOperationFailure classification, String code) {
        return new PkiOperationOutcome.Failure(operation, classification, code);
    }

    private static PkiOperationResult result(String operation, Map<String, PkiOperationValue> fields) {
        return new PkiOperationResult(operation, fields);
    }

    private static Map<String, PkiOperationValue> fields() {
        return new LinkedHashMap<>();
    }

    private static PkiOperationValue text(String value) {
        return new PkiOperationValue.Text(value);
    }

    private static PkiOperationValue integer(long value) {
        return new PkiOperationValue.IntegerValue(value);
    }

    private static PkiOperationValue bool(boolean value) {
        return new PkiOperationValue.BooleanValue(value);
    }

    /** Internal marker normalized to the public NOT_FOUND classification. */
    private static final class MissingObjectException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
