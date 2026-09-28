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

package zeroecho.pki.impl.core.signing; // NOPMD - CouplingBetweenObjects: one semantic facade binds prepared commands to durable continuation ownership.

import java.security.MessageDigest;
import java.io.IOException;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import java.util.Objects;
import java.util.Optional;
import java.util.HexFormat;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.core.CorrelatedIssuanceIdentity;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.impl.core.EndEntitySigningPreparation;
import zeroecho.pki.impl.core.PreparedFullCrlTbs;
import zeroecho.pki.impl.core.FullCrlSigningPreparation;
import zeroecho.pki.impl.core.ManagedKeyProofPreparation;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofBindings;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningScope;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Stateless, thread-safe semantic facade over the session's signing service.
 * Reads use a constant number of authoritative point lookups and local time and
 * memory linear in the bounded envelope, command and result bytes. Store index
 * and I/O costs remain those of the existing store. No operation registry is kept.
 */
public final class DefaultSemanticSigningService implements SemanticSigningService { // NOPMD - CyclomaticComplexity totals independent cohesive operations; method-level checks remain enabled.
    private static final String ACCESS_ARGUMENT = "access";
    private static final String CANCELLATION_ARGUMENT = "cancellation";
    private static final String ROLLOVER_ROOT = "ROLLOVER_ROOT";

    private final PkiStore store;
    private final DefaultSigningService signing;
    private final EndEntitySigningPreparation endEntity;
    private final long pureEdDsaMaximumTbsBytes;
    private final Optional<FullCrlSigningPreparation> fullCrl;
    private final Optional<ManagedKeyProofPreparation> managedKeyProof;
    private final Optional<zeroecho.pki.impl.core.IntermediateSigningPreparation> intermediate;
    private final Optional<zeroecho.pki.impl.core.RootSigningPreparation> root;

    /**
     * Binds a semantic facade to the exact store used by a session signing service.
     *
     * @param store authoritative session store
     * @param signing existing session-owned service and acceptance gate
     * @param endEntity session-owned verified leaf preparation
     */
    public DefaultSemanticSigningService(PkiStore store, DefaultSigningService signing,
            EndEntitySigningPreparation endEntity) {
        this(store, signing, endEntity, Integer.MAX_VALUE - 8L);
    }

    /**
     * Binds preparation to the session's resolved pure-EdDSA admission bound.
     * @param store authoritative session store
     * @param signing session signing service
     * @param endEntity verified leaf preparation
     * @param pureEdDsaMaximumTbsBytes positive inclusive raw-message bound
     */
    public DefaultSemanticSigningService(PkiStore store, DefaultSigningService signing,
            EndEntitySigningPreparation endEntity, long pureEdDsaMaximumTbsBytes) {
        this(store, signing, endEntity, pureEdDsaMaximumTbsBytes, Optional.empty());
    }

    /**
     * Binds the public semantic operations to session-owned preparation.
     * @param store authoritative store
     * @param signing existing signing service and acceptance gate
     * @param endEntity verified leaf preparation
     * @param pureEdDsaMaximumTbsBytes resolved positive raw-message limit
     * @param fullCrl exact selected-provider full-CRL preparation, absent for internal leaf-only fixtures
     */
    public DefaultSemanticSigningService(PkiStore store, DefaultSigningService signing,
            EndEntitySigningPreparation endEntity, long pureEdDsaMaximumTbsBytes,
            Optional<FullCrlSigningPreparation> fullCrl) {
        this(store, signing, endEntity, pureEdDsaMaximumTbsBytes, fullCrl, Optional.empty());
    }

    /**
     * Binds semantic operations to exact session-owned preparation dependencies.
     * @param store authoritative store
     * @param signing session signing service and acceptance gate
     * @param endEntity verified leaf preparation
     * @param pureEdDsaMaximumTbsBytes inclusive positive raw-message bound
     * @param fullCrl optional selected-provider full-CRL preparation
     * @param managedKeyProof optional exact selected-provider managed-key preparation
     */
    public DefaultSemanticSigningService(PkiStore store, DefaultSigningService signing,
            EndEntitySigningPreparation endEntity, long pureEdDsaMaximumTbsBytes,
            Optional<FullCrlSigningPreparation> fullCrl, Optional<ManagedKeyProofPreparation> managedKeyProof) {
        this(store, signing, endEntity, pureEdDsaMaximumTbsBytes, fullCrl, managedKeyProof, Optional.empty());
    }

    /**
     * Binds all currently supported semantic preparers to the same session graph.
     * @param store authoritative store
     * @param signing session signing service
     * @param endEntity leaf preparation
     * @param pureEdDsaMaximumTbsBytes inclusive configured input bound
     * @param fullCrl full-CRL preparation
     * @param managedKeyProof managed-key proof preparation
     * @param intermediate intermediate creation preparation, absent only in narrower internal fixtures
     */
    public DefaultSemanticSigningService(PkiStore store, DefaultSigningService signing,
            EndEntitySigningPreparation endEntity, long pureEdDsaMaximumTbsBytes,
            Optional<FullCrlSigningPreparation> fullCrl, Optional<ManagedKeyProofPreparation> managedKeyProof,
            Optional<zeroecho.pki.impl.core.IntermediateSigningPreparation> intermediate) {
        this(store, signing, endEntity, pureEdDsaMaximumTbsBytes, fullCrl, managedKeyProof, intermediate, Optional.empty());
    }

    /**
     * Binds root and intermediate creation to the existing session signing graph.
     * @param store authoritative store
     * @param signing session signing service and acceptance gate
     * @param endEntity verified leaf preparation
     * @param pureEdDsaMaximumTbsBytes inclusive configured input bound
     * @param fullCrl full-CRL preparation
     * @param managedKeyProof managed-key proof preparation
     * @param intermediate intermediate creation preparation
     * @param root root creation preparation, absent only in narrower internal fixtures
     */
    public DefaultSemanticSigningService(PkiStore store, DefaultSigningService signing,
            EndEntitySigningPreparation endEntity, long pureEdDsaMaximumTbsBytes,
            Optional<FullCrlSigningPreparation> fullCrl, Optional<ManagedKeyProofPreparation> managedKeyProof,
            Optional<zeroecho.pki.impl.core.IntermediateSigningPreparation> intermediate,
            Optional<zeroecho.pki.impl.core.RootSigningPreparation> root) {
        this.store = Objects.requireNonNull(store, "store");
        this.signing = Objects.requireNonNull(signing, "signing");
        this.endEntity = Objects.requireNonNull(endEntity, "endEntity");
        FullCrlSigningCommand.requireAdmission("", 0, pureEdDsaMaximumTbsBytes);
        this.pureEdDsaMaximumTbsBytes = pureEdDsaMaximumTbsBytes;
        this.fullCrl = Objects.requireNonNull(fullCrl, "fullCrl");
        this.managedKeyProof = Objects.requireNonNull(managedKeyProof, "managedKeyProof");
        this.intermediate = Objects.requireNonNull(intermediate, "intermediate");
        this.root = Objects.requireNonNull(root, "root");
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    @Override public PreparedSemanticSigningRequest prepareRootCreation(AccessContext access,
            zeroecho.pki.api.ca.CaCreateCommand command, CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        DomainSigningRequest domain;
        try {
            domain = root.orElseThrow(() -> new IllegalStateException("Root preparation unavailable"))
                    .prepare(access, command, signing.newSubmissionId(), signing.signingTtl(), cancellation);
        } catch (IOException failure) { throw new PkiException("Root creation preparation failed", failure); }
        try {
            cancellation.throwIfCancelled();
            return prepare(domain, DomainCommandEncoding.rootAuthorityId(domain.operationId()));
        } catch (IOException | RuntimeException | Error primary) {
            retireAfterAdoptionFailure(domain, primary);
            if (primary instanceof IOException failure) { throw new PkiException("Root creation preparation cancelled", failure); }
            if (primary instanceof RuntimeException failure) { throw failure; }
            throw (Error) primary;
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    @Override public PreparedSemanticSigningRequest prepareIntermediateCreation(AccessContext access,
            zeroecho.pki.api.ca.IntermediateCreateCommand command, CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        DomainSigningRequest domain;
        try {
            domain = intermediate.orElseThrow(() -> new IllegalStateException("Intermediate preparation unavailable"))
                    .prepare(access, command, signing.newSubmissionId(), signing.signingTtl(), cancellation);
        } catch (IOException failure) { throw new PkiException("Intermediate creation preparation failed", failure); }
        try {
            cancellation.throwIfCancelled();
            return prepare(domain, new PkiId(DomainCommandEncoding.decode(domain.domainTemplate().command()).field(1)));
        } catch (IOException | RuntimeException | Error primary) {
            retireAfterAdoptionFailure(domain, primary);
            if (primary instanceof IOException failure) { throw new PkiException("Intermediate creation preparation cancelled", failure); }
            if (primary instanceof RuntimeException failure) { throw failure; }
            throw (Error) primary;
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    @Override public PreparedSemanticSigningRequest prepareIntermediateIssuance(AccessContext access,
            zeroecho.pki.api.ca.IntermediateCertIssueCommand command, CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        DomainSigningRequest domain;
        try {
            domain = intermediate.orElseThrow(() -> new IllegalStateException("Intermediate preparation unavailable"))
                    .prepare(access, command, signing.newSubmissionId(), signing.signingTtl(), cancellation);
        } catch (IOException failure) { throw new PkiException("Intermediate issuance preparation failed", failure); }
        try {
            cancellation.throwIfCancelled();
            return prepare(domain, new PkiId(DomainCommandEncoding.decode(domain.domainTemplate().command()).field(1)));
        } catch (IOException | RuntimeException | Error primary) {
            retireAfterAdoptionFailure(domain, primary);
            if (primary instanceof IOException failure) { throw new PkiException("Intermediate issuance preparation cancelled", failure); }
            if (primary instanceof RuntimeException failure) { throw failure; }
            throw (Error) primary;
        }
    }

    @Override public PreparedSemanticSigningRequest prepareCaRollover(AccessContext access,
            CaRolloverCommand command, CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        DomainSigningRequest domain;
        PkiId fairness = switch (command) {
            case CaRolloverCommand.Root value -> value.caId();
            case CaRolloverCommand.Intermediate value -> value.issuerCaId();
        };
        try {
            domain = switch (command) {
                case CaRolloverCommand.Root value -> root.orElseThrow(() -> new IllegalStateException("Root preparation unavailable"))
                        .prepare(access, value, signing.newSubmissionId(), signing.signingTtl(), cancellation);
                case CaRolloverCommand.Intermediate value -> intermediate.orElseThrow(() -> new IllegalStateException("Intermediate preparation unavailable"))
                        .prepare(access, value, signing.newSubmissionId(), signing.signingTtl(), cancellation);
            };
        } catch (IOException failure) { throw new PkiException("CA rollover preparation failed", failure); }
        return adoptLifecycle(domain, fairness, cancellation);
    }

    @Override public PreparedSemanticSigningRequest prepareCaKeyRotation(AccessContext access,
            CaKeyRotationCommand command, CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        DomainSigningRequest domain;
        PkiId fairness = switch (command) {
            case CaKeyRotationCommand.Root value -> value.caId();
            case CaKeyRotationCommand.Intermediate value -> value.issuerCaId();
        };
        try {
            domain = switch (command) {
                case CaKeyRotationCommand.Root value -> root.orElseThrow(() -> new IllegalStateException("Root preparation unavailable"))
                        .prepare(access, value, signing.newSubmissionId(), signing.signingTtl(), cancellation);
                case CaKeyRotationCommand.Intermediate value -> intermediate.orElseThrow(() -> new IllegalStateException("Intermediate preparation unavailable"))
                        .prepare(access, value, signing.newSubmissionId(), signing.signingTtl(), cancellation);
            };
        } catch (IOException failure) { throw new PkiException("CA key rotation preparation failed", failure); }
        return adoptLifecycle(domain, fairness, cancellation);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Identity comparison preserves ownership tokens or prevents Throwable self-suppression; value equality is incorrect here.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CompareObjectsWithEquals" })
    private void retireAfterAdoptionFailure(DomainSigningRequest request, Throwable primary) {
        for (zeroecho.pki.api.content.DurableContentReference candidate : request.candidates()) {
            try { store.stagedContent().retireUnownedContent(candidate); }
            catch (IOException | RuntimeException | Error cleanup) { if (primary != cleanup) { primary.addSuppressed(cleanup); } }
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private PreparedSemanticSigningRequest adoptLifecycle(DomainSigningRequest domain, PkiId fairness,
            CancellationSignal cancellation) {
        try {
            cancellation.throwIfCancelled();
            return prepare(domain, fairness);
        } catch (IOException | RuntimeException | Error primary) {
            retireAfterAdoptionFailure(domain, primary);
            if (primary instanceof IOException failure) { throw new PkiException("CA lifecycle preparation cancelled", failure); }
            if (primary instanceof RuntimeException failure) { throw failure; }
            throw (Error) primary;
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    @Override public PreparedSemanticSigningRequest prepareManagedKeyProof(AccessContext access, ManagedKeyProofRequest request,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        DomainSigningRequest domain;
        try {
            domain = managedKeyProof.orElseThrow(() -> new IllegalStateException("Managed key proof preparation unavailable"))
                    .prepare(access, request, signing.newSubmissionId(), signing.signingTtl(), cancellation);
        } catch (IOException failure) {
            throw new PkiException("Managed key proof preparation failed", failure);
        }
        try {
            cancellation.throwIfCancelled();
            return prepare(domain, ManagedKeyProofCommand.authorityId(request));
        } catch (IOException | RuntimeException | Error primary) {
            retireAfterAdoptionFailure(domain, primary);
            if (primary instanceof IOException failure) { throw new PkiException("Managed key proof preparation cancelled", failure); }
            if (primary instanceof RuntimeException failure) { throw failure; }
            throw (Error) primary;
        }
    }

    @Override public PreparedSemanticSigningRequest prepareFullCrl(AccessContext access, FullCrlRequest request,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        PreparedFullCrlTbs prepared;
        try {
            cancellation.throwIfCancelled();
            prepared = fullCrl.orElseThrow(() -> new IllegalStateException("Full CRL preparation is not configured"))
                    .prepare(request, cancellation);
        } catch (IOException failure) {
            throw new PkiException("Full CRL preparation failed", failure);
        }
        return prepareFullCrl(access, prepared, cancellation);
    }

    @Override public PreparedSemanticSigningRequest prepareDeltaCrl(AccessContext access, DeltaCrlRequest request,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        PreparedFullCrlTbs prepared;
        try {
            cancellation.throwIfCancelled();
            prepared = fullCrl.orElseThrow(() -> new IllegalStateException("CRL preparation is not configured"))
                    .prepare(request, pureEdDsaMaximumTbsBytes, cancellation);
        } catch (IOException failure) {
            throw new PkiException("Delta CRL preparation failed", failure);
        }
        return prepareFullCrl(access, prepared, cancellation);
    }

    /**
     * Adopts module-owned completed CRL preparation without copying the staged TBS.
     * This implementation-package bridge is not a public product API. On success
     * the returned carrier owns acceptance/discard; definite preparation failure
     * retires only the unowned staged TBS. The consumed CRL number is never reused.
     * @param access trusted caller access context
     * @param prepared completed policy-validated full CRL preparation
     * @param cancellation preparation cancellation signal
     * @return opaque single-use signing preparation
     */
    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Identity comparison preserves ownership tokens or prevents Throwable self-suppression; value equality is incorrect here.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CompareObjectsWithEquals", "PMD.PreserveStackTrace" })
    public PreparedSemanticSigningRequest prepareFullCrl(AccessContext access, PreparedFullCrlTbs prepared,
            CancellationSignal cancellation) {
        Objects.requireNonNull(prepared, "prepared");
        try {
            signing.requireAvailable();
            Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT).throwIfCancelled();
            DomainSigningRequest domain = new DomainSigningRequest(signing.newSubmissionId().id(), access,
                    prepared.signingKeyRef(), prepared.signatureAlgorithm(), Encoding.BINARY,
                    prepared.tbsContent(), signing.signingTtl(), FullCrlSigningCommand.template(prepared), Optional.empty());
            return prepare(domain, prepared.authorityId());
        } catch (IOException | RuntimeException | Error primary) {
            try { store.stagedContent().retireUnownedContent(prepared.tbsContent()); }
            catch (IOException | RuntimeException cleanup) { if (primary != cleanup) { primary.addSuppressed(cleanup); } }
            if (primary instanceof IOException failure) { throw new PkiException("Full CRL preparation cancelled", failure); }
            if (primary instanceof RuntimeException failure) { throw failure; }
            throw (Error) primary;
        }
    }

    @Override public PreparedSemanticSigningRequest prepareEndEntity(AccessContext access,
            EndEntityIssuanceRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(evidence, "evidence");
        DomainSigningRequest domain;
        try {
            domain = endEntity.prepare(access, request, signing.newSubmissionId(), signing.signingTtl(), evidence, cancellation);
        } catch (IOException failure) {
            throw new PkiException("End-entity preparation failed", failure);
        }
        return adoptLeaf(domain, cancellation);
    }

    @Override public PreparedSemanticSigningRequest prepareRenewal(AccessContext access,
            EndEntityRenewalRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(evidence, "evidence");
        DomainSigningRequest domain;
        try {
            domain = endEntity.prepareRenewal(access, request, signing.newSubmissionId(), signing.signingTtl(), evidence, cancellation);
        } catch (IOException failure) {
            throw new PkiException("End-entity renewal preparation failed", failure);
        }
        return adoptLeaf(domain, cancellation);
    }

    @Override public CorrelatedIssuancePreparation prepareCorrelatedEndEntity(AccessContext access,
            CorrelatedEndEntityIssuanceRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(access, ACCESS_ARGUMENT);
        Objects.requireNonNull(request, "request");
        EndEntitySigningPreparation.validateEvidence(evidence, access, request.request().issuerCaId().value(),
                request.intent().expectedProfile().profileId());
        Objects.requireNonNull(cancellation, CANCELLATION_ARGUMENT);
        Optional<SemanticSigningOperation> existing = findIssuance(request);
        if (existing.isPresent()) {
            return new CorrelatedIssuancePreparation.Existing(existing.orElseThrow());
        }
        DomainSigningRequest domain;
        try {
            cancellation.throwIfCancelled();
            domain = endEntity.prepareCorrelated(access, request, signing.newSubmissionId(),
                    signing.signingTtl(), evidence, cancellation);
        } catch (IOException failure) {
            throw new PkiException("Correlated end-entity preparation failed", failure);
        }
        return new CorrelatedIssuancePreparation.Prepared(adoptLeaf(domain, cancellation));
    }

    @Override public PreparedSemanticSigningRequest prepareReplacement(AccessContext access,
            EndEntityReplacementRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(evidence, "evidence");
        DomainSigningRequest domain;
        try {
            domain = endEntity.prepareReplacement(access, request, signing.newSubmissionId(), signing.signingTtl(), evidence, cancellation);
        } catch (IOException failure) {
            throw new PkiException("End-entity replacement preparation failed", failure);
        }
        return adoptLeaf(domain, cancellation);
    }

    @Override public PreparedSemanticSigningRequest prepareReissue(AccessContext access,
            EndEntityReissueRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) {
        signing.requireAvailable();
        Objects.requireNonNull(evidence, "evidence");
        DomainSigningRequest domain;
        try {
            domain = endEntity.prepareReissue(access, request, signing.newSubmissionId(), signing.signingTtl(), evidence, cancellation);
        } catch (IOException failure) {
            throw new PkiException("End-entity reissue preparation failed", failure);
        }
        return adoptLeaf(domain, cancellation);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private PreparedSemanticSigningRequest adoptLeaf(DomainSigningRequest domain, CancellationSignal cancellation) {
        try {
            cancellation.throwIfCancelled();
            // The validated command owns the authoritative scheduling coordinate;
            // the caller input is not an independent source of issuer authority.
            PkiId fairnessAuthority = new PkiId(DomainCommandEncoding.decode(domain.domainTemplate().command()).field(0));
            return prepare(domain, fairnessAuthority);
        } catch (IOException | RuntimeException | Error primary) {
            try {
                store.stagedContent().retireUnownedContent(domain.content());
            } catch (IOException | RuntimeException cleanup) {
                primary.addSuppressed(cleanup);
            }
            if (primary instanceof IOException failure) {
                throw new PkiException("End-entity preparation cancelled", failure);
            }
            if (primary instanceof RuntimeException failure) {
                throw failure;
            }
            throw (Error) primary;
        }
    }

    /**
     * Adopts an already staged candidate from a module-owned domain preparer.
     * Canonical outer structure, signing-key binding and authoritative staging
     * metadata are validated before custody transfers. The caller retains custody
     * on failure; on success only the returned carrier may accept or discard it.
     * This method does not restage content or invoke the provider. Domain-specific
     * CSR, profile and issuer policy validation must have finished beforehand.
     *
     * @param request exact typed internal preparation, using the session algorithm and TTL
     * @param fairnessAuthorityId trusted scheduling coordinate, never authorization scope
     * @return opaque single-use preparation
     * @throws IllegalArgumentException if signing configuration or key binding differs
     */
    public PreparedSemanticSigningRequest prepare(DomainSigningRequest request, PkiId fairnessAuthorityId) {
        signing.requireAvailable();
        DomainSigningRequest exact = Objects.requireNonNull(request, "request");
        DomainContinuationTemplate template = exact.domainTemplate();
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(template);
        if (template.kind() == DomainContinuationStore.Kind.KEY_PROOF) {
            ManagedKeyProofBindings.requireCandidate(command, exact.content());
            if (!command.field(8).equals(exact.algorithmId()) || !command.field(1).equals(fairnessAuthorityId.value())) {
                throw new IllegalArgumentException("Managed key proof adoption metadata differs");
            }
            FullCrlSigningCommand.requireAdmission(exact.algorithmId(), exact.content().length(), pureEdDsaMaximumTbsBytes);
        }
        if (FullCrlSigningCommand.supports(command.operation())) {
            FullCrlSigningCommand.requireTbs(command, exact.content());
            if (!command.field(8).equals(exact.algorithmId())) {
                throw new IllegalArgumentException("Full CRL signing algorithm differs");
            }
            FullCrlSigningCommand.requireAdmission(exact.algorithmId(), exact.content().length(), pureEdDsaMaximumTbsBytes);
        }
        if (zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.supports(command.operation())) {
            SignWorkflowStore.CaSubjectProofStep proof = exact.proofStep().orElseThrow(
                    () -> new IllegalArgumentException("Intermediate signing proof candidate is missing"));
            FullCrlSigningCommand.requireAdmission(exact.algorithmId(), exact.content().length(), pureEdDsaMaximumTbsBytes);
            FullCrlSigningCommand.requireAdmission(proof.algorithmId(), proof.challenge().length(), pureEdDsaMaximumTbsBytes);
        }
        scope(template.kind(), command, exact.accessContext(), exact.keyRef());
        SignWorkflowStore.OuterCommand outer = new SignWorkflowStore.OuterCommand(template.kind(),
                template.correlationId().orElseThrow(
                        () -> new IllegalArgumentException("Semantic preparation requires a correlation identity")),
                template.command(), template.commandCommitment());
        DefaultPreparedSigningRequest prepared = signing.prepareDomain(exact, fairnessAuthorityId, outer);
        return new DefaultPreparedSemanticSigningRequest(prepared, this);
    }

    @Override public SigningAcceptanceResult accept(PreparedSemanticSigningRequest prepared) {
        signing.requireAvailable();
        DefaultPreparedSigningRequest exact = unwrap(prepared);
        Optional<DomainCommandEncoding.Decoded> intent = correlatedIntent(exact);
        if (intent.isEmpty()) {
            return signing.accept(exact);
        }
        exact.requireUnused();
        Optional<SigningAcceptanceResult> existing = correlatedAcceptance(exact, intent.orElseThrow());
        if (existing.isPresent()) {
            // The existing custody CAS prevents a competing accept/discard from
            // reclaiming this candidate once its acceptance has begun.
            signing.discard(exact);
            return existing.orElseThrow();
        }
        // Do not catch uncertain acceptance: preserve original receipt/custody
        // for resolve(), and never infer non-acceptance from another correlation.
        SigningAcceptanceResult result = signing.accept(exact);
        if (result.disposition() == SigningAcceptanceDisposition.CONFLICT
                || result.disposition() == SigningAcceptanceDisposition.CAPACITY_REJECTED) {
            // Definite rejection already reclaimed only unbound content in the
            // store. A concurrent winner may now be visible; do not discard twice.
            return correlatedAcceptance(exact, intent.orElseThrow()).orElse(result);
        }
        return result;
    }

    private static Optional<DomainCommandEncoding.Decoded> correlatedIntent(DefaultPreparedSigningRequest prepared) {
        Optional<SignWorkflowStore.OuterCommand> outer = prepared.outer();
        if (outer.isEmpty() || outer.orElseThrow().kind() != DomainContinuationStore.Kind.ISSUANCE) {
            return Optional.empty();
        }
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.orElseThrow().command());
        return "ISSUE_END_ENTITY".equals(command.operation()) && !command.field(15).isEmpty()
                ? Optional.of(command) : Optional.empty();
    }

    private Optional<SigningAcceptanceResult> correlatedAcceptance(DefaultPreparedSigningRequest prepared,
            DomainCommandEncoding.Decoded proposed) {
        String correlation = prepared.outer().orElseThrow().correlationId();
        Optional<DomainContinuationStore.Record> found = store.getDomainContinuation(
                DomainContinuationStore.Kind.ISSUANCE, correlation);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        DomainContinuationStore.Record domain = found.orElseThrow();
        SigningAcceptanceResult conflict = new SigningAcceptanceResult(
                SigningAcceptanceDisposition.CONFLICT, prepared.receipt());
        if (domain.kind() != DomainContinuationStore.Kind.ISSUANCE
                || domain.correlationId().filter(correlation::equals).isEmpty()) {
            return Optional.of(conflict);
        }
        Optional<SignWorkflowStore.Workflow> retained = signing.workflow(domain.operationId());
        if (retained.isEmpty()) {
            return Optional.empty();
        }
        SignWorkflowStore.Workflow winner = retained.orElseThrow();
        snapshot(winner, domain);
        DomainCommandEncoding.Decoded existing = DomainCommandEncoding.decode(domain.command());
        if (!sameIssuanceIntent(proposed, existing)) {
            return Optional.of(conflict);
        }
        SigningAcceptanceReceipt winnerReceipt = SigningAcceptanceReceipt.parse(winner.operationId(),
                winner.envelope().acceptanceCommitment().encoded());
        return Optional.of(new SigningAcceptanceResult(SigningAcceptanceDisposition.ATTACHED_EXISTING, winnerReceipt));
    }

    private static boolean sameIssuanceIntent(DomainCommandEncoding.Decoded proposed,
            DomainCommandEncoding.Decoded existing) {
        if (!proposed.operation().equals(existing.operation())
                || !proposed.field(15).equals(existing.field(15))
                || !proposed.field(16).equals(existing.field(16))) {
            return false;
        }
        // Authority, issuer, path/commitment and exact profile identity precede
        // generated certificate fields. Serial, validity evaluation and operation
        // identity intentionally do not participate in replay equality.
        for (int field = 0; field <= 6; field++) {
            if (!proposed.field(field).equals(existing.field(field))) {
                return false;
            }
        }
        return true;
    }

    @Override public void discard(PreparedSemanticSigningRequest prepared) {
        signing.requireAvailable();
        signing.discard(unwrap(prepared));
    }

    @Override public Optional<SemanticSigningOperation> find(PkiId operationId) {
        signing.requireAvailable();
        PkiId exact = Objects.requireNonNull(operationId, "operationId");
        SigningSubmissionId.parse(exact);
        // Read outer state first: a newer signature observation cannot falsely
        // claim completion when outer publication has not committed yet.
        Optional<DomainContinuationStore.Record> domain = store.getDomainContinuation(exact);
        Optional<SignWorkflowStore.Workflow> workflow = signing.workflow(exact);
        if (domain.isEmpty() || workflow.isEmpty() || workflow.orElseThrow().envelope().outer().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(snapshot(workflow.orElseThrow(), domain.orElseThrow()));
    }

    @Override public Optional<SemanticSigningOperation> cancel(PkiId operationId) {
        if (find(operationId).isEmpty()) {
            return Optional.empty();
        }
        signing.cancel(operationId);
        return find(operationId);
    }

    @Override
    public Optional<PkiId> completedStatusObjectId(SemanticSigningOperation operation) {
        Objects.requireNonNull(operation, "operation");
        if (operation.state() != SemanticSigningState.COMPLETED
                || operation.scope().kind() != SemanticSigningKind.STATUS
                || !FullCrlSigningCommand.supports(operation.scope().operation())) {
            return Optional.empty();
        }
        return Optional.of(FullCrlSigningCommand.resultId(operation.result().orElseThrow()));
    }

    @Override public RetainedIssuanceBinding issuanceBinding(CorrelatedEndEntityIssuanceRequest request) {
        signing.requireAvailable();
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        IssuanceIntent intent = request.intent();
        return new RetainedIssuanceBinding(request.request().issuerCaId(), intent.issuanceId(), intent.expectedProfile(),
                intent.expectedIssuerId(), intent.expectedChainPathId(), intent.expectedChainPathCommitment(),
                identity.effectiveCommitment());
    }

    @Override public Optional<SemanticSigningOperation> findIssuance(CorrelatedEndEntityIssuanceRequest request) {
        return findIssuance(issuanceBinding(request));
    }

    @Override public Optional<SemanticSigningOperation> findIssuance(RetainedIssuanceBinding binding) {
        signing.requireAvailable();
        Objects.requireNonNull(binding, "binding");
        String correlationId = CorrelatedIssuanceIdentity.correlationId(binding.authorityId(), binding.issuanceId());
        Optional<DomainContinuationStore.Record> found = store.getDomainContinuation(
                DomainContinuationStore.Kind.ISSUANCE, correlationId);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        DomainContinuationStore.Record domain = found.orElseThrow();
        if (domain.kind() != DomainContinuationStore.Kind.ISSUANCE
                || domain.correlationId().filter(correlationId::equals).isEmpty()) {
            throw new PkiException("Issuance correlation conflict: code=ISSUANCE_CONFLICT");
        }
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(
                new DomainContinuationTemplate(domain.kind(), domain.correlationId(), domain.command(),
                        domain.commandCommitment()));
        if (!"ISSUE_END_ENTITY".equals(command.operation())
                || !binding.authorityId().value().equals(command.field(0))
                || !binding.expectedIssuerId().value().equals(command.field(1))
                || !binding.expectedChainPathId().value().equals(command.field(2))
                || !binding.expectedChainPathCommitment().equals(command.field(3))
                || !binding.expectedProfile().profileId().equals(command.field(4))
                || !Long.toString(binding.expectedProfile().profileVersion()).equals(command.field(5))
                || !HexFormat.of().formatHex(binding.expectedProfile().canonicalSha256()).equals(command.field(6))
                || !binding.issuanceId().equals(command.field(15))
                || !binding.effectiveCommitment().equals(command.field(16))) {
            throw new PkiException("Issuance correlation conflict: code=ISSUANCE_CONFLICT");
        }
        // A concurrent purge can remove the workflow after the correlation read.
        return signing.workflow(domain.operationId()).map(workflow -> snapshot(workflow, domain));
    }

    @Override public SigningAcceptanceResolution resolve(SigningAcceptanceReceipt receipt) {
        signing.requireAvailable();
        SigningAcceptanceReceipt exact = Objects.requireNonNull(receipt, "receipt");
        Optional<SignWorkflowStore.Workflow> workflow = signing.workflow(exact.operationId());
        if (workflow.isPresent() && workflow.orElseThrow().envelope().outer().isEmpty()) {
            throw new IllegalArgumentException("Receipt names a sign-only operation");
        }
        return signing.resolve(exact);
    }

    @Override public Optional<SemanticSigningOperation> findByCorrelation(SemanticSigningKind kind,
            String correlationId) {
        signing.requireAvailable();
        Objects.requireNonNull(kind, "kind");
        if (correlationId == null || correlationId.length() > 128
                || !correlationId.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException("Semantic correlation identity is invalid");
        }
        DomainContinuationStore.Kind storedKind = DomainContinuationStore.Kind.valueOf(kind.name());
        Optional<DomainContinuationStore.Record> domain = store.getDomainContinuation(storedKind, correlationId);
        if (domain.isEmpty()) {
            return Optional.empty();
        }
        DomainContinuationStore.Record record = domain.orElseThrow();
        if (record.kind() != storedKind || record.correlationId().filter(correlationId::equals).isEmpty()) {
            throw new IllegalStateException("Semantic correlation binding is inconsistent");
        }
        return signing.workflow(record.operationId()).map(workflow -> snapshot(workflow, record));
    }

    private DefaultPreparedSigningRequest unwrap(PreparedSemanticSigningRequest prepared) {
        return ((DefaultPreparedSemanticSigningRequest) Objects.requireNonNull(prepared, "prepared")).unwrap(this);
    }

    private SemanticSigningOperation snapshot(SignWorkflowStore.Workflow workflow,
            DomainContinuationStore.Record domain) {
        SignWorkflowStore.AcceptanceEnvelope envelope = workflow.envelope();
        requireContinuationBinding(envelope, domain);
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(
                new DomainContinuationTemplate(domain.kind(), domain.correlationId(), domain.command(),
                        domain.commandCommitment()));
        if (FullCrlSigningCommand.supports(command.operation())) {
            FullCrlSigningCommand.requireTbs(command, envelope.candidate());
            if (!envelope.algorithmId().equals(command.field(8))) {
                throw new IllegalStateException("Full CRL acceptance algorithm differs");
            }
            if (domain.state() == DomainContinuationStore.State.COMPLETED) {
                FullCrlSigningCommand.requireCompleted(store, domain);
            }
        }
        if (domain.kind() == DomainContinuationStore.Kind.KEY_PROOF) {
            ManagedKeyProofBindings.requireWorkflow(workflow, domain);
        }
        if (zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.supports(command.operation())) {
            zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.requireEnvelope(envelope);
        }
        SemanticSigningScope scope = scope(domain.kind(), command, envelope.accessContext(), envelope.keyRef());
        SigningOperationState signingState = DefaultSigningService.operationState(workflow);
        if ((domain.state() == DomainContinuationStore.State.PUBLISHING
                || domain.state() == DomainContinuationStore.State.COMPLETED)
                && signingState != SigningOperationState.SUCCEEDED) {
            throw new IllegalStateException("Semantic publication has no successful signature");
        }
        return new SemanticSigningOperation(SigningSubmissionId.parse(envelope.operationId()), scope,
                signingState, SemanticSigningState.valueOf(domain.state().name()), workflow.revision(),
                domain.revision(), domain.createdAt(), domain.deadline(), domain.detailCode(), domain.result());
    }

    private static void requireContinuationBinding(SignWorkflowStore.AcceptanceEnvelope envelope,
            DomainContinuationStore.Record domain) {
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow(
                () -> new IllegalStateException("Semantic continuation has no acceptance binding"));
        boolean live = domain.state() == DomainContinuationStore.State.SIGNING
                || domain.state() == DomainContinuationStore.State.PUBLISHING;
        if (!envelope.operationId().equals(domain.operationId()) || outer.kind() != domain.kind()
                || domain.correlationId().filter(outer.correlationId()::equals).isEmpty()
                || !outer.commandCommitment().equals(domain.commandCommitment())
                || outer.command().encoding() != domain.command().encoding()
                || !MessageDigest.isEqual(outer.command().bytes(), domain.command().bytes())
                || !envelope.createdAt().equals(domain.createdAt()) || !envelope.deadline().equals(domain.deadline())
                || live && domain.signingContent().filter(envelope.candidate()::equals).isEmpty()) {
            throw new IllegalStateException("Semantic continuation binding is inconsistent");
        }
    }

    private static SemanticSigningScope scope(DomainContinuationStore.Kind kind,
            DomainCommandEncoding.Decoded command, AccessContext access, KeyRef key) {
        Optional<PkiId> authority = Optional.empty();
        Optional<PkiId> subjectAuthority = Optional.empty();
        Optional<String> profile = Optional.empty();
        int keyField;
        switch (kind) { // NOPMD - ExhaustiveSwitchHasDefault: statement definite assignment requires a fallback because KEY_PROOF returns.
            case KEY_PROOF -> { return ManagedKeyProofCommand.scope(command, access, key); }
            case ISSUANCE -> {
                EndEntitySigningPreparation.validateEvidence(
                        IssuanceExecutionEvidence.decode(DomainAttributeEncoding.decode(command.field(22))),
                        access, command.field(0), command.field(4));
                authority = Optional.of(new PkiId(command.field(0)));
                profile = Optional.of(command.field(4));
                keyField = 11;
                if (!"ISSUE_END_ENTITY".equals(command.operation())
                        && (access.objectId().filter(value -> value.value().equals(command.field(23))).isEmpty()
                                || access.formatId().filter(value -> "x509".equals(value.value())).isEmpty())) {
                    throw new IllegalArgumentException("Semantic predecessor access binding differs");
                }
            }
            case STATUS -> {
                authority = Optional.of(new PkiId(command.field(0)));
                keyField = 5;
            }
            case CA -> {
                boolean root = "CREATE_ROOT".equals(command.operation())
                        || ROLLOVER_ROOT.equals(command.operation());
                if (root) {
                    if (ROLLOVER_ROOT.equals(command.operation())) {
                        authority = Optional.of(new PkiId(command.field(13)));
                    }
                    profile = Optional.of(command.field(4));
                    keyField = 3;
                } else {
                    authority = Optional.of(new PkiId(command.field(1)));
                    subjectAuthority = Optional.of(new PkiId(command.field(2)));
                    profile = Optional.of(command.field(7));
                    keyField = 14;
                }
            }
            default -> throw new IllegalStateException("Unknown semantic domain");
        }
        if (!key.value().equals(command.field(keyField))) {
            throw new IllegalArgumentException("Semantic signing key binding differs");
        }
        return new SemanticSigningScope(SemanticSigningKind.valueOf(kind.name()), command.operation(),
                access, key, authority, subjectAuthority, profile, Optional.empty());
    }
}
