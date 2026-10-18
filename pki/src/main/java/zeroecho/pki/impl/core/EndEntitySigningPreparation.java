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

package zeroecho.pki.impl.core;

import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.ExtendedKeyUsage;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;

/**
 * Session-owned leaf TBS construction and staging boundary. Only validated
 * issuance or lifecycle inputs reach the shared builder. Local time and payload
 * memory are O(P + C + I + T), for bounded predecessor, CSR, issuer certificate
 * and TBS bytes, plus verification, policy validation and store I/O.
 * No signing provider, acceptance gate, thread or per-operation registry is owned.
 * Instances are thread-safe when their store is thread-safe.
 */
public final class EndEntitySigningPreparation {
    private static final String SUBMISSION_PARAMETER = "submission";
    private static final String TTL_PARAMETER = "ttl";

    private static final String EVIDENCE_ARGUMENT = "evidence";

    private final PkiStore store;
    private final EndEntityIssuancePreparation validation;
    private final EndEntityLifecyclePreparation lifecycle;

    /**
     * Creates preparation using the session's exact verification and binding graph.
     *
     * @param store authoritative session store
     * @param clock authoritative evaluation clock
     * @param authority immutable X.509 authority shared by the session
     * @param verifier cryptographic verifier bound into the authority
     * @param bindings exact configured binding registry
     * @param signatureAlgorithm canonical session signing algorithm identity
     */
    public EndEntitySigningPreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        this(store, new EndEntityIssuancePreparation(store, clock, authority, verifier, bindings, signatureAlgorithm));
    }

    /* default */ EndEntitySigningPreparation(PkiStore store, EndEntityIssuancePreparation validation) {
        this.store = Objects.requireNonNull(store, "store");
        this.validation = Objects.requireNonNull(validation, "validation");
        this.lifecycle = validation.lifecyclePreparation();
    }

    /**
     * Validates one request, freezes its command and stages its TBS exactly once.
     * On success the caller owns the returned unaccepted candidate and must either
     * hand it to semantic preparation or retire it if that handoff fails. Every
     * failure before return aborts or retires content owned by this invocation.
     *
     * @param access trusted requester audit context, not an authorization decision
     * @param request bounded caller input
     * @param submission internally generated session operation identity
     * @param ttl exact session signing lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative cancellation signal
     * @return typed domain preparation with exclusive unaccepted-content custody
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if request, issuer, profile or binding validation fails
     * @throws IllegalArgumentException if evidence conflicts with actor or frozen scope
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepare(AccessContext access, EndEntityIssuanceRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityIssuancePreparation.Prepared approved = validation.prepare(access, request, cancellation);
        return stage(approved, submission, ttl, evidence, cancellation, LeafOperation.ISSUE_END_ENTITY, Optional.empty());
    }

    /**
     * Validates a new correlated issuance against its exact imported profile and
     * current issuer/path selection, then stages one TBS with PKI-derived intent.
     * The semantic facade must perform authoritative replay lookup first. This
     * method does not reserve a correlation or accept work; custody and cleanup
     * match {@link #prepare}.
     *
     * @param access trusted requester audit context
     * @param request exact bounded request and frozen selection
     * @param submission fresh session operation identity
     * @param ttl exact session signing lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return exclusively owned staged domain preparation
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if proof, policy or frozen-selection validation fails
     * @throws IllegalArgumentException if evidence conflicts with actor or frozen scope
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareCorrelated(AccessContext access, CorrelatedEndEntityIssuanceRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        IssuanceIntent caller = request.intent();
        IssuanceIntent effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(),
                caller.expectedProfile(), caller.expectedIssuerId(), caller.expectedChainPathId(),
                caller.expectedChainPathCommitment());
        EndEntityIssuancePreparation.Prepared approved = validation.prepare(access, request.request(),
                Optional.of(effective), cancellation);
        return stage(approved, submission, ttl, evidence, cancellation, LeafOperation.ISSUE_END_ENTITY,
                Optional.empty(), identity.correlationId());
    }

    /**
     * Prepares a correlated renewal after the semantic facade has excluded an
     * accepted replay. Authoritative predecessor status and frozen selection are
     * checked before staging; content ownership matches {@link #prepare}.
     * @param access trusted requester audit context
     * @param request immutable predecessor binding and frozen selection
     * @param submission fresh session operation identity
     * @param ttl exact signing lifetime
     * @param evidence trusted issuance evidence, never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return exclusively owned staged renewal candidate
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor, policy or frozen selection is invalid
     */
    public DomainSigningRequest prepareCorrelatedRenewal(AccessContext access,
            CorrelatedEndEntityRenewalRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        IssuanceIntent caller = request.intent();
        IssuanceIntent effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(),
                caller.expectedProfile(), caller.expectedIssuerId(), caller.expectedChainPathId(),
                caller.expectedChainPathCommitment());
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareCorrelatedRenewal(
                lifecycleAccess(access, request.request().existingCredentialId()), request, effective, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.RENEW_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()), identity.correlationId());
    }

    /**
     * Stages a correlated replacement through the existing replacement continuation.
     * The caller exclusively owns the resulting candidate; no acceptance occurs.
     * @param access trusted requester audit context
     * @param request exact replacement and frozen predecessor binding
     * @param submission fresh internal signing identity
     * @param ttl signing lifetime
     * @param evidence trusted execution evidence, never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return exclusively owned staged candidate
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if proof, predecessor or frozen policy is invalid
     */
    public DomainSigningRequest prepareCorrelatedReplacement(AccessContext access,
            CorrelatedEndEntityReplacementRequest request, SigningSubmissionId submission, Duration ttl,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        IssuanceIntent caller = request.intent();
        IssuanceIntent effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(),
                caller.expectedProfile(), caller.expectedIssuerId(), caller.expectedChainPathId(),
                caller.expectedChainPathCommitment());
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareCorrelatedReplacement(
                lifecycleAccess(access, request.request().existingCredentialId()), request, effective, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.REPLACE_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()), identity.correlationId());
    }

    /**
     * Prepares renewal through the shared leaf builder and single staging path.
     * The predecessor supplies immutable source identity and current policy selection.
     * Ownership and cleanup match {@link #prepare}.
     * @param access trusted actor/purpose, with absent or matching source coordinates
     * @param request immutable renewal input
     * @param submission internally generated fresh operation identity
     * @param ttl exact session lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return staged domain request exclusively owned by its caller
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor or policy validation fails
     * @throws IllegalArgumentException if supplied access coordinates or evidence conflict
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareRenewal(AccessContext access, EndEntityRenewalRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareRenewal(
                lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.RENEW_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()));
    }

    /**
     * Prepares verified replacement through the shared leaf builder and staging path.
     * Ownership and cleanup match {@link #prepare}.
     * @param access trusted actor/purpose, with absent or matching source coordinates
     * @param request immutable predecessor, exact CSR and selected profile
     * @param submission internally generated fresh operation identity
     * @param ttl exact session lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return staged domain request exclusively owned by its caller
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor, proof or policy validation fails
     * @throws IllegalArgumentException if supplied access coordinates or evidence conflict
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareReplacement(AccessContext access, EndEntityReplacementRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareReplacement(
                lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.REPLACE_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()));
    }

    /**
     * Prepares reissue through the shared leaf builder and single staging path.
     * Ownership and cleanup match {@link #prepare}.
     * @param access trusted actor/purpose, with absent or matching source coordinates
     * @param request immutable reissue input
     * @param submission internally generated fresh operation identity
     * @param ttl exact session lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return staged domain request exclusively owned by its caller
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor or policy validation fails
     * @throws IllegalArgumentException if supplied access coordinates or evidence conflict
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareReissue(AccessContext access, EndEntityReissueRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareReissue(
                lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.REISSUE_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()));
    }

    private static AccessContext lifecycleAccess(AccessContext access, PkiId predecessor) {
        Objects.requireNonNull(access, "access");
        if (access.objectId().filter(value -> !value.equals(predecessor)).isPresent()
                || access.formatId().filter(value -> !value.equals(BcX509CredentialFramework.FORMAT_ID)).isPresent()) {
            throw new IllegalArgumentException("Lifecycle access coordinates conflict with predecessor");
        }
        return new AccessContext(access.principal(), access.purpose(), Optional.of(predecessor),
                Optional.of(BcX509CredentialFramework.FORMAT_ID));
    }

    private DomainSigningRequest stage(EndEntityIssuancePreparation.Prepared approved, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation,
            LeafOperation operation, Optional<PkiId> predecessor)
            throws IOException {
        String correlation = "issue." + sha256(submission.id().value().getBytes(StandardCharsets.UTF_8));
        return stage(approved, submission, ttl, evidence, cancellation, operation, predecessor, correlation);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private DomainSigningRequest stage(EndEntityIssuancePreparation.Prepared approved, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation,
            LeafOperation operation, Optional<PkiId> predecessor,
            String correlation) throws IOException {
        validateEvidence(evidence, approved.access(), approved.request().issuerCaId().value(),
                approved.request().profileId());
        byte[] tbs = tbs(approved);
        if (tbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate body exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        DomainContinuationTemplate template = continuation(approved, correlation, operation, predecessor, evidence);
        DurableContentReference content = null;
        try {
            cancellation.throwIfCancelled();
            try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER,
                    DurableContentReference.Lifecycle.OPERATION); OutputStream output = sink.outputStream()) {
                int offset = 0;
                while (offset < tbs.length) {
                    cancellation.throwIfCancelled();
                    int length = Math.min(16 * 1024, tbs.length - offset);
                    output.write(tbs, offset, length);
                    offset += length;
                }
                cancellation.throwIfCancelled();
                content = sink.complete();
            }
            cancellation.throwIfCancelled();
            return new DomainSigningRequest(submission.id(), approved.access(), approved.keyRef(),
                    approved.signature().canonicalForm(), Encoding.BINARY, content, ttl, template, Optional.empty());
        } catch (IOException | RuntimeException | Error primary) {
            if (content != null) {
                try {
                    store.stagedContent().retireUnownedContent(content);
                } catch (IOException | RuntimeException cleanup) {
                    primary.addSuppressed(cleanup);
                }
            }
            throw primary;
        }
    }

    private static byte[] tbs(EndEntityIssuancePreparation.Prepared approved) {
        ValidatedCertificateRequest request = approved.request();
        CertificateBuilder builder = Pkix.certificateBuilder().serialNumber(approved.serial())
                .issuer(Pkix.parseCertificate(approved.issuerDer()).getSubjectX500Principal())
                .subject(BcX509ProfileSupport.subject(request.subjectRdns()))
                .validity(request.validity().notBefore(), request.validity().notAfter())
                .publicKeyInfo(request.exactPublicKey().bytes())
                .basicConstraints(BasicConstraints.endEntity(), request.basicConstraintsCritical());
        if (!request.keyUsages().isEmpty()) {
            builder.keyUsage(keyUsages(request.keyUsages()), request.keyUsageCritical());
        }
        if (!request.extendedKeyUsages().isEmpty()) {
            builder.extendedKeyUsage(new ExtendedKeyUsage(request.extendedKeyUsages().stream()
                    .map(ExtendedKeyUsageId::oid).sorted().toList()), request.extendedKeyUsageCritical());
        }
        if (!request.subjectAlternativeNames().isEmpty()) {
            builder.subjectAlternativeNames(request.subjectAlternativeNames().stream()
                    .map(EndEntitySigningPreparation::generalName).toList(), request.subjectAlternativeNameCritical());
        }
        return builder.buildTbs(approved.signatureBinding());
    }

    private static DomainContinuationTemplate continuation(EndEntityIssuancePreparation.Prepared approved,
            String correlation, LeafOperation operation, Optional<PkiId> predecessor,
            Optional<IssuanceExecutionEvidence> evidence) {
        ValidatedCertificateRequest request = evidence.isPresent()
                ? approved.request().withExecutionEvidence(evidence.orElseThrow().attributes()) : approved.request();
        ValidatedCertificateRequest.FrozenIssuance frozen = request.frozenIssuance().orElseThrow();
        List<String> fields = new ArrayList<>(List.of(request.issuerCaId().value(), frozen.issuerId().value(), frozen.chainPathId().value(),
                frozen.chainPathCommitment(), request.profileId(), Long.toString(request.profileReference().profileVersion()),
                HexFormat.of().formatHex(request.profileReference().canonicalSha256()), request.subjectRef().value(),
                request.validity().notBefore().toString(), request.validity().notAfter().toString(), approved.serial().toString(),
                approved.keyRef().value(), approved.issuerContent().contentId(), approved.issuerContent().sha256(),
                sha256(request.exactPublicKey().bytes()), frozen.intent().map(IssuanceIntent::issuanceId).orElse(""),
                frozen.intent().map(IssuanceIntent::commandCommitment).orElse(""), request.subjectRdns().toString(),
                request.subjectAlternativeNames().toString(), request.keyUsages().stream().sorted().toList().toString(),
                request.extendedKeyUsages().stream().sorted(java.util.Comparator.comparing(ExtendedKeyUsageId::oid))
                        .toList().toString(),
                request.algorithmBindingPolicy().toString(), DomainAttributeEncoding.encode(request.executionEvidence())));
        predecessor.ifPresent(value -> fields.add(value.value()));
        return DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE, correlation,
                operation.name(), fields.toArray(String[]::new));
    }

    /** Leaf workflow discriminator retained in the accepted signing metadata. */
    private enum LeafOperation { ISSUE_END_ENTITY, RENEW_END_ENTITY, REPLACE_END_ENTITY, REISSUE_END_ENTITY }

    /**
     * Checks trusted evidence against the actor and already frozen issuance scope.
     * Performs no store lookup, policy admission, allocation of content or mutation.
     *
     * @param evidence trusted or decoded evidence, possibly empty but never null
     * @param access invocation or retained acceptance audit context
     * @param issuerCaId authoritative logical issuing authority identifier
     * @param profileId authoritative frozen profile identifier
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if present evidence conflicts with the supplied binding
     */
    public static void validateEvidence(Optional<IssuanceExecutionEvidence> evidence, AccessContext access,
            String issuerCaId, String profileId) {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(issuerCaId, "issuerCaId");
        Objects.requireNonNull(profileId, "profileId");
        if (evidence.isPresent()) {
            IssuanceExecutionEvidence value = evidence.orElseThrow();
            if (!value.actorId().equals(access.principal().name())
                    || !value.actorType().name().equals(access.principal().type())
                    || !value.issuerCaId().equals(issuerCaId) || !value.profileId().equals(profileId)) {
                throw new IllegalArgumentException("Issuance execution evidence binding differs");
            }
        }
    }

    private static Set<KeyUsage> keyUsages(Set<LeafKeyUsage> source) {
        Set<KeyUsage> result = EnumSet.noneOf(KeyUsage.class);
        for (LeafKeyUsage usage : source) {
            result.add(switch (usage) {
                case DIGITAL_SIGNATURE -> KeyUsage.DIGITAL_SIGNATURE;
                case CONTENT_COMMITMENT -> KeyUsage.NON_REPUDIATION;
                case KEY_ENCIPHERMENT -> KeyUsage.KEY_ENCIPHERMENT;
                case DATA_ENCIPHERMENT -> KeyUsage.DATA_ENCIPHERMENT;
                case KEY_AGREEMENT -> KeyUsage.KEY_AGREEMENT;
                case ENCIPHER_ONLY -> KeyUsage.ENCIPHER_ONLY;
                case DECIPHER_ONLY -> KeyUsage.DECIPHER_ONLY;
            });
        }
        return result;
    }

    private static GeneralName generalName(SubjectAlternativeName name) {
        return switch (name) {
            case SubjectAlternativeName.DnsName dns -> new GeneralName.DnsName(dns.value());
            case SubjectAlternativeName.Rfc822Name email -> new GeneralName.Rfc822Name(email.value());
            case SubjectAlternativeName.UriName uri -> new GeneralName.UniformResourceIdentifier(uri.value());
            case SubjectAlternativeName.IpAddress ip -> new GeneralName.IpAddress(ipLiteral(ip.bytes()));
        };
    }

    private static String ipLiteral(byte[] octets) {
        try {
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (UnknownHostException impossible) {
            throw new IllegalArgumentException("Invalid validated IP address length", impossible);
        }
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
