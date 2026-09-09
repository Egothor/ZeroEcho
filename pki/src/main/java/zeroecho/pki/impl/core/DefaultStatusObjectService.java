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
package zeroecho.pki.impl.core;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import java.security.cert.X509Certificate;

import zeroecho.pkix.Pkix;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectQuery;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509SignedObjectValidator;
import zeroecho.pki.impl.core.async.PendingSigningOperation;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SignedObjectCompletion;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pki.spi.store.RevocationView;

/**
 * Default implementation of {@link StatusObjectService}.
 *
 * <p>
 * This service coordinates generation and lookup of PKI status objects against
 * the configured {@link PkiStore} and delegates format-specific object creation
 * to the active {@link CredentialFramework}. The store acts as the
 * authoritative source of issuer CA state, issuer credentials, revocation
 * transitions, and previously generated status objects.
 * </p>
 *
 * <p>
 * The current runtime implementation primarily supports generation workflows
 * that require issuer certificate material and issuer signing key indirection
 * to be provided through status-object attributes. For X.509 CRL generation,
 * this class derives structured CRL entries from a stable ordered current-state
 * snapshot and the referenced X.509 credentials.
 * </p>
 *
 * <h2>Persistence model</h2>
 * <ul>
 * <li>Each successfully generated {@link StatusObject} is persisted through the
 * configured {@link PkiStore}.</li>
 * <li>Lookup operations read directly from the store and do not maintain an
 * internal cache.</li>
 * <li>The service is stateless apart from its immutable collaborators.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This service does not access private key material directly.</li>
 * <li>Issuer signing capability is conveyed only through
 * {@link BcX509Attributes#ISSUER_KEYREF}.</li>
 * <li>For CRL generation, every selected current state and referenced target is
 * validated before signing. Any unresolved or malformed state aborts generation
 * with a stable redacted failure.</li>
 * <li>The correctness of the generated status object depends on the configured
 * {@link CredentialFramework} matching the requested runtime format and
 * honoring the supplied attributes.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is safe for concurrent use provided that the injected
 * {@link PkiStore} and {@link CredentialFramework} implementations are
 * themselves safe for the intended concurrency model.
 * </p>
 */
// Status generation deliberately keeps the closed CRL/OCSP policy branches in one cohesive service.
@SuppressWarnings("PMD.CyclomaticComplexity")
public final class DefaultStatusObjectService implements StatusObjectService {
    private static final String CRL_GENERATION_FAILED = "CRL_GENERATION_FAILED";
    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose STATUS_PURPOSE = new Purpose("STATUS_GENERATION");

    private final PkiStore store;
    private final CredentialFramework framework;
    private final AuditSink auditSink;
    private final EffectiveCredentialStatusResolver statusResolver;
    private final X509AuthoritySnapshot authority;

    /**
     * Creates a status object service bound to the supplied persistence and
     * framework collaborators.
     *
     * @param store          PKI store used for issuer lookup, revocation
     *                       enumeration, status object persistence, and status
     *                       object listing; must not be {@code null}
     * @param framework      credential framework providing the format-specific
     *                       status object generator; must not be {@code null}
     * @param auditSink      required sink for safe trust-rejection audit events
     * @param statusResolver authoritative runtime credential-status resolver
     * @param authority trusted X.509 algorithm authority snapshot
     * @throws NullPointerException if an argument is {@code null}
     */
    public DefaultStatusObjectService(PkiStore store, CredentialFramework framework, AuditSink auditSink,
            EffectiveCredentialStatusResolver statusResolver, X509AuthoritySnapshot authority) {
        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.statusResolver = Objects.requireNonNull(statusResolver, "statusResolver");
        this.authority = Objects.requireNonNull(authority, "authority");
    }

    /**
     * Generates a new status object for the specified issuer CA and persists the
     * result.
     *
     * <p>
     * The issuer CA must already exist, must be in {@link CaState#ACTIVE} state,
     * and must expose at least one usable credential matching the requested format.
     * Candidates are evaluated newest-first against current revocation state and
     * one authoritative evaluation time.
     * </p>
     *
     * <p>
     * The supplied command attributes are copied and then enriched with issuer
     * material required by the current backend wiring:
     * </p>
     * <ul>
     * <li>{@link BcX509Attributes#ISSUER_CERT_DER} is populated from the selected
     * issuer credential encoding,</li>
     * <li>{@link BcX509Attributes#ISSUER_KEYREF} is populated from the issuer CA
     * key reference.</li>
     * </ul>
     *
     * <p>
     * When {@link StatusObjectType#CRL} is requested, the service validates every
     * current state from one stable authoritative revision before signing. Hold and permanent
     * states are transported with the exact positive X.509 serial, authoritative
     * transition time, and explicit reason. Current {@code CLEAR} states are
     * omitted.
     * </p>
     *
     * <p>
     * Missing targets, malformed credentials, duplicate serials, future
     * transitions, corrupt derived state, and store failures abort the complete CRL
     * before generator invocation or persistence with a stable redacted error.
     * </p>
     *
     * @param command status object generation request; must not be {@code null}
     * @return generated and persisted status object
     * @throws IllegalArgumentException if {@code command} is {@code null}
     * @throws PkiException             if the issuer CA does not exist, is not
     *                                  active, has no credentials, if the framework
     *                                  generator fails, or if persistence of the
     *                                  generated status object fails
     */
    @Override
    public StatusObject generate(StatusObjectGenerateCommand command) {
        return generate(command, CancellationSignal.NONE);
    }

    @Override
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    public StatusObject generate(StatusObjectGenerateCommand command, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, "cancellation");
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        if (command.type() == StatusObjectType.OCSP) {
            return generateAndPersistOcsp(command, cancellation);
        }
        if (command.type() != StatusObjectType.CRL && command.type() != StatusObjectType.DELTA_CRL) {
            return generateAndPersistOther(command.type());
        }
        CaRecord ca = store.getCa(command.issuerCaId()).orElseThrow(() -> new PkiException("Issuer CA not found",
                zeroecho.pki.api.PkiFailureReason.ISSUER_CA_NOT_FOUND));
        if (ca.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA not ACTIVE",
                    zeroecho.pki.api.PkiFailureReason.ISSUER_CA_NOT_ACTIVE);
        }
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCred = selectIssuerCredential(ca, command, statusEvaluation);

        SimpleAttributeSet.Builder b = SimpleAttributeSet.builder();
        b.putAll(command.attributes());
        byte[] issuerDer = materializeValidatedCertificate(issuerCred);
        try {
            b.put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(issuerDer.clone()));
        } finally {
            Arrays.fill(issuerDer, (byte) 0);
        }
        b.put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(ca.issuerKeyRef().value()));
        b.put(BcX509Attributes.CRL_NUMBER,
                new AttributeValue.StringValue(nextCrlNumber(command.issuerCaId()).toString()));

        Optional<Instant> deltaSinceExclusive = Optional.empty();
        if (command.type() == StatusObjectType.DELTA_CRL) {
            StatusObject base = getLatest(command.issuerCaId(), StatusObjectType.CRL).orElseThrow(
                    () -> new PkiException("Delta CRL requires a base full CRL: code=DELTA_CRL_BASE_MISSING"));
            b.put(BcX509Attributes.BASE_CRL_NUMBER,
                    new AttributeValue.StringValue(requireBaseCrlNumber(base).toString()));
            deltaSinceExclusive = Optional.of(base.thisUpdate());
        }

        StatusObjectGenerateCommand wired = new StatusObjectGenerateCommand(command.issuerCaId(), command.type(),
                command.formatId(), b.build());
        try (CrlEntrySource entries = openCrlEntries(command.issuerCaId(), statusEvaluation.evaluationTime(),
                deltaSinceExclusive)) {
            return generateAndPersistCrl(wired, entries, issuerCred, cancellation);
        } catch (PendingSigningOperation | zeroecho.pki.api.SigningExecutionException signingFailure) {
            throw signingFailure;
        } catch (IOException | RuntimeException exception) {
            // The public boundary deliberately removes hostile provider and persisted-data details.
            throw crlGenerationFailure();
        }
    }

    private StatusObject generateAndPersistCrl(StatusObjectGenerateCommand command, CrlEntrySource entries,
            Credential issuer, CancellationSignal cancellation) {
        X509SignedObjectCompletion completion = framework.statusObjectGenerator().generate(command, entries,
                cancellation);
        StatusObject generated = authority.requireStatusCompletion(completion);
        X509ExecutionPlan<SignatureWorkflow> signingPlan = authority.requireStatusSigningPlan(completion);
        requirePersistableContent(generated.content());
        boolean accepted = false;
        try {
            requireGeneratedMetadata(command, generated);
            byte[] issuerDer = materializeValidatedCertificate(issuer);
            try (RepeatableContent content = store.stagedContent().openContent(generated.content())) {
                X509Certificate holder = Pkix.parseCertificate(issuerDer);
                new BcX509SignedObjectValidator(authority).validateGeneratedCrl(content, signingPlan,
                        holder, generated.thisUpdate(), generated.nextUpdate(), cancellation);
            } finally {
                Arrays.fill(issuerDer, (byte) 0);
            }
            store.putStatusObject(generated);
            accepted = true;
            auditStatusGenerated(generated);
            return generated;
        } catch (IOException exception) {
            throw new PkiException("Status postcondition validation failed: code=CONTENT_IO_FAILED", exception);
        } finally {
            if (!accepted) {
                releaseRejectedContent(generated.content());
            }
        }
    }

    private StatusObject generateAndPersistOther(StatusObjectType type) {
        throw new PkiException("Status object type not supported: code=STATUS_TYPE_NOT_SUPPORTED type=" + type.name());
    }

    /**
     * Generates and persists a single-certificate, issuer-signed OCSP status
     * object. The operator supplies the target serial via
     * {@link BcX509Attributes#OCSP_TARGET_SERIAL}; the service resolves the target's
     * authoritative current revocation status from one stable revocation view and
     * conveys it to the generator, which signs the response through the durable
     * status signing seam.
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private StatusObject generateAndPersistOcsp(StatusObjectGenerateCommand command, CancellationSignal cancellation) {
        CaRecord ca = store.getCa(command.issuerCaId()).orElseThrow(() -> new PkiException("Issuer CA not found",
                zeroecho.pki.api.PkiFailureReason.ISSUER_CA_NOT_FOUND));
        if (ca.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA not ACTIVE",
                    zeroecho.pki.api.PkiFailureReason.ISSUER_CA_NOT_ACTIVE);
        }
        EffectiveCredentialStatusResolver.Evaluation evaluation = statusResolver.beginEvaluation();
        Credential issuerCred = selectIssuerCredential(ca, command, evaluation);
        BigInteger serial = requireOcspTargetSerial(command.attributes());
        Credential target = resolveOcspTarget(ca, serial);

        SimpleAttributeSet.Builder b = SimpleAttributeSet.builder();
        b.putAll(command.attributes());
        byte[] issuerDer = materializeValidatedCertificate(issuerCred);
        try {
            b.put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(issuerDer.clone()));
        } finally {
            Arrays.fill(issuerDer, (byte) 0);
        }
        b.put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(ca.issuerKeyRef().value()));
        b.put(BcX509Attributes.OCSP_TARGET_SERIAL, new AttributeValue.StringValue(serial.toString()));
        wireOcspStatus(b, target);

        StatusObjectGenerateCommand wired = new StatusObjectGenerateCommand(command.issuerCaId(), command.type(),
                command.formatId(), b.build());
        try (CrlEntrySource empty = EmptyCrlEntrySource.INSTANCE) {
            return generateAndPersistOcspObject(wired, issuerCred, empty, cancellation);
        } catch (zeroecho.pki.impl.core.async.ImmediateSigningPending | PendingSigningOperation
                | zeroecho.pki.api.SigningExecutionException signingFailure) {
            throw signingFailure;
        } catch (IOException | RuntimeException exception) {
            throw ocspGenerationFailure(exception);
        }
    }

    private StatusObject generateAndPersistOcspObject(StatusObjectGenerateCommand command, Credential issuer,
            CrlEntrySource entries, CancellationSignal cancellation) {
        X509SignedObjectCompletion completion = framework.statusObjectGenerator().generate(command, entries,
                cancellation);
        StatusObject generated = authority.requireStatusCompletion(completion);
        X509ExecutionPlan<SignatureWorkflow> signingPlan = authority.requireStatusSigningPlan(completion);
        requirePersistableContent(generated.content());
        boolean accepted = false;
        try {
            requireGeneratedMetadata(command, generated);
            byte[] issuerDer = materializeValidatedCertificate(issuer);
            try (RepeatableContent content = store.stagedContent().openContent(generated.content())) {
                X509Certificate holder = Pkix.parseCertificate(issuerDer);
                new BcX509SignedObjectValidator(authority).validateGeneratedOcsp(content, signingPlan, holder,
                        generated.thisUpdate(), generated.nextUpdate(), cancellation);
            } finally {
                Arrays.fill(issuerDer, (byte) 0);
            }
            store.putStatusObject(generated);
            accepted = true;
            auditStatusGenerated(generated);
            return generated;
        } catch (IOException exception) {
            throw new PkiException("Status postcondition validation failed: code=CONTENT_IO_FAILED", exception);
        } finally {
            if (!accepted) {
                releaseRejectedContent(generated.content());
            }
        }
    }

    private static BigInteger requireOcspTargetSerial(zeroecho.pki.api.attr.AttributeSet attributes) {
        Optional<AttributeValue> value = attributes.get(BcX509Attributes.OCSP_TARGET_SERIAL);
        if (value.isEmpty() || !(value.orElseThrow() instanceof AttributeValue.StringValue text)) {
            throw new PkiException("OCSP target serial required: code=OCSP_TARGET_REQUIRED");
        }
        try {
            BigInteger serial = new BigInteger(text.value());
            if (serial.signum() <= 0) {
                throw new PkiException("Invalid OCSP target serial: code=OCSP_TARGET_INVALID");
            }
            return serial;
        } catch (NumberFormatException ex) {
            throw new PkiException("Invalid OCSP target serial: code=OCSP_TARGET_INVALID", ex);
        }
    }

    private Credential resolveOcspTarget(CaRecord ca, BigInteger serial) {
        for (PkiId issuerId : ca.issuerIds()) {
            Optional<Credential> found = store.getCredentialByIssuerAndSerial(issuerId, serial);
            if (found.isPresent()) {
                return found.orElseThrow();
            }
        }
        throw new PkiException("OCSP target not found: code=OCSP_TARGET_UNKNOWN",
                zeroecho.pki.api.PkiFailureReason.STATUS_TARGET_NOT_FOUND);
    }

    private void wireOcspStatus(SimpleAttributeSet.Builder b, Credential target) {
        try (RevocationView view = store.openRevocationView()) {
            Optional<RevocationRecord> record = view.get(target.credentialId());
            RevocationState state = record.map(r -> r.transition().state()).orElse(RevocationState.CLEAR);
            if (state == RevocationState.CLEAR) {
                b.put(BcX509Attributes.OCSP_CERT_STATUS, new AttributeValue.StringValue("GOOD"));
                return;
            }
            RevocationTransition transition = record.orElseThrow().transition();
            RevocationReason reason = switch (state) {
                case HELD -> RevocationReason.CERTIFICATE_HOLD;
                case PERMANENTLY_REVOKED -> transition.permanentReason().orElse(RevocationReason.UNSPECIFIED);
                case CLEAR -> RevocationReason.UNSPECIFIED;
            };
            b.put(BcX509Attributes.OCSP_CERT_STATUS, new AttributeValue.StringValue("REVOKED"));
            b.put(BcX509Attributes.OCSP_REVOCATION_TIME, new AttributeValue.InstantValue(transition.time()));
            b.put(BcX509Attributes.OCSP_REVOCATION_REASON, new AttributeValue.StringValue(reason.name()));
        } catch (IOException ex) {
            throw ocspGenerationFailure(ex);
        }
    }

    private static PkiException ocspGenerationFailure(Throwable cause) {
        return new PkiException("OCSP status generation failed: code=OCSP_GENERATION_FAILED", cause);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void auditStatusGenerated(StatusObject generated) {
        try {
            auditSink.record(new AuditEvent(generated.thisUpdate(), "STATUS", "STATUS_GENERATED",
                    SYSTEM_PKI, STATUS_PURPOSE, Optional.of(generated.statusObjectId()),
                    Optional.of(generated.formatId()),
                    java.util.Map.of("type", generated.type().name(),
                            "issuerCaId", generated.issuerCaId().value())));
        } catch (RuntimeException ignored) {
            // Best-effort: audit failures must not alter the persistence outcome.
        }
    }

    /** Non-null empty CRL entry source for status types that carry no CRL entries. */
    private enum EmptyCrlEntrySource implements CrlEntrySource {
        INSTANCE;

        @Override
        public Cursor openCursor() {
            return new Cursor() {
                @Override
                public boolean next() {
                    return false;
                }

                @Override
                public CrlEntry current() {
                    throw new IllegalStateException("Empty CRL entry cursor is not positioned");
                }

                @Override
                public long ordinal() {
                    throw new IllegalStateException("Empty CRL entry cursor is not positioned");
                }

                @Override
                public void close() {
                    // No resources.
                }
            };
        }

        @Override
        public OptionalLong count() {
            return OptionalLong.of(0L);
        }

        @Override
        public void close() {
            // No resources.
        }
    }

    private BigInteger nextCrlNumber(PkiId issuerCaId) {
        BigInteger max = BigInteger.ZERO;
        for (StatusObject object : store.listStatusObjects(issuerCaId)) {
            if (object.type() != StatusObjectType.CRL && object.type() != StatusObjectType.DELTA_CRL) {
                continue;
            }
            Optional<BigInteger> number = crlNumber(object);
            if (number.isPresent() && number.orElseThrow().compareTo(max) > 0) {
                max = number.orElseThrow();
            }
        }
        return max.add(BigInteger.ONE);
    }

    private static BigInteger requireBaseCrlNumber(StatusObject base) {
        return crlNumber(base).orElseThrow(
                () -> new PkiException("Base CRL has no CRL number: code=DELTA_CRL_BASE_INVALID"));
    }

    private static Optional<BigInteger> crlNumber(StatusObject object) {
        Optional<AttributeValue> value = object.attributes().get(BcX509Attributes.CRL_NUMBER);
        if (value.isEmpty() || !(value.orElseThrow() instanceof AttributeValue.StringValue text)) {
            return Optional.empty();
        }
        try {
            BigInteger number = new BigInteger(text.value());
            return number.signum() >= 0 ? Optional.of(number) : Optional.empty();
        } catch (NumberFormatException ex) {
            return Optional.empty();
        }
    }

    private void requirePersistableContent(DurableContentReference content) {
        if (content.lifecycle() != DurableContentReference.Lifecycle.PERSISTED
                || !store.stagedContent().contentStoreId().equals(content.storeId())
                || content.encoding() != Encoding.DER) {
            throw new PkiException("Status content lifecycle invalid: code=STAGED_CONTENT_FOREIGN_RUNTIME");
        }
    }

    private static void requireGeneratedMetadata(StatusObjectGenerateCommand command, StatusObject generated) {
        if (generated.type() != command.type() || !generated.formatId().equals(command.formatId())
                || !generated.issuerCaId().equals(command.issuerCaId())
                || generated.nextUpdate().filter(next -> !next.isAfter(generated.thisUpdate())).isPresent()) {
            throw new PkiException("Status metadata binding invalid: code=STATUS_OBJECT_BINDING_MISMATCH");
        }
    }

    private void releaseRejectedContent(DurableContentReference content) {
        try {
            store.stagedContent().retireUnownedContent(content);
        } catch (IOException cleanupFailure) {
            throw new PkiException("Rejected status content cleanup failed: code=CONTENT_IO_FAILED", cleanupFailure);
        }
    }

    private CrlEntrySource openCrlEntries(PkiId issuerCaId, Instant evaluationTime,
            Optional<Instant> sinceExclusive) {
        return new CheckpointCrlEntrySource(store.openRevocationSnapshot(), issuerCaId, evaluationTime,
                sinceExclusive);
    }

    private Optional<CrlEntry> collectCrlEntry(PkiId issuerCaId, Instant evaluationTime, RevocationRecord record) {
        Objects.requireNonNull(record, "record");
        RevocationTransition latest = Objects.requireNonNull(record.transition(), "latest transition");
        if (latest.time().isAfter(evaluationTime)) {
            throw crlGenerationFailure();
        }
        if (latest.state() == RevocationState.CLEAR) {
            return Optional.empty();
        }
        Credential credential = store.getCredential(record.credentialId())
                .orElseThrow(DefaultStatusObjectService::crlGenerationFailure);
        if (!issuerCaId.equals(credential.issuerRef().caId())) {
            return Optional.empty();
        }
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())
                || credential.content().encoding() != Encoding.DER) {
            throw crlGenerationFailure();
        }
        BigInteger serial = certificateSerial(credential);
        RevocationReason reason = switch (latest.state()) {
            case HELD -> RevocationReason.CERTIFICATE_HOLD;
            case PERMANENTLY_REVOKED ->
                latest.permanentReason().orElseThrow(DefaultStatusObjectService::crlGenerationFailure);
            case CLEAR -> throw crlGenerationFailure();
        };
        return Optional.of(new CrlEntry(serial, latest.time(), reason));
    }

    /** Stable restartable view over one revocation-store snapshot. */
    private final class CheckpointCrlEntrySource implements CrlEntrySource {
        private final RevocationSnapshot snapshot;
        private final PkiId issuerCaId;
        private final Instant evaluationTime;
        private final Optional<Instant> sinceExclusive;

        private CheckpointCrlEntrySource(RevocationSnapshot snapshot, PkiId issuerCaId, Instant evaluationTime,
                Optional<Instant> sinceExclusive) {
            this.snapshot = snapshot;
            this.issuerCaId = issuerCaId;
            this.evaluationTime = evaluationTime;
            this.sinceExclusive = sinceExclusive;
        }

        @Override
        public Cursor openCursor() throws IOException {
            return new CheckpointCrlCursor(snapshot.openCursor(), issuerCaId, evaluationTime, sinceExclusive);
        }

        @Override
        public OptionalLong count() {
            return OptionalLong.empty();
        }

        @Override
        public void close() throws IOException {
            snapshot.close();
        }
    }

    /** Bounded cursor translating stable validated current states into CRL entries. */
    private final class CheckpointCrlCursor implements CrlEntrySource.Cursor {
        private final RevocationSnapshot.Cursor cursor;
        private final PkiId issuerCaId;
        private final Instant evaluationTime;
        private final Optional<Instant> sinceExclusive;
        private CrlEntry current;
        private long ordinal = -1L;

        private CheckpointCrlCursor(RevocationSnapshot.Cursor cursor, PkiId issuerCaId, Instant evaluationTime,
                Optional<Instant> sinceExclusive) {
            this.cursor = cursor;
            this.issuerCaId = issuerCaId;
            this.evaluationTime = evaluationTime;
            this.sinceExclusive = sinceExclusive;
        }

        @Override
        public boolean next() throws IOException {
            while (cursor.next()) {
                Optional<CrlEntry> candidate = collectCrlEntry(issuerCaId, evaluationTime, cursor.current());
                if (candidate.isPresent() && includesInDelta(candidate.orElseThrow())) {
                    current = candidate.orElseThrow();
                    ordinal = Math.addExact(ordinal, 1L);
                    return true;
                }
            }
            current = null;
            return false;
        }

        private boolean includesInDelta(CrlEntry entry) {
            return sinceExclusive.isEmpty() || entry.transitionTime().isAfter(sinceExclusive.orElseThrow());
        }

        @Override
        public CrlEntry current() {
            if (current == null) {
                throw new IllegalStateException("CRL entry cursor is not positioned");
            }
            return current;
        }

        @Override
        public long ordinal() {
            if (current == null) {
                throw new IllegalStateException("CRL entry cursor is not positioned");
            }
            return ordinal;
        }

        @Override
        public void close() throws IOException {
            cursor.close();
            current = null;
        }
    }

    // Parser failures can contain persisted certificate details; the original
    // cause is intentionally removed at this public service boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private BigInteger certificateSerial(Credential credential) {
        byte[] der = materializeValidatedCertificate(credential);
        BigInteger serial;
        try {
            serial = Pkix.parseCertificate(der).getSerialNumber();
        } catch (Exception exception) {
            throw crlGenerationFailure();
        } finally {
            Arrays.fill(der, (byte) 0);
        }
        if (serial == null || serial.signum() <= 0) {
            throw crlGenerationFailure();
        }
        return serial;
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private byte[] materializeValidatedCertificate(Credential credential) {
        try {
            CredentialContent.validateCertificate(store, credential.content(), authority, Optional.empty());
            return CredentialContent.materializeForBc(store, credential.content());
        } catch (RuntimeException exception) {
            throw crlGenerationFailure();
        }
    }

    private static PkiException crlGenerationFailure() {
        return new PkiException("CRL generation failed: code=" + CRL_GENERATION_FAILED);
    }

    private Credential selectIssuerCredential(CaRecord ca, StatusObjectGenerateCommand command,
            EffectiveCredentialStatusResolver.Evaluation evaluation) {
        Credential credential = IssuerAuthorities.currentCredential(store, ca);
        if (!command.formatId().equals(credential.formatId())) {
            throw new PkiException("Issuer credential unavailable: code=ISSUER_CREDENTIAL_UNAVAILABLE");
        }
        EffectiveCredentialStatus status = evaluation.resolve(credential);
        if (status != EffectiveCredentialStatus.USABLE) {
            CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), credential,
                    CredentialUse.STATUS_OBJECT_ISSUER, "ISSUER_CREDENTIAL_UNAVAILABLE", status);
            throw new PkiException("Issuer credential unavailable: code=ISSUER_CREDENTIAL_UNAVAILABLE");
        }
        return credential;
    }

    /**
     * Resolves the most recent status object of the requested type for a given
     * issuer CA.
     *
     * <p>
     * The method examines all status objects returned by
     * {@link PkiStore#listStatusObjects(PkiId)} for the supplied issuer and selects
     * the object with the greatest {@link StatusObject#thisUpdate()} value among
     * those whose {@link StatusObjectType} matches the requested type.
     * </p>
     *
     * <p>
     * If multiple objects share the same latest {@code thisUpdate} instant, the
     * stream {@code max(...)} semantics determine which matching object is
     * returned. The current implementation does not define any additional tie-break
     * rule.
     * </p>
     *
     * @param issuerCaId identifier of the issuer CA whose latest status object is
     *                   to be resolved; must not be {@code null}
     * @param type       requested status object type; must not be {@code null}
     * @return optional containing the latest matching status object, or an empty
     *         optional when no object of the requested type exists for the issuer
     * @throws IllegalArgumentException if {@code issuerCaId} or {@code type} is
     *                                  {@code null}
     */
    @Override
    public Optional<StatusObject> getLatest(PkiId issuerCaId, StatusObjectType type) {
        if (issuerCaId == null) {
            throw new IllegalArgumentException("issuerCaId must not be null");
        }
        if (type == null) {
            throw new IllegalArgumentException("type must not be null");
        }
        List<StatusObject> all = store.listStatusObjects(issuerCaId);
        return all.stream().filter(o -> o.type() == type).max(java.util.Comparator.comparing(StatusObject::thisUpdate));
    }

    /**
     * Lists status objects for one issuer CA filtered by the supplied query
     * constraints.
     *
     * <p>
     * Filtering is performed in memory over the status objects returned by
     * {@link PkiStore#listStatusObjects(PkiId)} for the queried issuer CA. Only
     * constraints present in the {@link StatusObjectQuery} are applied.
     * </p>
     *
     * <h4>Time filtering semantics</h4>
     * <ul>
     * <li>{@code createdAfter}: objects strictly earlier than the supplied instant
     * are excluded; objects exactly at the supplied instant are retained.</li>
     * <li>{@code createdBefore}: objects at or after the supplied instant are
     * excluded; only objects strictly before the supplied instant are
     * retained.</li>
     * </ul>
     *
     * @param query query describing the issuer CA and optional filtering criteria;
     *              must not be {@code null}
     * @return immutable list of matching status objects; never {@code null}
     * @throws IllegalArgumentException if {@code query} is {@code null}
     */
    @Override
    public List<StatusObject> list(StatusObjectQuery query) {
        if (query == null) {
            throw new IllegalArgumentException("query must not be null");
        }
        List<StatusObject> all = store.listStatusObjects(query.issuerCaId());
        return all.stream().filter(o -> {
            if (query.type().isPresent() && query.type().get() != o.type()) {
                return false;
            }
            if (query.createdAfter().isPresent() && o.thisUpdate().isBefore(query.createdAfter().get())) {
                return false;
            }
            return !(query.createdBefore().isPresent() && !o.thisUpdate().isBefore(query.createdBefore().get()));
        }).toList();
    }
}
