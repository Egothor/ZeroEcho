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

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectQuery;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default implementation of {@link StatusObjectService}.
 *
 * <p>
 * This service coordinates generation and lookup of PKI status objects against
 * the configured {@link PkiStore} and delegates format-specific object creation
 * to the active {@link CredentialFramework}. The store acts as the
 * authoritative source of issuer CA state, issuer credentials, revocation
 * journals, and previously generated status objects.
 * </p>
 *
 * <p>
 * The current runtime implementation primarily supports generation workflows
 * that require issuer certificate material and issuer signing key indirection
 * to be provided through status-object attributes. For X.509 CRL generation,
 * this class derives structured CRL entries from authoritative journals and the
 * referenced X.509 credentials.
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
 * <li>For CRL generation, every active journal and referenced target is
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
public final class DefaultStatusObjectService implements StatusObjectService {
    private static final String CRL_GENERATION_FAILED = "CRL_GENERATION_FAILED";

    private final PkiStore store;
    private final CredentialFramework framework;
    private final AuditSink auditSink;
    private final EffectiveCredentialStatusResolver statusResolver;

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
     * @throws NullPointerException if an argument is {@code null}
     */
    public DefaultStatusObjectService(PkiStore store, CredentialFramework framework, AuditSink auditSink,
            EffectiveCredentialStatusResolver statusResolver) {
        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.statusResolver = Objects.requireNonNull(statusResolver, "statusResolver");
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
     * authoritative active journal before signing. Current hold and permanent
     * states are transported with the exact positive X.509 serial, authoritative
     * transition time, and explicit reason. Current {@code CLEAR} states are
     * omitted.
     * </p>
     *
     * <p>
     * Missing targets, malformed credentials, duplicate serials, future
     * transitions, corrupt journals, and store failures abort the complete CRL
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
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        CaRecord ca = store.getCa(command.issuerCaId()).orElseThrow(() -> new PkiException("Issuer CA not found"));
        if (ca.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA not ACTIVE");
        }
        if (ca.caCredentials().isEmpty()) {
            throw new PkiException("Issuer CA has no credentials");
        }
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCred = selectIssuerCredential(ca, command, statusEvaluation);
        List<CrlEntry> crlEntries = command.type() == StatusObjectType.CRL
                ? collectCrlEntries(command.issuerCaId(), statusEvaluation.evaluationTime())
                : List.of();

        SimpleAttributeSet.Builder b = SimpleAttributeSet.builder();
        b.putAll(command.attributes());
        b.put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(issuerCred.encoded().bytes()));
        b.put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(ca.issuerKeyRef().value()));

        StatusObjectGenerateCommand wired = new StatusObjectGenerateCommand(command.issuerCaId(), command.type(),
                command.formatId(), b.build());
        if (command.type() == StatusObjectType.CRL) {
            return generateAndPersistCrl(wired, crlEntries);
        }
        StatusObject obj = framework.statusObjectGenerator().generate(wired, crlEntries);
        store.putStatusObject(obj);
        return obj;
    }

    // Framework, signing, and store failures may carry provider or persisted
    // material. CRL generation deliberately replaces the complete boundary with
    // one fresh cause-free and suppressed-free exception.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private StatusObject generateAndPersistCrl(StatusObjectGenerateCommand command, List<CrlEntry> entries) {
        try {
            StatusObject generated = framework.statusObjectGenerator().generate(command, entries);
            store.putStatusObject(generated);
            return generated;
        } catch (RuntimeException exception) {
            throw crlGenerationFailure();
        }
    }

    // Store and parser failures may contain persisted material; the complete
    // collection boundary deliberately replaces every cause with one stable code.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private List<CrlEntry> collectCrlEntries(PkiId issuerCaId, Instant evaluationTime) {
        try {
            List<RevocationJournal> journals = Objects.requireNonNull(store.listRevocationJournals(),
                    "revocation journals");
            List<CrlEntry> entries = new java.util.ArrayList<>();
            Set<BigInteger> serials = new HashSet<>();
            for (RevocationJournal journal : journals) {
                collectCrlEntry(issuerCaId, evaluationTime, journal, serials).ifPresent(entries::add);
            }
            return List.copyOf(entries);
        } catch (RuntimeException exception) {
            throw crlGenerationFailure();
        }
    }

    private Optional<CrlEntry> collectCrlEntry(PkiId issuerCaId, Instant evaluationTime, RevocationJournal journal,
            Set<BigInteger> serials) {
        Objects.requireNonNull(journal, "journal");
        RevocationTransition latest = Objects.requireNonNull(journal.latest(), "latest transition");
        if (latest.time().isAfter(evaluationTime)) {
            throw crlGenerationFailure();
        }
        if (latest.state() == RevocationState.CLEAR) {
            return Optional.empty();
        }
        Credential credential = store.getCredential(journal.credentialId())
                .orElseThrow(DefaultStatusObjectService::crlGenerationFailure);
        if (!issuerCaId.equals(credential.issuerRef().caId())) {
            return Optional.empty();
        }
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())
                || credential.encoded().encoding() != Encoding.DER) {
            throw crlGenerationFailure();
        }
        BigInteger serial = certificateSerial(credential);
        if (!serials.add(serial)) {
            throw crlGenerationFailure();
        }
        RevocationReason reason = switch (latest.state()) {
            case HELD -> RevocationReason.CERTIFICATE_HOLD;
            case PERMANENTLY_REVOKED ->
                latest.permanentReason().orElseThrow(DefaultStatusObjectService::crlGenerationFailure);
            case CLEAR -> throw crlGenerationFailure();
        };
        return Optional.of(new CrlEntry(serial, latest.time(), reason));
    }

    // Parser failures can contain persisted certificate details; the original
    // cause is intentionally removed at this public service boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static BigInteger certificateSerial(Credential credential) {
        byte[] der = credential.encoded().bytes();
        BigInteger serial;
        try {
            serial = new X509CertificateHolder(der).getSerialNumber();
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

    private static PkiException crlGenerationFailure() {
        return new PkiException("CRL generation failed: code=" + CRL_GENERATION_FAILED);
    }

    private Credential selectIssuerCredential(CaRecord ca, StatusObjectGenerateCommand command,
            EffectiveCredentialStatusResolver.Evaluation evaluation) {
        Credential lastRejected = null;
        EffectiveCredentialStatus lastStatus = null;
        List<Credential> credentials = ca.caCredentials();
        for (int index = credentials.size() - 1; index >= 0; index--) {
            Credential credential = credentials.get(index);
            if (credential == null || !command.formatId().equals(credential.formatId())) {
                continue;
            }
            EffectiveCredentialStatus status;
            try {
                status = evaluation.resolve(credential);
            } catch (PkiException exception) {
                CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), credential,
                        CredentialUse.STATUS_OBJECT_ISSUER,
                        StoreBackedEffectiveCredentialStatusResolver.RESOLUTION_FAILED_CODE, null);
                throw exception;
            }
            if (status == EffectiveCredentialStatus.USABLE) {
                return credential;
            }
            lastRejected = credential;
            lastStatus = status;
        }
        if (lastRejected != null) {
            CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), lastRejected,
                    CredentialUse.STATUS_OBJECT_ISSUER, "ISSUER_CREDENTIAL_UNAVAILABLE", lastStatus);
        }
        throw new PkiException("Issuer credential unavailable: code=ISSUER_CREDENTIAL_UNAVAILABLE");
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
