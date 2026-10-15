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
package zeroecho.pki.server.enrollment;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.server.AdministrativeDecisionActor;
import zeroecho.pki.server.ApprovalService;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.RoleTemplateCatalog;
import zeroecho.pki.server.SecurityPrincipal;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.ServerRealmConfiguration;
import zeroecho.pki.server.acme.AcmeControlStore;
import zeroecho.pki.server.acme.AcmeState;

/**
 * Realm-owned durable enrollment admission, independent approval and exact signing
 * continuation. Thread-safe under the realm control-store monitor. Domain parsing,
 * provider work and signing occur outside that monitor. Startup makes one O(N)
 * snapshot pass and retains counters rather than a transaction mirror; each active
 * invocation retains only its bounded request and record. Unknown mutations fence
 * this instance until reopening and authoritative reconciliation.
 */
// Admission, approval, keygen, dispatch and recovery share one realm's control monitor and transition authority.
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class EnrollmentCoordinator implements AutoCloseable { // NOPMD CyclomaticComplexity, TooManyMethods - One durable realm lifecycle owns admission, approval, dispatch and recovery; methods remain checked.
    private final ServerControlStore control;
    private final ServerRealmConfiguration realm;
    private final PkiSession session;
    private final EnrollmentEndpointRegistry endpoints;
    private final EnrollmentProfileService profiles;
    private final AcmeControlStore acme;
    private final EnrollmentRuntime runtime;
    private final EnrollmentIdentityAliases aliases;
    private final EnrollmentRuntimeConfiguration.Budgets budgets;
    private final Clock clock;
    private final Object requestStorageLock = new Object();
    private int retained;
    private int pending;
    private long retainedBytes;
    private int dispatches;
    private int admissionCalls;
    private final Set<String> inFlight = new HashSet<>();
    private final Set<String> admissions = new HashSet<>();
    private final Set<String> keygenJobs = new HashSet<>();
    private int keygenArtifacts;
    private long keygenCiphertextBytes;
    private boolean fenced;
    private boolean closed;

    /**
     * Validates retained references and rebuilds bounded counters before readiness.
     * The realm must not publish this instance until construction completes.
     * @param control sole realm control authority
     * @param realm immutable realm policy
     * @param session lifecycle-owned domain session
     * @param endpoints durable protocol registry
     * @param profiles durable enrollment policies
     * @param acme durable ACME registry
     * @param runtime installed enrollment budgets and credential custody
     * @param aliases trusted configured administrative mapping exclusions
     * @param clock authoritative clock
     */
    public EnrollmentCoordinator(ServerControlStore control, ServerRealmConfiguration realm, PkiSession session,
            EnrollmentEndpointRegistry endpoints, EnrollmentProfileService profiles, AcmeControlStore acme,
            EnrollmentRuntime runtime, EnrollmentIdentityAliases aliases, Clock clock) {
        this.control = Objects.requireNonNull(control, "control"); this.realm = Objects.requireNonNull(realm, "realm");
        this.session = Objects.requireNonNull(session, "session"); this.endpoints = Objects.requireNonNull(endpoints, "endpoints");
        this.profiles = Objects.requireNonNull(profiles, "profiles"); this.acme = Objects.requireNonNull(acme, "acme");
        this.runtime = Objects.requireNonNull(runtime, "runtime"); this.aliases = Objects.requireNonNull(aliases, "aliases");
        this.clock = Objects.requireNonNull(clock, "clock"); budgets = runtime.configuration().budgets();
        recoverAcmeAccounts();
        recoverCmpTransactions();
        recoverCmpResponseSlots();
        recoverKeygenDescriptors();
        recoverEnrollments();
        if (retained > budgets.maximumTransactions() || pending > budgets.maximumPending()
                || retainedBytes > budgets.maximumRetainedRequestBytes()) {
            throw unavailable();
        }
        finishKeygenRecovery();
    }


    private void recoverAcmeAccounts() {
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ACME_ACCOUNT)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                AcmeState.Account account = acme.decodeAccount(next.orElseThrow());
                retained = Math.addExact(retained, 1);
                retainedBytes = Math.addExact(retainedBytes, acme.accountHistoryCharge(account));
                if (retained > budgets.maximumTransactions() || retainedBytes > budgets.maximumRetainedRequestBytes()) {
                    throw unavailable();
                }
            }
        }
    }

    private void recoverCmpTransactions() {
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.CMP_TRANSACTION)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                CmpTransaction value = CmpTransactionCodec.decode(next.orElseThrow());
                requireCmpReferences(value);
                CmpTransactionCodec.response(control, value);
                value.enrollmentId().ifPresent(id -> {
                    EnrollmentTransaction enrollment = find(id).orElseThrow(EnrollmentCoordinator::unavailable);
                    requireCmpLink(value, enrollment); requireCmpPayload(value, loadRequest(enrollment));
                });
                retained = Math.addExact(retained, 1);
                retainedBytes = Math.addExact(retainedBytes, CmpTransactionCodec.reservation(value));
                if (retained > budgets.maximumTransactions() || retainedBytes > budgets.maximumRetainedRequestBytes()) {
                    throw unavailable();
                }
            }
        }
    }

    private void recoverCmpResponseSlots() {
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.CMP_RESPONSE)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                CmpTransactionCodec.requireOwnedSlot(control, next.orElseThrow());
            }
        }
    }

    private void recoverEnrollments() {
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ENROLLMENT_REQUEST)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                EnrollmentTransaction value = EnrollmentTransactionCodec.decode(next.orElseThrow());
                requireRealm(value); loadRequest(value); validateReferences(value);
                requests().requireProfileProof(requests().get(value.intent().requestId()).orElseThrow(EnrollmentCoordinator::unavailable), value.intent().profile());
                if (!value.id().equals(EnrollmentTransactionCodec.replayId(value.intent().realmId(), value.intent().source(),
                        value.intent().requester(), value.intent().transactionId(), value.intent().operation()))) {
                    throw unavailable();
                }
                value.intent().source().credentialId().ifPresent(runtime::requireRetainedCredential);
                if (value.intent().source().protocol() == EnrollmentTransaction.Protocol.CMP) {
                    requireCmpLink(findCmp(value.intent().source().label(), value.intent().transactionId()).orElseThrow(EnrollmentCoordinator::unavailable), value);
                } else if (value.intent().artifact().isPresent()) {
                    requireKeygenLink(keygen(value.intent().artifact().orElseThrow().artifactId()).orElseThrow(EnrollmentCoordinator::unavailable), value);
                } else {
                    retained = Math.addExact(retained, 1);
                }
                if (value.intent().artifact().isEmpty()) {
                    retainedBytes = Math.addExact(retainedBytes, reservedBytes(value));
                }
                if (unaccepted(value.state())) {
                    pending = Math.addExact(pending, 1);
                }
                if (value.receipt().isPresent()) {
                    value = reconcile(value);
                }
                expireUnclaimed(value);
            }
        }
    }


    /**
     * Creates or atomically replaces an ACME account while retaining all observed
     * requester keys and aliases. Shares the enrollment retention budget and
     * control-store monitor with approval decisions; no authentication is granted.
     * @param prior expected previous account, empty only for creation
     * @param proposed authenticated account update
     * @return durably sealed account with append-only exclusion history
     */
    public AcmeState.Account storeAcmeAccount(Optional<AcmeState.Account> prior, AcmeState.Account proposed) {
        Objects.requireNonNull(prior, "prior"); Objects.requireNonNull(proposed, "proposed");
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            Optional<AcmeState.Account> current = acme.get(AcmeState.Account.class, proposed.accountId());
            if (!current.map(AcmeState.Account::commitment).equals(prior.map(AcmeState.Account::commitment))) {
                throw unavailable();
            }
            if (prior.filter(value -> !value.accountId().equals(proposed.accountId())).isPresent()) {
                throw unavailable();
            }
            List<AcmeState.AccountKeyIdentity> history = new ArrayList<>(current.map(AcmeState.Account::keyHistory).orElse(List.of()));
            current.ifPresent(value -> observeAccountKey(history, value.publicKeySpki()));
            observeAccountKey(history, proposed.publicKeySpki());
            AcmeState.Account next = new AcmeState.Account(proposed.accountId(), proposed.directoryId(), proposed.directoryRevision(),
                    proposed.directoryPolicyCommitment(), proposed.keyThumbprint(), proposed.publicKeySpki(), proposed.status(),
                    proposed.contacts(), proposed.termsAgreed(), proposed.eabPolicyCommitment(), proposed.createdAt(),
                    proposed.updatedAt(), proposed.commitment(), history);
            long previous = current.map(acme::accountHistoryCharge).orElse(0L);
            long growth = Math.subtractExact(acme.accountHistoryCharge(next), previous);
            if (growth < 0 || growth > budgets.maximumRetainedRequestBytes() - retainedBytes
                    || current.isEmpty() && retained >= budgets.maximumTransactions()) {
                throw unavailable();
            }
            retainedBytes = Math.addExact(retainedBytes, growth);
            if (current.isEmpty()) {
                retained++;
            }
            try {
                return current.isEmpty() ? acme.create(next) : (AcmeState.Account) acme.replace(
                        List.of(new AcmeControlStore.Replacement(current.orElseThrow(), next))).getFirst();
            } catch (RuntimeException uncertain) { // NOPMD AvoidCatchingGenericException - Provider and untrusted-input failures are normalized before crossing the public trust boundary.
                fenced = true;
                throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
            }
        }
    }


    /**
     * Finds a wire reservation by stable coordinates. This lookup grants no
     * authentication; callers must verify the retained requester before use.
     * @param label endpoint label
     * @param transactionSha256 exact transaction identifier commitment
     * @return immutable retained manifest, if present
     */
    public Optional<CmpTransaction> findCmp(String label, String transactionSha256) {
        EnrollmentTransaction.id(label); EnrollmentTransaction.digest(transactionSha256);
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            return control.protocolRecord(ServerControlStore.CMP_TRANSACTION,
                    CmpTransactionCodec.id(realm.realmId(), label, transactionSha256)).map(CmpTransactionCodec::decode);
        }
    }

    /**
     * Reserves one logical transaction and its full response capacity before any
     * domain side effect. Repeating a reservation requires the identical frozen
     * coordinates. Unknown persistence outcomes fence the whole coordinator.
     * @param supplied authenticated, bounded original request and credential selection
     * @return durably reserved manifest including all currently known requester aliases
     */
    public CmpTransaction reserveCmp(CmpTransaction.Frozen supplied) {
        Objects.requireNonNull(supplied, "frozen");
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            EnrollmentTransaction.Requester requester = withCurrentAliases(supplied.requester());
            CmpTransaction.Frozen frozen = new CmpTransaction.Frozen(supplied.realmId(), supplied.source(), requester,
                    supplied.authorityId(), supplied.profile(), supplied.issuerId(), supplied.pathId(), supplied.pathCommitment(),
                    supplied.transactionSha256(), supplied.originalWireSha256(), supplied.originalType(), supplied.requestId(), supplied.requestSha256(),
                    supplied.implicitConfirmation(), supplied.createdAt(), supplied.expiresAt(), supplied.maximumResponseBytes());
            Optional<CmpTransaction> existing = findCmp(frozen.source().label(), frozen.transactionSha256());
            if (existing.isPresent()) {
                if (!existing.orElseThrow().frozen().equals(frozen)) {
                    throw unavailable();
                }
                return existing.orElseThrow();
            }
            CmpTransaction value = new CmpTransaction(CmpTransactionCodec.id(realm.realmId(), frozen.source().label(),
                    frozen.transactionSha256()), 1, frozen, Optional.empty(), Optional.empty());
            requireCmpReferences(value);
            requireCmpReservation(frozen);
            long reservation = CmpTransactionCodec.reservation(value);
            if (retained >= budgets.maximumTransactions() || reservation > budgets.maximumRetainedRequestBytes() - retainedBytes) {
                throw unavailable();
            }
            retained++; retainedBytes += reservation;
            mutateCmp(CmpTransactionCodec.create(value));
            return value;
        }
    }

    /**
     * Revalidates a reserved non-enrollment transaction before a fresh protocol
     * effect. The exact manifest, endpoint policy, authority and frozen credential
     * must remain usable; rotating the active credential alone does not invalidate
     * its retained predecessor. This read-only check creates no durable claim and
     * does not order a later domain effect atomically against policy changes.
     * Already committed effects and exact response replay do not require it.
     * @param expected exact previously observed non-enrollment manifest
     */
    public void requireCmpCurrentSource(CmpTransaction expected) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen(); CmpTransaction current = requireCmpCurrent(expected);
            CmpTransaction.Frozen frozen = current.frozen();
            if (frozen.enrollment() || !clock.instant().isBefore(frozen.expiresAt())
                    || !realm.authorityExposure().allows(frozen.authorityId())) {
                throw unavailable();
            }
            Selection selected = selection(EnrollmentTransaction.Protocol.CMP, frozen.source().label());
            EnrollmentTransaction.Source source = selected.source();
            source = new EnrollmentTransaction.Source(source.protocol(), source.label(), source.recordId(), source.revision(),
                    source.commitment(), source.enrollmentProfileId(), source.enrollmentCommitment(), frozen.source().credentialId());
            if (!source.equals(frozen.source()) || !selected.authorityId().equals(frozen.authorityId())
                    || !selected.profileId().equals(frozen.profile().profileId())) {
                throw unavailable();
            }
            runtime.requireAdmissionCredential(frozen.source().credentialId().orElseThrow(), frozen.authorityId().value(),
                    frozen.issuerId().value(), frozen.pathId().value());
            CaRecord authority = session.repository().authority(frozen.authorityId()).orElseThrow(EnrollmentCoordinator::unavailable);
            if (!authority.currentIssuanceIssuerId().equals(frozen.issuerId()) || !authority.issuanceChainPathId().equals(frozen.pathId())) {
                throw unavailable();
            }
        }
    }

    /**
     * Returns a complete committed response from a consistent manifest/slot view.
     * Authentication and replay-nonce validation remain the adapter's obligation.
     * @param expected exact previously observed manifest
     * @return defensive response bytes, empty only before the first response
     */
    public byte[] cmpResponse(CmpTransaction expected) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen(); CmpTransaction current = requireCmpCurrent(expected);
            return CmpTransactionCodec.response(control, current);
        }
    }

    /**
     * Publishes protected bytes, nonce metadata and all fixed slots atomically.
     * A stale computation fails without emitting its response; callers may return
     * bytes only after this method acknowledges their persistence.
     * @param expected full expected manifest commitment
     * @param response bounded complete protected response
     * @param metadata exact response and triggering request commitments
     * @return acknowledged next manifest
     */
    public CmpTransaction storeCmpResponse(CmpTransaction expected, byte[] response, CmpTransaction.Response metadata) {
        Objects.requireNonNull(response, "response"); Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(expected, "expected");
        if (response.length > expected.frozen().maximumResponseBytes()) {
            throw unavailable();
        }
        byte[] owned = response.clone();
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen(); CmpTransaction current = requireCmpCurrent(expected);
            if (current.response().filter(CmpTransaction.Response::terminal).isPresent()) {
                throw unavailable();
            }
            CmpTransaction next = new CmpTransaction(current.id(), Math.addExact(current.revision(), 1), current.frozen(),
                    current.enrollmentId(), Optional.of(metadata));
            mutateCmp(CmpTransactionCodec.response(control, current, next, owned));
            return next;
        }
    }

    private CmpTransaction requireCmpCurrent(CmpTransaction expected) {
        Objects.requireNonNull(expected, "expected");
        CmpTransaction current = control.protocolRecord(ServerControlStore.CMP_TRANSACTION, expected.id())
                .map(CmpTransactionCodec::decode).orElseThrow(EnrollmentCoordinator::unavailable);
        if (!current.commitment().equals(expected.commitment()) || !current.frozen().realmId().equals(realm.realmId())) {
            throw unavailable();
        }
        return current;
    }

    private void mutateCmp(List<ServerControlStore.ProtocolMutation> mutations) {
        try { control.mutateProtocol(mutations); }
        catch (RuntimeException uncertain) { fenced = true; throw unavailable(); } // NOPMD AvoidCatchingGenericException, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private void requireCmpReferences(CmpTransaction value) {
        CmpTransaction.Frozen frozen = value.frozen();
        if (!frozen.realmId().equals(realm.realmId())) {
            throw unavailable();
        }
        runtime.requireRetainedCredential(frozen.source().credentialId().orElseThrow(), frozen.authorityId().value(),
                frozen.issuerId().value(), frozen.pathId().value());
        if (!session.profiles().getImportedVersion(frozen.profile().profileId(), frozen.profile().profileVersion())
                .orElseThrow(EnrollmentCoordinator::unavailable).reference().equals(frozen.profile())) {
            throw unavailable();
        }
        zeroecho.pki.api.ca.IssuerGeneration issuer = session.repository().issuer(frozen.issuerId()).orElseThrow(EnrollmentCoordinator::unavailable);
        zeroecho.pki.api.ca.IssuerChainPath path = session.repository().chainPath(frozen.pathId()).orElseThrow(EnrollmentCoordinator::unavailable);
        if (session.repository().authority(frozen.authorityId()).isEmpty() || !issuer.authorityId().equals(frozen.authorityId())
                || !path.authorityId().equals(frozen.authorityId()) || !path.issuerId().equals(frozen.issuerId())
                || !path.pathCommitment().equals(frozen.pathCommitment())) {
            throw unavailable();
        }
    }

    private void requireCmpReservation(CmpTransaction.Frozen frozen) {
        Selection selected = selection(EnrollmentTransaction.Protocol.CMP, frozen.source().label());
        if (!selected.source().equals(frozen.source()) || !selected.authorityId().equals(frozen.authorityId())
                || !session.profiles().requireActiveProfile(selected.profileId()).reference().equals(frozen.profile())
                || !withCurrentAliases(frozen.requester()).equals(frozen.requester())
                || !clock.instant().isBefore(frozen.expiresAt())
                || frozen.createdAt().isAfter(clock.instant())
                || frozen.expiresAt().isAfter(frozen.createdAt().plus(budgets.pendingLifetime()))) {
            throw unavailable();
        }
        runtime.requireAdmissionCredential(frozen.source().credentialId().orElseThrow(), frozen.authorityId().value(),
                frozen.issuerId().value(), frozen.pathId().value());
        CaRecord authority = session.repository().authority(frozen.authorityId()).orElseThrow(EnrollmentCoordinator::unavailable);
        if (!authority.currentIssuanceIssuerId().equals(frozen.issuerId()) || !authority.issuanceChainPathId().equals(frozen.pathId())) {
            throw unavailable();
        }
    }

    private void requireCmpLink(CmpTransaction manifest, EnrollmentTransaction enrollment) {
        CmpTransaction.Frozen frozen = manifest.frozen();
        EnrollmentTransaction.Intent intent = enrollment.intent();
        if (!manifest.enrollmentId().equals(Optional.of(enrollment.id())) || !frozen.enrollment()
                || !intent.realmId().equals(frozen.realmId()) || !intent.source().equals(frozen.source())
                || !intent.requester().equals(frozen.requester()) || !intent.transactionId().equals(frozen.transactionSha256())
                || !intent.requestSha256().equals(frozen.requestSha256().orElseThrow())) {
            throw unavailable();
        }
        requireCmpIssuanceBinding(frozen, intent);
    }

    private static void requireCmpIssuanceBinding(CmpTransaction.Frozen frozen, EnrollmentTransaction.Intent intent) {
        if (intent.requestKind() != X509EnrollmentPayload.Kind.CRMF
                || !intent.authorityId().equals(frozen.authorityId()) || !intent.profile().equals(frozen.profile()) || !intent.issuerId().equals(frozen.issuerId())
                || !intent.pathId().equals(frozen.pathId()) || !intent.pathCommitment().equals(frozen.pathCommitment())
                || intent.expiresAt().isAfter(frozen.expiresAt())
                || intent.operation() != (frozen.originalType() == 7 ? EnrollmentTransaction.Operation.REPLACE : EnrollmentTransaction.Operation.ISSUE)) {
            throw unavailable();
        }
    }

    private static void requireCmpPayload(CmpTransaction manifest, X509EnrollmentPayload payload) {
        if (payload.kind() != X509EnrollmentPayload.Kind.CRMF) {
            throw unavailable();
        }
        zeroecho.pkix.cmp.CrmfRequest original = zeroecho.pkix.cmp.CrmfRequest.parse(payload.der());
        if (!original.requestId().equals(manifest.frozen().requestId())
                || original.oldCertificate().isPresent() != (manifest.frozen().originalType() == 7)) {
            throw unavailable();
        }
    }

    private void observeAccountKey(List<AcmeState.AccountKeyIdentity> history, byte[] spki) {
        zeroecho.pkix.PublicKeyIdentity key = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(spki);
        java.util.SortedSet<String> exclusions = new java.util.TreeSet<>(aliases.knownKeyAliases(key).principalIds());
        int existing = -1;
        for (int index = 0; index < history.size(); index++) {
            if (history.get(index).canonicalSha256().equals(key.canonicalSha256())) {
                existing = index; exclusions.addAll(history.get(index).aliases()); break;
            }
        }
        AcmeState.AccountKeyIdentity observed = new AcmeState.AccountKeyIdentity(key.canonicalSha256(),
                key.equivalentSubjectPublicKeyInfoSha256(), exclusions);
        if (existing < 0) {
            history.add(observed);
        } else {
            history.set(existing, observed);
        }
    }

    private void requireIndependentAccountHistory(EnrollmentTransaction.Requester requester,
            AdministrativeDecisionActor actor, CertificateIdentityEvidence evidence) {
        if (requester.type() != IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT) {
            return;
        }
        AcmeState.Account account = acme.get(AcmeState.Account.class, requester.actorId()).orElseThrow(EnrollmentCoordinator::unavailable);
        Set<String> hashes = new HashSet<>();
        for (AcmeState.AccountKeyIdentity key : account.keyHistory()) {
            if (key.canonicalSha256().equals(evidence.canonicalKeySha256()) || key.aliases().contains(actor.principalId())) {
                throw unavailable();
            }
            hashes.addAll(key.legacySpkiSha256());
        }
        if (aliases.knownKeyHashes(hashes).principalIds().contains(actor.principalId())) {
            throw unavailable();
        }
    }

    /**
     * Verified adapter input; this API does not authenticate wire messages.
     * @param protocol protocol family
     * @param endpointId configured label, or exact ACME directory ID
     * @param requester authenticated protocol requester
     * @param transactionId SHA-256 of the protocol transaction coordinate
     * @param operation operation replay domain
     * @param payload exact proved request
     * @param validity optional requested validity
     * @param predecessorId authoritative renewal predecessor
     * @param protocolDeadline additional immutable protocol expiry, mandatory for ACME orders
     */
    public record Admission(EnrollmentTransaction.Protocol protocol, String endpointId, EnrollmentTransaction.Requester requester,
            String transactionId, EnrollmentTransaction.Operation operation, X509EnrollmentPayload payload,
            Optional<Validity> validity, Optional<PkiId> predecessorId, Optional<Instant> protocolDeadline) {
        /**
         * Creates input for a protocol governed solely by configured admission lifetime.
         * @param protocol non-ACME protocol family
         * @param endpointId stable endpoint label
         * @param requester verified actor evidence
         * @param transactionId protocol transaction commitment
         * @param operation requested operation
         * @param payload exact request payload
         * @param validity optional certificate validity
         * @param predecessorId optional renewal or replacement predecessor
         */
        public Admission(EnrollmentTransaction.Protocol protocol, String endpointId, EnrollmentTransaction.Requester requester,
                String transactionId, EnrollmentTransaction.Operation operation, X509EnrollmentPayload payload,
                Optional<Validity> validity, Optional<PkiId> predecessorId) {
            this(protocol, endpointId, requester, transactionId, operation, payload, validity, predecessorId, Optional.empty());
        }
        /** Validates bounded, non-null adapter input without retaining mutable data. */
        public Admission {
            Objects.requireNonNull(protocol, "protocol"); EnrollmentTransaction.id(endpointId); Objects.requireNonNull(requester, "requester");
            EnrollmentTransaction.digest(transactionId); Objects.requireNonNull(operation, "operation"); Objects.requireNonNull(payload, "payload");
            Objects.requireNonNull(validity, "validity"); Objects.requireNonNull(predecessorId, "predecessorId");
            Objects.requireNonNull(protocolDeadline, "protocolDeadline");
            if (protocol == EnrollmentTransaction.Protocol.ACME && protocolDeadline.isEmpty()) {
                throw EnrollmentTransaction.invalid();
            }
            if ((operation == EnrollmentTransaction.Operation.RENEW || operation == EnrollmentTransaction.Operation.REPLACE)
                    != predecessorId.isPresent()) {
                throw EnrollmentTransaction.invalid();
            }
            if (operation == EnrollmentTransaction.Operation.REPLACE && (protocol != EnrollmentTransaction.Protocol.CMP
                    || requester.type() != IssuanceExecutionEvidence.ActorType.CMP_SIGNER
                    || payload.kind() != X509EnrollmentPayload.Kind.CRMF || validity.isPresent())) {
                throw EnrollmentTransaction.invalid();
            }
        }
        /** @return redacted admission description */
        @Override public String toString() { return "EnrollmentCoordinator.Admission[redacted]"; }
    }

    /**
     * Stores the exact verified request before publishing its durable approval
     * reference. Identical retries reuse the retained result; transaction reuse
     * with different request, operation or requester evidence fails closed.
     * @param admission authenticated protocol input
     * @return durable transaction, including retained terminal results
     */
    public EnrollmentTransaction admit(Admission admission) {
        return admitBound(admission, Optional.empty());
    }

    /**
     * Admits verified protocol input against the exact endpoint context used for
     * protocol authentication, preventing a policy replacement between verification
     * and durable admission. Retried requests use their frozen source commitment.
     * @param admission authenticated protocol input
     * @param expectedEndpointCommitment exact previously observed source commitment
     * @return durable transaction or retained identical result
     */
    public EnrollmentTransaction admit(Admission admission, String expectedEndpointCommitment) {
        EnrollmentTransaction.digest(expectedEndpointCommitment);
        return admitBound(admission, Optional.of(expectedEndpointCommitment));
    }

    private EnrollmentTransaction admitBound(Admission admission, Optional<String> expectedEndpointCommitment) {
        if (admission.protocol() == EnrollmentTransaction.Protocol.CMP) {
            throw unavailable();
        }
        return admitBound(admission, expectedEndpointCommitment, Optional.empty());
    }

    /**
     * Attaches an exact authenticated original CRMF to its reserved CMP manifest.
     * Domain storage precedes one atomic manifest/enrollment publication. No second
     * logical transaction is charged; request and future decision bytes are reserved
     * before storing the domain request. Retry bytes never replace published data.
     * @param admission authenticated original issuance or replacement request
     * @param expected exact unlinked or identically linked wire manifest
     * @return durable linked enrollment transaction
     */
    public EnrollmentTransaction admitCmp(Admission admission, CmpTransaction expected) {
        Objects.requireNonNull(admission, "admission"); Objects.requireNonNull(expected, "expected");
        if (admission.protocol() != EnrollmentTransaction.Protocol.CMP || !expected.frozen().enrollment()
                || !admission.endpointId().equals(expected.frozen().source().label())
                || !admission.requester().equals(expected.frozen().requester())
                || !admission.transactionId().equals(expected.frozen().transactionSha256())
                || admission.payload().kind() != X509EnrollmentPayload.Kind.CRMF
                || !EnrollmentTransactionCodec.sha256(admission.payload().der()).equals(expected.frozen().requestSha256().orElseThrow())) {
            throw unavailable();
        }
        requireCmpPayload(expected, admission.payload());
        synchronized (control) { requireOpen(); requireCmpCurrent(expected); } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
        return admitBound(admission, Optional.of(expected.frozen().source().commitment()), Optional.of(expected));
    }

    private EnrollmentTransaction admitBound(Admission admission, Optional<String> expectedEndpointCommitment, Optional<CmpTransaction> cmp) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            if (admissionCalls >= budgets.maximumConcurrentDispatches()) {
                throw unavailable();
            }
            admissionCalls++;
        }
        try { return admitInternal(admission, expectedEndpointCommitment, cmp); }
        finally { synchronized (control) { admissionCalls--; } } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
    }

    /**
     * Finds the stable server-keygen replay descriptor and checks the exact original
     * template and authenticated recipient. Lookup reconciles expired delivery
     * and releases eligible ciphertext; it does not generate keys or dispatch.
     * @param admission original EST server-keygen template and authenticated evidence
     * @return retained descriptor, including terminal tombstones
     */
    public Optional<EnrollmentKeygenArtifact> findKeygen(Admission admission) {
        requireKeygenAdmission(admission);
        String id = EnrollmentTransactionCodec.replayId(realm.realmId(), admission.protocol(), admission.endpointId(),
                admission.requester(), admission.transactionId(), admission.operation()).substring("enrollment:".length());
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            Optional<EnrollmentKeygenArtifact> retained = keygen(id);
            retained.ifPresent(value -> requireKeygenReplay(value, admission));
            if (retained.isEmpty()) {
                return Optional.empty();
            }
        }
        cleanupKeygen(id);
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            return keygen(id);
        }
    }

    /**
     * Reserves all descriptor, CSR, approval, ciphertext and generation capacity
     * before returning permission to generate one key. The original template is
     * stored before the durable reservation is published. A borrower must close
     * its generation handle after attachment or failure; interrupted reservations
     * become terminal failures on recovery and never regenerate.
     * @param admission exact verified EST server-keygen template
     * @param recipient actual authenticated mTLS recipient certificate
     * @return exclusive bounded generation handle
     */
    public KeygenGeneration beginKeygen(Admission admission, java.security.cert.X509Certificate recipient) {
        requireKeygenAdmission(admission);
        zeroecho.pkix.EstKeygen.requireRecipient(admission.payload().der(), recipient);
        reclaimExpiredKeygen();
        EnrollmentRuntimeConfiguration.KeygenArtifacts config = runtime.configuration().keygenArtifacts().orElseThrow(EnrollmentCoordinator::unavailable);
        try {
            if (!EnrollmentTransactionCodec.sha256(recipient.getEncoded()).equals(
                    admission.requester().certificate().orElseThrow().certificateSha256())) {
                throw unavailable();
            }
            recipient.checkValidity(java.util.Date.from(clock.instant()));
        } catch (java.security.cert.CertificateException failure) { throw unavailable(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        Instant deadline = earlier(clock.instant().plus(config.deliveryRetention()), recipient.getNotAfter().toInstant());
        Admission bounded = new Admission(admission.protocol(), admission.endpointId(), admission.requester(), admission.transactionId(),
                admission.operation(), admission.payload(), admission.validity(), admission.predecessorId(), Optional.of(deadline));
        PlannedAdmission planned = planAdmission(bounded, Optional.empty(), Optional.empty());
        EnrollmentTransaction.Intent template = planned.intent();
        deadline = earlier(deadline, runtime.credentialNotAfter(template.source().credentialId().orElseThrow()));
        String id = EnrollmentTransactionCodec.replayId(realm.realmId(), template.source(), template.requester(),
                template.transactionId(), template.operation()).substring("enrollment:".length());
        EnrollmentKeygenArtifact value;
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            value = reserveKeygen(admission, planned, template, config, deadline, id);
        }
        try {
            storeKeygenRequest(planned.parsed(), admission.payload());
            synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                requireOpen(); requireCurrent(template);
                keygenMutation(null, value);
            }
            return new KeygenGeneration(value);
        } catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Provider and untrusted-input failures are normalized before crossing the public trust boundary.
            synchronized (control) { fenced = true; keygenJobs.remove(id); } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    // Called only while holding the control-store monitor; persistence follows outside this reservation.
    private EnrollmentKeygenArtifact reserveKeygen(Admission admission, PlannedAdmission planned,
            EnrollmentTransaction.Intent template, EnrollmentRuntimeConfiguration.KeygenArtifacts config,
            Instant deadline, String id) {
        requireOpen(); requireCurrent(template);
        if (keygen(id).isPresent() || keygenJobs.contains(id)) {
            throw unavailable();
        }
        zeroecho.pki.server.est.KeygenPolicy policy = requireKeygenPolicy(admission.endpointId());
        EnrollmentKeygenArtifact value = new EnrollmentKeygenArtifact(id, 1, template, policy.permittedAlgorithms().getFirst(), policy.maximumKeySizeBits(),
                config.maximumArtifactBytes(), budgets.maximumRequestBytes(), deadline, EnrollmentKeygenArtifact.State.GENERATING, Optional.empty(), false);
        // Validate that the frozen approval policy can fit before any key generation.
        EnrollmentTransaction.ArtifactBinding bound = new EnrollmentTransaction.ArtifactBinding(id, value.generationCommitment(), "0".repeat(64), 1);
        EnrollmentTransaction.Intent boundedIntent = generatedIntent(template, planned.parsed(), admission.payload(), bound);
        reservedBytes(new EnrollmentTransaction(value.enrollmentId(), 1, boundedIntent, boundedIntent.approvalPolicy().isPresent()
                ? EnrollmentTransaction.State.PENDING : EnrollmentTransaction.State.APPROVED, List.of(), Optional.empty(), Optional.empty()));
        long charge = keygenCharge(value);
        if (pending >= budgets.maximumPending()) {
            expireUnclaimedRequests();
        }
        if (retained >= budgets.maximumTransactions() || pending >= budgets.maximumPending()
                || charge > budgets.maximumRetainedRequestBytes() - retainedBytes || keygenArtifacts >= config.maximumArtifacts()
                || config.maximumArtifactBytes() > config.maximumRetainedBytes() - keygenCiphertextBytes
                || keygenJobs.size() >= config.maximumConcurrentGenerations()) {
            throw unavailable();
        }
        retained++; pending++; retainedBytes += charge; keygenArtifacts++; keygenCiphertextBytes += config.maximumArtifactBytes();
        keygenJobs.add(id);
        return value;
    }

    private zeroecho.pki.server.est.KeygenPolicy requireKeygenPolicy(String endpointId) {
        zeroecho.pki.server.est.EstEndpoint endpoint = (zeroecho.pki.server.est.EstEndpoint) endpoints
                .find(EnrollmentEndpointRegistry.Protocol.EST, endpointId).orElseThrow(EnrollmentCoordinator::unavailable);
        zeroecho.pki.server.est.KeygenPolicy policy = endpoint.keygen();
        if (!policy.enabled() || policy.storeGeneratedKeys()) {
            throw unavailable();
        }
        if ("RSA".equals(policy.permittedAlgorithms().getFirst()) && policy.maximumKeySizeBits() < 2048) {
            throw unavailable();
        }
        return policy;
    }

    /**
     * Exclusive generation claim. No raw private key is accepted by this handle;
     * the adapter encrypts it for the frozen recipient before attachment.
     */
    public final class KeygenGeneration implements AutoCloseable {
        private final EnrollmentKeygenArtifact reserved;
        private boolean attached;
        private boolean released;
        private KeygenGeneration(EnrollmentKeygenArtifact reserved) { this.reserved = reserved; }
        /** {@return immutable original template, policy and resource reservation} */
        public EnrollmentKeygenArtifact descriptor() { return reserved; }

        /**
         * Stores the proved generated CSR and publishes encrypted bytes before one
         * atomic descriptor/enrollment attachment. Any uncertain publication fences
         * this coordinator. The generated request must preserve every template
         * subject and SAN and satisfy the frozen key and proof policy.
         * @param generated exact proved generated PKCS#10 request
         * @param ciphertext already client-encrypted PKCS#8 CMS delivery bytes
         * @return durable approval or approved enrollment
         */
        // Serializes generated ciphertext attachment with release of this key-generation admission.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        public synchronized EnrollmentTransaction attach(X509EnrollmentPayload generated, byte[] ciphertext) {
            if (released || attached) {
                throw unavailable();
            }
            ParsedCertificationRequest parsed = requests().parseX509(generated);
            requireGeneratedIdentity(reserved, parsed, generated);
            String digest = EnrollmentKeygenSpool.hash(ciphertext);
            EnrollmentTransaction.ArtifactBinding binding = new EnrollmentTransaction.ArtifactBinding(reserved.id(),
                    reserved.generationCommitment(), digest, ciphertext.length);
            EnrollmentTransaction.Intent intent = generatedIntent(reserved.template(), parsed, generated, binding);
            EnrollmentTransaction value = new EnrollmentTransaction(reserved.enrollmentId(), 1, intent,
                    intent.approvalPolicy().isPresent() ? EnrollmentTransaction.State.PENDING : EnrollmentTransaction.State.APPROVED,
                    List.of(), Optional.empty(), Optional.empty());
            EnrollmentKeygenArtifact linked = keygenState(reserved, EnrollmentKeygenArtifact.State.ATTACHED, Optional.of(binding), false);
            if (ciphertext.length > reserved.maximumCiphertextBytes()
                    || reservedBytes(value) > EnrollmentTransactionCodec.MAXIMUM_BYTES + (long) reserved.maximumGeneratedRequestBytes()) {
                throw unavailable();
            }
            try {
                synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                    requireOpen(); requireKeygenCurrent(reserved); requireCurrent(reserved.template());
                    if (!clock.instant().isBefore(reserved.template().expiresAt())) {
                        throw unavailable();
                    }
                }
                runtime.keygenSpool().publish(reserved.id(), ciphertext, digest);
                storeKeygenRequest(parsed, generated);
                synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                    requireOpen(); requireKeygenCurrent(reserved); requireCurrent(reserved.template());
                    if (!clock.instant().isBefore(reserved.template().expiresAt())) {
                        throw unavailable();
                    }
                    mutateCmp(List.of(new ServerControlStore.ProtocolMutation(EnrollmentKeygenCodec.record(linked), Optional.of(reserved.commitment())),
                            new ServerControlStore.ProtocolMutation(EnrollmentTransactionCodec.record(value), Optional.empty())));
                    attached = true;
                }
                return value;
            } catch (java.io.IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
                synchronized (control) { fenced = true; } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
            }
        }

        /**
         * Releases generation capacity. A confirmed unattached generation is
         * terminalized before deletion; uncertain state is left for startup recovery.
         */
        // Serializes release of this key-generation admission with concurrent attachment.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void close() {
            if (released) {
                return;
            }
            synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                try {
                    if (!attached && !fenced && !closed) {
                        EnrollmentKeygenArtifact current = requireKeygenCurrent(reserved);
                        keygenMutation(current, keygenState(current, EnrollmentKeygenArtifact.State.FAILED, Optional.empty(), false));
                        pending--;
                    }
                } finally {
                    keygenJobs.remove(reserved.id()); released = true;
                }
            }
            if (!attached && !fenced && !closed) {
                cleanupKeygen(reserved.id());
            }
        }
    }

    private void requireKeygenAdmission(Admission admission) {
        Objects.requireNonNull(admission, "admission");
        if (admission.protocol() != EnrollmentTransaction.Protocol.EST || admission.operation() != EnrollmentTransaction.Operation.SERVER_KEYGEN
                || admission.payload().kind() != X509EnrollmentPayload.Kind.PKCS10 || admission.payload().der().length > budgets.maximumRequestBytes()
                || admission.validity().isPresent() || admission.predecessorId().isPresent()) {
            throw unavailable();
        }
    }
    private Optional<EnrollmentKeygenArtifact> keygen(String id) {
        return control.protocolRecord(ServerControlStore.ENROLLMENT_KEYGEN, id).map(EnrollmentKeygenCodec::decode);
    }
    private EnrollmentKeygenArtifact requireKeygenCurrent(EnrollmentKeygenArtifact expected) {
        EnrollmentKeygenArtifact current = keygen(expected.id()).orElseThrow(EnrollmentCoordinator::unavailable);
        if (!current.commitment().equals(expected.commitment())) {
            throw unavailable();
        }
        return current;
    }
    private void keygenMutation(EnrollmentKeygenArtifact prior, EnrollmentKeygenArtifact next) {
        mutateCmp(List.of(new ServerControlStore.ProtocolMutation(EnrollmentKeygenCodec.record(next),
                Optional.ofNullable(prior).map(EnrollmentKeygenArtifact::commitment))));
    }
    private static EnrollmentKeygenArtifact keygenState(EnrollmentKeygenArtifact value, EnrollmentKeygenArtifact.State state,
            Optional<EnrollmentTransaction.ArtifactBinding> artifact, boolean released) {
        return new EnrollmentKeygenArtifact(value.id(), Math.addExact(value.revision(), 1), value.template(), value.algorithm(),
                value.maximumKeySizeBits(), value.maximumCiphertextBytes(), value.maximumGeneratedRequestBytes(), value.deliveryDeadline(),
                state, artifact, released);
    }
    private long keygenCharge(EnrollmentKeygenArtifact value) {
        // Reserve the complete bounded future enrollment record plus exact CSR budget before generation.
        EnrollmentKeygenArtifact reservation = new EnrollmentKeygenArtifact(value.id(), 1, value.template(), value.algorithm(), value.maximumKeySizeBits(),
                value.maximumCiphertextBytes(), value.maximumGeneratedRequestBytes(), value.deliveryDeadline(),
                EnrollmentKeygenArtifact.State.GENERATING, Optional.empty(), false);
        return Math.addExact(Math.addExact(EnrollmentKeygenCodec.encode(reservation).length + 1024L, value.template().requestBytes()),
                EnrollmentTransactionCodec.MAXIMUM_BYTES + (long) value.maximumGeneratedRequestBytes());
    }
    private void requireKeygenReplay(EnrollmentKeygenArtifact value, Admission admission) {
        EnrollmentTransaction.Intent intent = value.template();
        if (!intent.realmId().equals(realm.realmId()) || !intent.requestSha256().equals(EnrollmentTransactionCodec.sha256(admission.payload().der()))
                || !intent.requester().certificate().equals(admission.requester().certificate())
                || !intent.requester().canonicalKeySha256().equals(admission.requester().canonicalKeySha256())) {
            throw unavailable();
        }
        loadRequest(intent);
    }
    private void storeKeygenRequest(ParsedCertificationRequest parsed, X509EnrollmentPayload payload) {
        synchronized (requestStorageLock) { // NOPMD AvoidSynchronizedStatement - Serializes owned request-file publication with cleanup.
            Optional<ParsedCertificationRequest> prior = requests().get(parsed.requestId());
            if (prior.isPresent()) {
                X509EnrollmentPayload exact = requests().encodedX509Request(prior.orElseThrow());
                if (exact.kind() != payload.kind() || !java.util.Arrays.equals(exact.der(), payload.der())) {
                    throw unavailable();
                }
            } else if (!requests().store(parsed, RequestStorePolicy.STORE_ALWAYS).equals(parsed.requestId())) {
                throw unavailable();
            }
        }
    }
    private void requireGeneratedIdentity(EnrollmentKeygenArtifact value, ParsedCertificationRequest generated, X509EnrollmentPayload payload) {
        if (payload.kind() != X509EnrollmentPayload.Kind.PKCS10 || payload.der().length > value.maximumGeneratedRequestBytes()) {
            throw unavailable();
        }
        ParsedCertificationRequest original = requests().parseX509(loadRequest(value.template()));
        if (!original.subjectRef().equals(generated.subjectRef()) || !original.subjectRdns().equals(generated.subjectRdns())
                || original.subjectAlternativeNamePresent() != generated.subjectAlternativeNamePresent()
                || !original.subjectAlternativeNames().equals(generated.subjectAlternativeNames())) {
            throw unavailable();
        }
        java.security.PublicKey key = zeroecho.pkix.Pkix.publicKeyFromSubjectPublicKeyInfo(generated.publicKeyInfo().bytes());
        int bits;
        if (key instanceof java.security.interfaces.RSAPublicKey rsa && "RSA".equals(value.algorithm())) {
            bits = rsa.getModulus().bitLength();
        }
        else if (key instanceof java.security.interfaces.ECPublicKey ec && "EC".equals(value.algorithm())) {
            bits = ec.getParams().getCurve().getField().getFieldSize();
        }
        else {
            throw unavailable();
        }
        if (bits > value.maximumKeySizeBits()) {
            throw unavailable();
        }
        requests().requireProfileProof(generated, value.template().profile());
    }
    private static EnrollmentTransaction.Intent generatedIntent(EnrollmentTransaction.Intent t, ParsedCertificationRequest parsed,
            X509EnrollmentPayload payload, EnrollmentTransaction.ArtifactBinding artifact) {
        return generatedIntent(t, parsed.requestId(), payload.kind(), EnrollmentTransactionCodec.sha256(payload.der()), payload.der().length, artifact);
    }
    private static EnrollmentTransaction.Intent generatedIntent(EnrollmentTransaction.Intent t, PkiId request,
            X509EnrollmentPayload.Kind kind, String digest, int size, EnrollmentTransaction.ArtifactBinding artifact) {
        return new EnrollmentTransaction.Intent(t.realmId(), t.source(), t.requester(), t.transactionId(), t.operation(), request,
                kind, digest, size, t.authorityId(), t.profile(), t.issuerId(),
                t.pathId(), t.pathCommitment(), t.validity(), t.predecessorId(), t.predecessorSha256(), t.approvalCategory(), t.approvalPolicy(),
                Optional.of(artifact), t.createdAt(), t.expiresAt());
    }
    private void requireKeygenLink(EnrollmentKeygenArtifact artifact, EnrollmentTransaction enrollment) {
        if (artifact.artifact().isEmpty() || !artifact.enrollmentId().equals(enrollment.id())
                || !artifact.artifact().equals(enrollment.intent().artifact())) {
            throw unavailable();
        }
        if (artifact.state() == EnrollmentKeygenArtifact.State.EXPIRED
                && enrollment.state() != EnrollmentTransaction.State.ISSUED && enrollment.state() != EnrollmentTransaction.State.REJECTED
                && enrollment.state() != EnrollmentTransaction.State.EXPIRED && enrollment.state() != EnrollmentTransaction.State.FAILED) {
            throw unavailable();
        }
        EnrollmentTransaction.Intent intent = enrollment.intent();
        if (!generatedIntent(artifact.template(), intent.requestId(), intent.requestKind(), intent.requestSha256(), intent.requestBytes(),
                artifact.artifact().orElseThrow()).equals(intent)) {
            throw unavailable();
        }
    }

    /**
     * Opens a bounded ciphertext lease only for the exact authenticated template
     * after its correlated certificate is durably issued. Transport success does
     * not consume the artifact; retries remain available until durable expiry.
     * @param admission original template and authenticated recipient
     * @return owned ciphertext lease
     */
    public KeygenDelivery keygenDelivery(Admission admission) {
        EnrollmentKeygenArtifact observed = findKeygen(admission).orElseThrow(EnrollmentCoordinator::unavailable);
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            EnrollmentKeygenArtifact value = keygen(observed.id()).orElseThrow(EnrollmentCoordinator::unavailable);
            EnrollmentTransaction enrollment = find(value.enrollmentId()).orElseThrow(EnrollmentCoordinator::unavailable);
            requireKeygenLink(value, enrollment);
            if (value.state() != EnrollmentKeygenArtifact.State.ATTACHED || value.bytesReleased()
                    || !clock.instant().isBefore(value.deliveryDeadline()) || enrollment.state() != EnrollmentTransaction.State.ISSUED) {
                throw unavailable();
            }
            EnrollmentTransaction.ArtifactBinding body = value.artifact().orElseThrow();
            try { return new KeygenDelivery(runtime.keygenSpool().acquire(value.id(), body.ciphertextBytes(), body.ciphertextSha256()), body.ciphertextBytes()); }
            catch (EnrollmentKeygenSpool.CapacityUnavailable capacity) { throw unavailable(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
            catch (java.io.IOException failure) { fenced = true; throw unavailable(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    /** Bounded ciphertext borrower; the caller must close it on every HTTP outcome. */
    public static final class KeygenDelivery implements AutoCloseable {
        private final EnrollmentKeygenSpool.Lease lease;
        private final long length;
        private KeygenDelivery(EnrollmentKeygenSpool.Lease lease, long length) { this.lease = lease; this.length = length; }
        /** {@return exact encrypted body length} */
        public long length() { return length; }
        /**
         * Opens the sole bounded body stream. Closing it also releases this lease.
         * @return encrypted body, never a plaintext private key
         * @throws java.io.IOException if the lease was released or already opened
         */
        public java.io.InputStream openStream() throws java.io.IOException { return lease.openStream(); }
        /** @throws java.io.IOException if the owned file cannot be closed */
        @Override public void close() throws java.io.IOException { lease.close(); }
    }

    private void cleanupKeygen(String id) {
        EnrollmentKeygenArtifact expired;
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen();
            EnrollmentKeygenArtifact value = keygen(id).orElseThrow(EnrollmentCoordinator::unavailable);
            if (value.bytesReleased() || keygenJobs.contains(id) || value.state() == EnrollmentKeygenArtifact.State.GENERATING) {
                return;
            }
            if (value.state() == EnrollmentKeygenArtifact.State.ATTACHED) {
                EnrollmentTransaction enrollment = find(value.enrollmentId()).orElseThrow(EnrollmentCoordinator::unavailable);
                requireKeygenLink(value, enrollment);
                if (enrollment.state() == EnrollmentTransaction.State.DISPATCHING || enrollment.state() == EnrollmentTransaction.State.ACCEPTED
                        || enrollment.state() == EnrollmentTransaction.State.UNCERTAIN) {
                    return;
                }
                if (clock.instant().isBefore(value.deliveryDeadline()) && enrollment.state() != EnrollmentTransaction.State.REJECTED
                        && enrollment.state() != EnrollmentTransaction.State.EXPIRED && enrollment.state() != EnrollmentTransaction.State.FAILED) {
                    return;
                }
                // The delivery deadline also caps fresh signing admission; accepted work was excluded above.
                expireUnclaimed(enrollment);
                expired = keygenState(value, EnrollmentKeygenArtifact.State.EXPIRED, value.artifact(), false);
                keygenMutation(value, expired);
            } else {
                expired = value;
            }
            keygenJobs.add(id);
        }
        try {
            if (runtime.keygenSpool().deleteExpired(id)) {
                synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                    requireOpen(); requireKeygenCurrent(expired);
                    keygenMutation(expired, keygenState(expired, expired.state(), expired.artifact(), true));
                    keygenCiphertextBytes -= expired.maximumCiphertextBytes();
                }
            }
        } catch (java.io.IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Provider and untrusted-input failures are normalized before crossing the public trust boundary.
            synchronized (control) { fenced = true; } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } finally { synchronized (control) { keygenJobs.remove(id); } } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
    }

    private void reclaimExpiredKeygen() {
        synchronized (control) { requireOpen(); } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ENROLLMENT_KEYGEN)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                cleanupKeygen(EnrollmentKeygenCodec.decode(next.orElseThrow()).id());
            }
        }
    }

    private void recoverKeygenDescriptors() {
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ENROLLMENT_KEYGEN)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                EnrollmentKeygenArtifact value = EnrollmentKeygenCodec.decode(next.orElseThrow());
                EnrollmentRuntimeConfiguration.KeygenArtifacts config = runtime.configuration().keygenArtifacts().orElseThrow(EnrollmentCoordinator::unavailable);
                validateRecoveredKeygen(value, config);
                accountRecoveredKeygen(value, config);
            }
            if (runtime.configuration().keygenArtifacts().isPresent()) {
                runtime.keygenSpool().inspectFiles(id -> {
                EnrollmentKeygenArtifact value = keygen(id).orElseThrow(EnrollmentCoordinator::unavailable);
                if (value.bytesReleased()) {
                    throw unavailable();
                }
            });
            }
        } catch (java.io.IOException failure) { throw unavailable(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private void validateRecoveredKeygen(EnrollmentKeygenArtifact value, EnrollmentRuntimeConfiguration.KeygenArtifacts config)
            throws java.io.IOException {
        if (value.maximumCiphertextBytes() > config.maximumArtifactBytes()
                || value.maximumGeneratedRequestBytes() > budgets.maximumRequestBytes()) {
            throw unavailable();
        }
        validateReferences(value.template());
        if (value.deliveryDeadline().isAfter(runtime.credentialNotAfter(value.template().source().credentialId().orElseThrow()))) {
            throw unavailable();
        }
        X509EnrollmentPayload original = loadRequest(value.template());
        zeroecho.pkix.EstKeygen.requireAttributes(original.der());
        // RFC 7030 templates retain exact bytes and policy identity, but carry no proof obligation.
        requests().parseX509(original);
        if (value.artifact().isPresent()) {
            EnrollmentTransaction enrollment = find(value.enrollmentId()).orElseThrow(EnrollmentCoordinator::unavailable);
            requireKeygenLink(value, enrollment);
            X509EnrollmentPayload generated = loadRequest(enrollment);
            requireGeneratedIdentity(value, requests().parseX509(generated), generated);
            if (value.state() == EnrollmentKeygenArtifact.State.ATTACHED) {
                EnrollmentTransaction.ArtifactBinding body = value.artifact().orElseThrow();
                runtime.keygenSpool().verify(value.id(), body.ciphertextBytes(), body.ciphertextSha256());
            }
        } else if (find(value.enrollmentId()).isPresent()) {
            throw unavailable();
        }
    }

    private void accountRecoveredKeygen(EnrollmentKeygenArtifact value, EnrollmentRuntimeConfiguration.KeygenArtifacts config) {
        retained = Math.addExact(retained, 1);
        retainedBytes = Math.addExact(retainedBytes, keygenCharge(value));
        keygenArtifacts = Math.addExact(keygenArtifacts, 1);
        if (!value.bytesReleased()) {
            keygenCiphertextBytes = Math.addExact(keygenCiphertextBytes, value.maximumCiphertextBytes());
        }
        if (value.state() == EnrollmentKeygenArtifact.State.GENERATING) {
            pending = Math.addExact(pending, 1);
        }
        if (retained > budgets.maximumTransactions() || retainedBytes > budgets.maximumRetainedRequestBytes()
                || keygenArtifacts > config.maximumArtifacts() || keygenCiphertextBytes > config.maximumRetainedBytes()) {
            throw unavailable();
        }
    }

    // Runs only after all control namespaces, immutable requests and bidirectional links validated.
    private void finishKeygenRecovery() {
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ENROLLMENT_KEYGEN)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                EnrollmentKeygenArtifact value = EnrollmentKeygenCodec.decode(next.orElseThrow());
                if (value.state() == EnrollmentKeygenArtifact.State.GENERATING) {
                    EnrollmentKeygenArtifact failed = keygenState(value, EnrollmentKeygenArtifact.State.FAILED, Optional.empty(), false);
                    keygenMutation(value, failed); pending--;
                }
                cleanupKeygen(value.id());
            }
        }
    }

    private record PlannedAdmission(ParsedCertificationRequest parsed, EnrollmentTransaction.Intent intent) { }

    private PlannedAdmission planAdmission(Admission admission, Optional<String> expectedEndpointCommitment, Optional<CmpTransaction> cmp) {
        byte[] der = admission.payload().der();
        Selection selection = admissionSelection(admission, cmp);
        if (expectedEndpointCommitment.isPresent() && !expectedEndpointCommitment.orElseThrow().equals(selection.source().commitment())) {
            throw unavailable();
        }
        ParsedCertificationRequest parsed = requests().parseX509(admission.payload());
        EnrollmentProfile policy = profiles.requireBinding(selection.source().enrollmentProfileId(), selection.profileId(), selection.authorityId().value(), true);
        validateIdentity(policy, parsed);
        AdmissionProfile profile = admissionProfile(admission, cmp, selection);
        CertificateProfileRef profileReference = profile.reference();
        CertificateProfileDefinition profileDefinition = profile.definition();
        if (admission.operation() != EnrollmentTransaction.Operation.SERVER_KEYGEN) {
            requests().requireProfileProof(parsed, profileReference);
        }
        CaRecord authority = session.repository().authority(selection.authorityId()).orElseThrow(EnrollmentCoordinator::unavailable);
        zeroecho.pki.api.ca.IssuerChainPath path = session.repository().chainPath(authority.issuanceChainPathId()).orElseThrow(EnrollmentCoordinator::unavailable);
        if (admission.protocol() == EnrollmentTransaction.Protocol.ACME) {
            requireAcmeIssuanceBinding(selection, profileReference, authority, path);
        }
        Optional<String> predecessorDigest = predecessorDigest(admission, parsed, selection.authorityId(), profileReference);
        ApprovalCategory category = switch (profileDefinition.approvalRequirement()) {
            case NONE -> policy.requireApproval() ? ApprovalCategory.ISSUANCE_SINGLE : ApprovalCategory.NONE;
            case SINGLE -> ApprovalCategory.ISSUANCE_SINGLE;
            case THRESHOLD -> ApprovalCategory.ISSUANCE_THRESHOLD;
        };
        Optional<ApprovalService.Policy> approval = admissionApproval(category);
        Instant now = clock.instant();
        Instant expires = admissionExpiry(admission, cmp, approval, selection, now);
        EnrollmentTransaction.Requester requester = cmp.isPresent() ? cmp.orElseThrow().frozen().requester() : withCurrentAliases(admission.requester());
        EnrollmentTransaction.Intent intent = new EnrollmentTransaction.Intent(realm.realmId(), selection.source(), requester, admission.transactionId(),
                admission.operation(), parsed.requestId(), admission.payload().kind(), EnrollmentTransactionCodec.sha256(der), der.length, selection.authorityId(),
                profileReference, authority.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment(), admission.validity(), admission.predecessorId(), predecessorDigest,
                category, approval, Optional.empty(), now, expires);
        return new PlannedAdmission(parsed, intent);
    }

    private Optional<ApprovalService.Policy> admissionApproval(ApprovalCategory category) {
        if (category == ApprovalCategory.NONE) {
            return Optional.empty();
        }
        return Optional.of(Optional.ofNullable(realm.approvalPolicies().get(category)).orElseThrow(EnrollmentCoordinator::unavailable));
    }

    private void requireAcmeIssuanceBinding(Selection selection, CertificateProfileRef profile,
            CaRecord authority, zeroecho.pki.api.ca.IssuerChainPath path) {
        AcmeState.Directory directory = acme.get(AcmeState.Directory.class, selection.source().recordId())
                .orElseThrow(EnrollmentCoordinator::unavailable);
        if (!directory.profile().equals(profile) || !directory.issuerId().equals(authority.currentIssuanceIssuerId())
                || !directory.issuancePathId().equals(path.pathId())
                || !directory.issuancePathCommitment().equals(path.pathCommitment())) {
            throw unavailable();
        }
    }

    private Selection admissionSelection(Admission admission, Optional<CmpTransaction> cmp) {
        Selection selection = selection(admission.protocol(), admission.endpointId());
        if (admission.operation() == EnrollmentTransaction.Operation.SERVER_KEYGEN) {
            EnrollmentTransaction.Source source = selection.source();
            String credential = runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.EST, selection.authorityId().value());
            selection = new Selection(new EnrollmentTransaction.Source(source.protocol(), source.label(), source.recordId(), source.revision(),
                    source.commitment(), source.enrollmentProfileId(), source.enrollmentCommitment(), Optional.of(credential)),
                    selection.authorityId(), selection.profileId());
        }
        if (cmp.isPresent()) {
            CmpTransaction manifest = cmp.orElseThrow();
            if (manifest.enrollmentId().isPresent() || manifest.response().isPresent()) {
                throw unavailable();
            }
            EnrollmentTransaction.Source frozen = manifest.frozen().source();
            EnrollmentTransaction.Source observed = selection.source();
            observed = new EnrollmentTransaction.Source(observed.protocol(), observed.label(), observed.recordId(), observed.revision(),
                    observed.commitment(), observed.enrollmentProfileId(), observed.enrollmentCommitment(), frozen.credentialId());
            if (!observed.equals(frozen)) {
                throw unavailable();
            }
            selection = new Selection(frozen, selection.authorityId(), selection.profileId());
        }
        return selection;
    }

    private AdmissionProfile admissionProfile(Admission admission, Optional<CmpTransaction> cmp, Selection selection) {
        CertificateProfileRef profileReference;
        CertificateProfileDefinition profileDefinition;
        if (cmp.isPresent()) {
            CertificateProfileRef frozen = cmp.orElseThrow().frozen().profile();
            ImportedCertificateProfileVersion imported = session.profiles().getImportedVersion(frozen.profileId(), frozen.profileVersion())
                    .orElseThrow(EnrollmentCoordinator::unavailable);
            if (!imported.reference().equals(frozen)) {
                throw unavailable();
            }
            profileReference = frozen; profileDefinition = imported.definition();
        } else if (admission.protocol() == EnrollmentTransaction.Protocol.ACME) {
            AcmeState.Directory directory = acme.get(AcmeState.Directory.class, selection.source().recordId()).orElseThrow(EnrollmentCoordinator::unavailable);
            ImportedCertificateProfileVersion imported = session.profiles().getImportedVersion(directory.profile().profileId(),
                    directory.profile().profileVersion()).orElseThrow(EnrollmentCoordinator::unavailable);
            if (!imported.reference().equals(directory.profile())) {
                throw unavailable();
            }
            profileReference = imported.reference();
            profileDefinition = imported.definition();
        } else {
            ActiveCertificateProfile active = session.profiles().requireActiveProfile(selection.profileId());
            profileReference = active.reference();
            profileDefinition = active.definition();
        }
        return new AdmissionProfile(profileReference, profileDefinition);
    }

    private Optional<String> predecessorDigest(Admission admission, ParsedCertificationRequest parsed,
            PkiId selectedAuthority, CertificateProfileRef profileReference) {
        return admission.predecessorId().map(predecessor -> {
            if (admission.operation() == EnrollmentTransaction.Operation.RENEW) {
                requests().requireRenewalIdentity(parsed, predecessor);
            }
            Credential credential = session.repository().credential(predecessor).orElseThrow(EnrollmentCoordinator::unavailable);
            if (!credential.issuerRef().caId().equals(selectedAuthority) || !(credential.profileBinding() instanceof EndEntityProfileBinding binding)
                    || admission.operation() == EnrollmentTransaction.Operation.RENEW && !binding.reference().equals(profileReference)) {
                throw unavailable();
            }
            return credential.content().sha256();
        });
    }

    private Instant admissionExpiry(Admission admission, Optional<CmpTransaction> cmp,
            Optional<ApprovalService.Policy> approval, Selection selection, Instant now) {
        Instant expires = now.plus(budgets.pendingLifetime());
        if (admission.protocolDeadline().isPresent()) {
            expires = earlier(expires, admission.protocolDeadline().orElseThrow());
        }
        if (cmp.isPresent()) {
            expires = earlier(expires, cmp.orElseThrow().frozen().expiresAt());
        }
        if (!expires.isAfter(now)) {
            throw unavailable();
        }
        if (approval.isPresent()) {
            expires = earlier(expires, now.plus(approval.orElseThrow().lifetime()));
        }
        if (selection.source().credentialId().isPresent()) {
            expires = earlier(expires, runtime.admissionDeadline(selection.source().credentialId().orElseThrow()));
        }
        return expires;
    }

    private record AdmissionProfile(CertificateProfileRef reference, CertificateProfileDefinition definition) { }

    private EnrollmentTransaction admitInternal(Admission admission, Optional<String> expectedEndpointCommitment, Optional<CmpTransaction> cmp) {
        Objects.requireNonNull(admission, "admission");
        byte[] der = admission.payload().der();
        if (der.length > budgets.maximumRequestBytes()) {
            throw unavailable();
        }
        if (admission.operation() == EnrollmentTransaction.Operation.SERVER_KEYGEN) {
            throw new IllegalStateException("Encrypted key-generation artifact admission is not installed");
        }
        String label = admission.protocol() == EnrollmentTransaction.Protocol.ACME
                ? acme.get(AcmeState.Directory.class, admission.endpointId()).orElseThrow(EnrollmentCoordinator::unavailable).alias() : admission.endpointId();
        String id = EnrollmentTransactionCodec.replayId(realm.realmId(), admission.protocol(), label, admission.requester(), admission.transactionId(), admission.operation());
        Optional<EnrollmentTransaction> existing;
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen(); existing = find(id);
        }
        if (existing.isPresent()) {
            cmp.ifPresent(manifest -> requireCmpLink(manifest, existing.orElseThrow()));
            if (expectedEndpointCommitment.filter(value -> !value.equals(existing.orElseThrow().intent().source().commitment())).isPresent()) {
                throw unavailable();
            }
            return requireReplay(existing.orElseThrow(), admission);
        }
        PlannedAdmission planned = planAdmission(admission, expectedEndpointCommitment, cmp);
        ParsedCertificationRequest parsed = planned.parsed();
        EnrollmentTransaction.Intent intent = planned.intent();
        EnrollmentTransaction value = new EnrollmentTransaction(id, 1, intent, intent.approvalPolicy().isPresent() ? EnrollmentTransaction.State.PENDING
                : EnrollmentTransaction.State.APPROVED, List.of(), Optional.empty(), Optional.empty());
        long reservation = reservedBytes(value);
        Optional<CmpTransaction> linked = cmp.map(manifest -> new CmpTransaction(manifest.id(), Math.addExact(manifest.revision(), 1),
                manifest.frozen(), Optional.of(value.id()), manifest.response()));
        linked.ifPresent(manifest -> requireCmpLink(manifest, value));
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            reserveAdmission(value, cmp, reservation);
        }
        try {
            synchronized (requestStorageLock) { // NOPMD AvoidSynchronizedStatement - Serializes owned request-file publication with cleanup.
                storeAdmissionRequest(parsed, admission.payload(), der);
            }
            synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                requireOpen(); Optional<EnrollmentTransaction> prior = find(id);
                if (prior.isPresent()) {
                    if (cmp.isEmpty()) {
                        retained--;
                    }
                    pending--; retainedBytes -= reservation;
                    throw unavailable();
                }
                requireCurrent(value);
                if (cmp.isPresent()) {
                    CmpTransaction manifest = requireCmpCurrent(cmp.orElseThrow());
                    mutateCmp(List.of(new ServerControlStore.ProtocolMutation(CmpTransactionCodec.record(linked.orElseThrow()), Optional.of(manifest.commitment())),
                            new ServerControlStore.ProtocolMutation(EnrollmentTransactionCodec.record(value), Optional.empty())));
                } else {
                    write(null, value);
                }
                return value;
            }
        } catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            synchronized (control) { fenced = true; } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } finally {
            synchronized (control) { admissions.remove(id); } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
        }
    }

    // Called under requestStorageLock so replay validation and publication remain indivisible.
    private void storeAdmissionRequest(ParsedCertificationRequest parsed, X509EnrollmentPayload payload, byte[] der) {
        Optional<ParsedCertificationRequest> storedRequest = requests().get(parsed.requestId());
        if (storedRequest.isPresent()) {
            X509EnrollmentPayload retainedRequest = requests().encodedX509Request(storedRequest.orElseThrow());
            if (retainedRequest.kind() != payload.kind()
                    || !java.util.Arrays.equals(retainedRequest.der(), der)) {
                throw unavailable();
            }
        } else if (!requests().store(parsed, RequestStorePolicy.STORE_ALWAYS).equals(parsed.requestId())) {
            throw unavailable();
        }
    }

    // Called under the control monitor before request persistence starts.
    private void reserveAdmission(EnrollmentTransaction value, Optional<CmpTransaction> cmp, long reservation) {
        String id = value.id();
        requireOpen(); Optional<EnrollmentTransaction> prior = find(id);
        cmp.ifPresent(this::requireCmpCurrent);
        if (prior.isPresent() || admissions.contains(id)) {
            throw unavailable();
        }
        requireCurrent(value);
        if (pending >= budgets.maximumPending()) {
            expireUnclaimedRequests();
        }
        if (cmp.isEmpty() && retained >= budgets.maximumTransactions() || pending >= budgets.maximumPending()
                || reservation > budgets.maximumRetainedRequestBytes() - retainedBytes) {
            throw unavailable();
        }
        if (cmp.isEmpty()) {
            retained++;
        }
        pending++; retainedBytes += reservation; admissions.add(id);
    }

    /**
     * Finds the exact retained transaction without changing its state.
     * @param id durable enrollment identity
     * @return exact retained record or empty
     */
    public Optional<EnrollmentTransaction> find(String id) {
        return control.protocolRecord(ServerControlStore.ENROLLMENT_REQUEST, id).map(EnrollmentTransactionCodec::decode);
    }

    /**
     * Finds a retained transaction by stable authenticated protocol coordinates.
     * This grants no authentication or authorization and does not consult mutable
     * endpoint policy; adapters must cross-check the returned frozen binding.
     * @param protocol exact protocol family
     * @param label stable endpoint label or ACME directory alias
     * @param actorType authenticated protocol identity kind
     * @param actorId authenticated stable actor identity
     * @param transactionId exact protocol transaction SHA-256
     * @param operation exact operation replay domain
     * @return retained transaction or empty
     */
    public Optional<EnrollmentTransaction> find(EnrollmentTransaction.Protocol protocol, String label,
            IssuanceExecutionEvidence.ActorType actorType, String actorId, String transactionId, EnrollmentTransaction.Operation operation) {
        Objects.requireNonNull(protocol, "protocol"); Objects.requireNonNull(actorType, "actorType"); Objects.requireNonNull(operation, "operation");
        EnrollmentTransaction.id(label); EnrollmentTransaction.id(actorId); EnrollmentTransaction.digest(transactionId);
        return find(EnrollmentTransactionCodec.replayId(realm.realmId(), protocol, label, actorType, actorId, transactionId, operation));
    }

    /**
     * Projects the actual domain correlation for a retained issuance request.
     * Uses its exact stored payload and frozen intent; creates no signing work.
     * @param id retained ISSUE transaction identity
     * @return exact domain issuance binding
     */
    public zeroecho.pki.api.issuance.RetainedIssuanceBinding issuanceBinding(String id) {
        EnrollmentTransaction value = find(id).orElseThrow(EnrollmentCoordinator::unavailable);
        if (value.intent().operation() != EnrollmentTransaction.Operation.ISSUE) {
            throw unavailable();
        }
        return signing().issuanceBinding(issuance(value, loadRequest(value)));
    }

    /**
     * Reads a bounded deterministic page for the authoritative administrative projection.
     * Authorization filters are applied by the gateway before disclosure.
     * @param offset nonnegative offset
     * @param limit page size, at most 256
     * @return immutable retained transaction page
     */
    public ServerControlStore.Page<EnrollmentTransaction> list(int offset, int limit) {
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page = control.protocolRecords(ServerControlStore.ENROLLMENT_REQUEST, offset, limit);
        return new ServerControlStore.Page<>(page.values().stream().map(EnrollmentTransactionCodec::decode).toList(), page.nextOffset(), page.hasMore());
    }

    /**
     * Re-parses the exact retained request for authorized administrative inspection.
     * Callers must authorize the persisted scope before disclosing the result and
     * project only intended public identity fields, not its original byte attributes.
     * @param id durable enrollment identity
     * @return bounded authoritative request parse
     */
    public ParsedCertificationRequest inspectIdentity(String id) {
        EnrollmentTransaction value = find(id).orElseThrow(EnrollmentCoordinator::unavailable);
        return requests().parseX509(loadRequest(value));
    }

    /**
     * Persists an independently authenticated, currently eligible decision before
     * acknowledgement. One mathematical key can supply at most one vote.
     * @param id exact retained request identity
     * @param expectedCommitment exact record reviewed by the administrator
     * @param actor trusted administrative end-client evidence
     * @param choice approval or rejection
     * @param justification bounded operator explanation
     * @return durably updated record
     */
    public EnrollmentTransaction decide(String id, String expectedCommitment, AdministrativeDecisionActor actor,
            ApprovalService.Choice choice, String justification) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen(); EnrollmentTransaction current = find(id).orElseThrow(EnrollmentCoordinator::unavailable);
            if (!current.commitment().equals(expectedCommitment) || current.state() != EnrollmentTransaction.State.PENDING) {
                throw unavailable();
            }
            if (!current.intent().expiresAt().isAfter(clock.instant())) {
                return expire(current);
            }
            ApprovalService.Policy policy = current.intent().approvalPolicy().orElseThrow();
            CertificateIdentityEvidence evidence = requireApprover(current, actor, policy, justification);
            List<EnrollmentTransaction.Decision> decisions = new ArrayList<>(current.decisions());
            decisions.add(new EnrollmentTransaction.Decision(actor.principalId(), evidence, choice, justification, clock.instant()));
            EnrollmentTransaction.State state = choice == ApprovalService.Choice.REJECT ? EnrollmentTransaction.State.REJECTED
                    : decisions.size() >= policy.threshold() ? EnrollmentTransaction.State.APPROVED : EnrollmentTransaction.State.PENDING;
            EnrollmentTransaction updated = new EnrollmentTransaction(id, current.revision() + 1, current.intent(), state, decisions, Optional.empty(), Optional.empty());
            write(current, updated); return updated;
        }
    }

    // Called under the control monitor; eligibility and vote independence precede the durable decision.
    private CertificateIdentityEvidence requireApprover(EnrollmentTransaction current, AdministrativeDecisionActor actor,
            ApprovalService.Policy policy, String justification) {
        SecurityPrincipal principal = control.requirePrincipal(actor.principalId());
        CertificateIdentityEvidence evidence = actor.credentialEvidence().orElseThrow(EnrollmentCoordinator::unavailable);
        if (!principal.enabled() || !evidence.realmId().equals(realm.realmId())) {
            throw unavailable();
        }
        Permission.Scope scope = scope(current);
        boolean eligible = policy.eligibleApprovers().contains(principal.principalId()) || control.assignmentsFor(principal.principalId()).stream()
                .filter(RoleTemplateCatalog.Assignment::enabled).filter(assignment -> contains(assignment.scope(), scope))
                .anyMatch(assignment -> policy.requiredRoleTemplateIds().contains(assignment.templateId()));
        if (!eligible || policy.justificationRequired() && (justification == null || justification.isBlank())) {
            throw unavailable();
        }
        EnrollmentTransaction.Requester requester = current.intent().requester();
        requireIndependentAccountHistory(requester, actor, evidence);
        EnrollmentIdentityAliases.Snapshot exclusions = withCurrentAliases(requester).aliases();
        if (exclusions.principalIds().contains(actor.principalId())
                || requester.certificate().filter(evidence::sameCredential).isPresent()
                || requester.canonicalKeySha256().filter(evidence.canonicalKeySha256()::equals).isPresent()) {
            throw unavailable();
        }
        for (EnrollmentTransaction.Decision prior : current.decisions()) {
            if (prior.principalId().equals(actor.principalId()) || prior.evidence().sameCredential(evidence)) {
                throw unavailable();
            }
        }
        return evidence;
    }

    /**
     * Dispatches or reconciles one approved request. Durable DISPATCHING is the
     * admission boundary; suspension after that claim does not revoke admission.
     * Provider preparation and acceptance never hold the global control monitor.
     * @param id retained enrollment identity
     * @return latest durable state, including an explicit uncertain outcome
     */
    public EnrollmentTransaction dispatch(String id) {
        return dispatch(id, CancellationSignal.NONE);
    }

    /**
     * Dispatches with cooperative cancellation before the durable claim. Once
     * admitted, exact receipt reconciliation owns the outcome despite cancellation.
     * @param id retained enrollment identity
     * @param cancellation caller cancellation signal
     * @return latest durable transaction state
     */
    public EnrollmentTransaction dispatch(String id, CancellationSignal cancellation) {
        return dispatch(id, cancellation, () -> { });
    }

    /**
     * Dispatches with a transport-owned last pre-claim validation. The validator
     * runs outside the control monitor before preparation and immediately before
     * a fresh claim, including a retry proven not accepted. It does not run for
     * reconciliation of already admitted work. Failure after preparation discards
     * the candidate. This is not atomic ordering against external status changes.
     *
     * @param id retained enrollment identity
     * @param cancellation caller cancellation signal
     * @param beforeClaim validator that throws on loss of transport authorization
     * @return latest durable transaction state
     */
    public EnrollmentTransaction dispatch(String id, CancellationSignal cancellation, Runnable beforeClaim) {
        Objects.requireNonNull(cancellation, "cancellation");
        Objects.requireNonNull(beforeClaim, "beforeClaim");
        EnrollmentTransaction initial;
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen(); initial = find(id).orElseThrow(EnrollmentCoordinator::unavailable);
            if (inFlight.contains(id)) {
                return initial;
            }
            if (dispatches >= budgets.maximumConcurrentDispatches()) {
                throw unavailable();
            }
            dispatches++; inFlight.add(id);
        }
        try {
            if (initial.receipt().isPresent()) {
                initial = reconcile(initial);
            }
            if ((initial.state() == EnrollmentTransaction.State.PENDING || initial.state() == EnrollmentTransaction.State.APPROVED)
                    && !initial.intent().expiresAt().isAfter(clock.instant())) {
                return expire(initial);
            }
            if (initial.state() != EnrollmentTransaction.State.APPROVED) {
                return initial;
            }
            requireNotCancelled(cancellation);
            beforeClaim.run();
            requireNotCancelled(cancellation);
            synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                if (!initial.intent().expiresAt().isAfter(clock.instant())) {
                    return expire(initial);
                }
                requireCurrent(initial);
            }
            PreparedDispatch preparation = prepareDispatch(initial, cancellation);
            SemanticSigningService signing = preparation.signing();
            PreparedSemanticSigningRequest candidate = preparation.candidate();
            EnrollmentTransaction claimed;
            try {
                claimed = claimPrepared(initial, candidate, cancellation, beforeClaim);
            } catch (RuntimeException failure) { signing.discard(candidate); throw failure; } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            try {
                SigningAcceptanceResult accepted = signing.accept(candidate);
                if (!accepted.receipt().equals(claimed.receipt().orElseThrow())) {
                    throw unavailable();
                }
            } catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
                // The exact receipt, not an empty correlation lookup, decides retry safety.
                return reconcile(claimed);
            }
            return reconcile(claimed);
        } finally { synchronized (control) { dispatches--; inFlight.remove(id); } } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
    }

    private EnrollmentTransaction claimPrepared(EnrollmentTransaction initial, PreparedSemanticSigningRequest candidate,
            CancellationSignal cancellation, Runnable beforeClaim) {
        String id = initial.id();
        requireNotCancelled(cancellation);
        beforeClaim.run();
        requireNotCancelled(cancellation);
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireOpen(); EnrollmentTransaction current = find(id).orElseThrow(EnrollmentCoordinator::unavailable);
            if (current.revision() != initial.revision()) {
                throw unavailable();
            }
            if (!current.intent().expiresAt().isAfter(clock.instant())) {
                expire(current); throw unavailable();
            }
            requireCurrent(current);
            EnrollmentTransaction claimed = new EnrollmentTransaction(id, current.revision() + 1, current.intent(), EnrollmentTransaction.State.DISPATCHING,
                    current.decisions(), Optional.of(candidate.receipt()), Optional.empty());
            write(current, claimed);
            return claimed;
        }
    }

    private PreparedDispatch prepareDispatch(EnrollmentTransaction initial, CancellationSignal cancellation) {
        X509EnrollmentPayload payload = loadRequest(initial);
        EnrollmentTransaction.Intent intent = initial.intent();
        IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.enrollment(intent.requester().type(), intent.requester().actorId(),
                realm.realmId().value(), initial.id(), intent.requester().authentication(), intent.approvalPolicy().isPresent(),
                initial.intentCommitment(), intent.authorityId().value(), intent.profile().profileId());
        AccessContext access = new AccessContext(new Principal(intent.requester().type().name(), intent.requester().actorId()),
                new Purpose("ENROLLMENT"), Optional.of(intent.predecessorId().orElse(intent.requestId())), Optional.empty());
        SemanticSigningService signing = signing();
        CorrelatedIssuancePreparation prepared = switch (intent.operation()) {
            case RENEW -> signing.prepareCorrelatedRenewal(access, renewal(initial), Optional.of(evidence), cancellation);
            case REPLACE -> signing.prepareCorrelatedReplacement(access, replacement(initial, payload), Optional.of(evidence), cancellation);
            case ISSUE, SERVER_KEYGEN -> signing.prepareCorrelatedEndEntity(access, issuance(initial, payload), Optional.of(evidence), cancellation);
        };
        if (prepared instanceof CorrelatedIssuancePreparation.Existing) {
            // Every accepted attempt must have had its receipt durably attached first.
            throw unavailable();
        }
        PreparedSemanticSigningRequest candidate = ((CorrelatedIssuancePreparation.Prepared) prepared).prepared();
        return new PreparedDispatch(signing, candidate);
    }

    private record PreparedDispatch(SemanticSigningService signing, PreparedSemanticSigningRequest candidate) { }

    private static void requireNotCancelled(CancellationSignal cancellation) {
        try { cancellation.throwIfCancelled(); }
        catch (java.io.InterruptedIOException cancelled) { throw new zeroecho.pki.api.PkiException("Enrollment dispatch was cancelled"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    /**
     * Derives administrative scope solely from the retained authoritative request.
     * @param value durable enrollment record
     * @return exact realm, authority, issuer and certificate-profile scope
     */
    public static Permission.Scope scope(EnrollmentTransaction value) {
        return new Permission.Scope(value.intent().realmId(), Optional.of(value.intent().authorityId()),
                Optional.of(value.intent().issuerId()), Optional.of(value.intent().profile().profileId()));
    }

    /** Fences new work; active callers must drain before realm dependencies close. */
    @Override public void close() {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            closed = true;
            if (dispatches != 0 || admissionCalls != 0 || !keygenJobs.isEmpty()) {
                throw new IllegalStateException("Enrollment work is still active");
            }
        }
    }

    private EnrollmentTransaction reconcile(EnrollmentTransaction observed) {
        if (observed.receipt().isEmpty()) {
            return observed;
        }
        SigningAcceptanceResolution resolution;
        try { resolution = signing().resolve(observed.receipt().orElseThrow()); }
        catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Provider and untrusted-input failures are normalized before crossing the public trust boundary.
            if (observed.state() == EnrollmentTransaction.State.ISSUED || observed.state() == EnrollmentTransaction.State.FAILED) {
                throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
            }
            if (observed.state() == EnrollmentTransaction.State.ACCEPTED) {
                return observed;
            }
            return transition(observed, EnrollmentTransaction.State.UNCERTAIN, observed.receipt(), Optional.empty());
        }
        if (resolution == SigningAcceptanceResolution.CONFLICT) {
            synchronized (control) { fenced = true; } throw unavailable(); // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
        }
        if (resolution == SigningAcceptanceResolution.NOT_ACCEPTED) {
            if (observed.state() == EnrollmentTransaction.State.ACCEPTED || observed.state() == EnrollmentTransaction.State.ISSUED
                    || observed.state() == EnrollmentTransaction.State.FAILED) {
                synchronized (control) { fenced = true; } // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
                throw unavailable();
            }
            return transition(observed, EnrollmentTransaction.State.APPROVED, Optional.empty(), Optional.empty());
        }
        return reconcileAccepted(observed);
    }

    private EnrollmentTransaction reconcileAccepted(EnrollmentTransaction observed) {
        X509EnrollmentPayload payload = loadRequest(observed);
        SemanticSigningOperation operation = (switch (observed.intent().operation()) {
            case RENEW -> signing().findRenewal(renewal(observed));
            case REPLACE -> signing().findReplacement(replacement(observed, payload));
            case ISSUE, SERVER_KEYGEN -> signing().findIssuance(issuance(observed, payload));
        }).orElseThrow(EnrollmentCoordinator::unavailable);
        if (!operation.submissionId().id().equals(observed.receipt().orElseThrow().operationId())) {
            throw unavailable();
        }
        EnrollmentTransaction.State state = EnrollmentTransaction.State.ACCEPTED;
        Optional<PkiId> credential = Optional.empty();
        if (operation.state() == SemanticSigningState.COMPLETED) {
            credential = operation.completedCredentialId();
            requireIssuedCredential(observed, credential.orElseThrow());
            state = EnrollmentTransaction.State.ISSUED;
        } else if (operation.state() == SemanticSigningState.FAILED || operation.state() == SemanticSigningState.EXPIRED) {
            state = EnrollmentTransaction.State.FAILED;
        }
        if (observed.state() == EnrollmentTransaction.State.ISSUED && !observed.credentialId().equals(credential)) {
            throw unavailable();
        }
        return transition(observed, state, observed.receipt(), credential);
    }

    private void requireIssuedCredential(EnrollmentTransaction observed, PkiId credentialId) {
        Credential stored = session.repository().credential(credentialId).orElseThrow(EnrollmentCoordinator::unavailable);
        if (!stored.issuerRef().caId().equals(observed.intent().authorityId())
                || !stored.issuerRef().issuerId().equals(observed.intent().issuerId())
                || !stored.issuerRef().chainPathId().equals(observed.intent().pathId())
                || !(stored.profileBinding() instanceof EndEntityProfileBinding profile) || !profile.reference().equals(observed.intent().profile())) {
            throw unavailable();
        }
    }

    private EnrollmentTransaction transition(EnrollmentTransaction prior, EnrollmentTransaction.State state,
            Optional<SigningAcceptanceReceipt> receipt, Optional<PkiId> credential) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            EnrollmentTransaction current = find(prior.id()).orElseThrow(EnrollmentCoordinator::unavailable);
            if (current.revision() != prior.revision()) {
                return current;
            }
            if (state == current.state() && receipt.equals(current.receipt()) && credential.equals(current.credentialId())) {
                return current;
            }
            EnrollmentTransaction next = new EnrollmentTransaction(current.id(), current.revision() + 1, current.intent(), state, current.decisions(), receipt, credential);
            write(current, next); return next;
        }
    }

    private EnrollmentTransaction expire(EnrollmentTransaction value) {
        return transition(value, EnrollmentTransaction.State.EXPIRED, Optional.empty(), Optional.empty());
    }

    private void expireUnclaimed(EnrollmentTransaction value) {
        if ((value.state() == EnrollmentTransaction.State.PENDING || value.state() == EnrollmentTransaction.State.APPROVED)
                && !value.intent().expiresAt().isAfter(clock.instant())) {
            expire(value);
        }
    }

    private void expireUnclaimedRequests() {
        // Capacity pressure makes one bounded snapshot pass; terminal replay records remain retained.
        try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ENROLLMENT_REQUEST)) {
            Optional<ServerControlStore.ProtocolRecord> next;
            while ((next = cursor.next()).isPresent()) {
                expireUnclaimed(EnrollmentTransactionCodec.decode(next.orElseThrow()));
            }
        }
    }

    private void write(EnrollmentTransaction prior, EnrollmentTransaction value) {
        if (EnrollmentTransactionCodec.encode(value).length + value.intent().requestBytes() > reservedBytes(value)) {
            throw unavailable();
        }
        try {
            control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(EnrollmentTransactionCodec.record(value),
                    Optional.ofNullable(prior).map(EnrollmentTransaction::commitment))));
        } catch (RuntimeException failure) { fenced = true; throw unavailable(); } // NOPMD AvoidCatchingGenericException, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        if (prior != null && unaccepted(prior.state()) != unaccepted(value.state())) {
            pending += unaccepted(value.state()) ? 1 : -1;
        }
    }

    private long reservedBytes(EnrollmentTransaction value) {
        EnrollmentTransaction blank = new EnrollmentTransaction(value.id(), 1, value.intent(),
                value.intent().approvalPolicy().isPresent() ? EnrollmentTransaction.State.PENDING : EnrollmentTransaction.State.APPROVED,
                List.of(), Optional.empty(), Optional.empty());
        // Modified UTF-8 encodes each justification UTF-16 unit in at most three bytes.
        // Vote = principal (258), realm (258), six hashes (396), collection (4),
        // choice (9), justification (6146), time (12); 7200 safely bounds all fields.
        long metadata = Math.addExact(EnrollmentTransactionCodec.encode(blank).length,
                Math.addExact(1024, Math.multiplyExact(7200L, value.intent().approvalPolicy().map(ApprovalService.Policy::threshold).orElse(0))));
        if (metadata > EnrollmentTransactionCodec.MAXIMUM_BYTES) {
            throw unavailable();
        }
        return Math.addExact(value.intent().requestBytes(), metadata);
    }

    private X509EnrollmentPayload loadRequest(EnrollmentTransaction value) {
        requireRealm(value);
        return loadRequest(value.intent());
    }

    private X509EnrollmentPayload loadRequest(EnrollmentTransaction.Intent intent) {
        if (!realm.realmId().equals(intent.realmId())) {
            throw unavailable();
        }
        ParsedCertificationRequest parsed = requests().get(intent.requestId()).orElseThrow(EnrollmentCoordinator::unavailable);
        X509EnrollmentPayload payload = requests().encodedX509Request(parsed);
        byte[] der = payload.der();
        if (!parsed.requestId().equals(intent.requestId()) || payload.kind() != intent.requestKind()
                || der.length != intent.requestBytes() || !EnrollmentTransactionCodec.sha256(der).equals(intent.requestSha256())) {
            throw unavailable();
        }
        return payload;
    }

    private void requireCurrent(EnrollmentTransaction value) {
        requireCurrent(value.intent());
        if (value.intent().artifact().isPresent()) {
            EnrollmentKeygenArtifact artifact = keygen(value.intent().artifact().orElseThrow().artifactId()).orElseThrow(EnrollmentCoordinator::unavailable);
            requireKeygenLink(artifact, value);
            if (artifact.state() != EnrollmentKeygenArtifact.State.ATTACHED || artifact.bytesReleased()
                    || !clock.instant().isBefore(artifact.deliveryDeadline())) {
                throw unavailable();
            }
        }
    }

    private void requireCurrent(EnrollmentTransaction.Intent intent) {
        if (!realm.authorityExposure().allows(intent.authorityId())) {
            throw unavailable();
        }
        Selection current = selection(intent.source().protocol(), intent.source().protocol() == EnrollmentTransaction.Protocol.ACME
                ? intent.source().recordId() : intent.source().label());
        EnrollmentTransaction.Source observed = current.source();
        if (intent.source().credentialId().isPresent()) {
            runtime.requireRetainedCredential(EnrollmentRuntimeConfiguration.Protocol.valueOf(intent.source().protocol().name()),
                    intent.source().credentialId().orElseThrow(), intent.authorityId().value(), intent.issuerId().value(), intent.pathId().value());
            runtime.requireAdmissionCredential(intent.source().credentialId().orElseThrow(), intent.authorityId().value(),
                    intent.issuerId().value(), intent.pathId().value());
            CaRecord authority = session.repository().authority(intent.authorityId()).orElseThrow(EnrollmentCoordinator::unavailable);
            if (!authority.currentIssuanceIssuerId().equals(intent.issuerId()) || !authority.issuanceChainPathId().equals(intent.pathId())) {
                throw unavailable();
            }
            observed = new EnrollmentTransaction.Source(observed.protocol(), observed.label(), observed.recordId(), observed.revision(),
                    observed.commitment(), observed.enrollmentProfileId(), observed.enrollmentCommitment(), intent.source().credentialId());
        }
        if (!observed.equals(intent.source()) || !current.authorityId().equals(intent.authorityId())
                || !current.profileId().equals(intent.profile().profileId())) {
            throw unavailable();
        }
    }

    private void validateReferences(EnrollmentTransaction value) {
        validateReferences(value.intent());
    }

    private void validateReferences(EnrollmentTransaction.Intent intent) {
        if (intent.source().credentialId().isPresent()) {
            runtime.requireRetainedCredential(EnrollmentRuntimeConfiguration.Protocol.valueOf(intent.source().protocol().name()),
                    intent.source().credentialId().orElseThrow(), intent.authorityId().value(), intent.issuerId().value(), intent.pathId().value());
        }
        if (!session.profiles().getImportedVersion(intent.profile().profileId(), intent.profile().profileVersion())
                .orElseThrow(EnrollmentCoordinator::unavailable).reference().equals(intent.profile())) {
            throw unavailable();
        }
        zeroecho.pki.api.ca.IssuerGeneration issuer = session.repository().issuer(intent.issuerId()).orElseThrow(EnrollmentCoordinator::unavailable);
        zeroecho.pki.api.ca.IssuerChainPath path = session.repository().chainPath(intent.pathId()).orElseThrow(EnrollmentCoordinator::unavailable);
        if (session.repository().authority(intent.authorityId()).isEmpty() || !issuer.authorityId().equals(intent.authorityId())
                || !path.authorityId().equals(intent.authorityId()) || !path.issuerId().equals(intent.issuerId())
                || !path.pathCommitment().equals(intent.pathCommitment())) {
            throw unavailable();
        }
    }

    private Selection selection(EnrollmentTransaction.Protocol protocol, String id) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            String label; String recordId; long revision; String commitment; String enrollment; String certificate; PkiId authority;
            if (protocol == EnrollmentTransaction.Protocol.ACME) {
                AcmeState.Directory directory = acme.get(AcmeState.Directory.class, id).orElseThrow(EnrollmentCoordinator::unavailable);
                if (directory.status() != AcmeState.DirectoryStatus.ACTIVE) {
                    throw unavailable();
                }
                label = directory.alias(); recordId = directory.directoryId(); revision = directory.revision(); commitment = directory.commitment();
                enrollment = directory.enrollmentProfileId(); certificate = directory.profile().profileId(); authority = directory.authorityId();
            } else {
                EnrollmentEndpointRegistry.Protocol kind = EnrollmentEndpointRegistry.Protocol.valueOf(protocol.name());
                EnrollmentEndpoint endpoint = endpoints.find(kind, id).orElseThrow(EnrollmentCoordinator::unavailable);
                EnrollmentEndpointRegistry.Snapshot snapshot = endpoints.requireCurrent(endpoint);
                label = endpoint.label(); recordId = protocol.name() + ":" + label; revision = snapshot.revision(); commitment = snapshot.commitment();
                enrollment = endpoint.enrollmentProfileId(); certificate = endpoint.profileId(); authority = new PkiId(endpoint.authorityId());
            }
            EnrollmentProfile policy = profiles.requireBinding(enrollment, certificate, authority.value(), true);
            Optional<String> credential = protocol == EnrollmentTransaction.Protocol.SCEP || protocol == EnrollmentTransaction.Protocol.CMP
                    ? Optional.of(runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.valueOf(protocol.name()), authority.value())) : Optional.empty();
            return new Selection(new EnrollmentTransaction.Source(protocol, label, recordId, revision, commitment, enrollment,
                    EnrollmentProfileService.commitment(policy), credential), authority, certificate);
        }
    }

    private EnrollmentTransaction requireReplay(EnrollmentTransaction value, Admission admission) {
        EnrollmentTransaction.Intent intent = value.intent();
        if (intent.requestKind() != admission.payload().kind() || !intent.requestSha256().equals(EnrollmentTransactionCodec.sha256(admission.payload().der()))
                || !intent.validity().equals(admission.validity()) || !intent.predecessorId().equals(admission.predecessorId())
                || !intent.requester().canonicalKeySha256().equals(admission.requester().canonicalKeySha256())
                || !intent.requester().certificate().equals(admission.requester().certificate())) {
            throw unavailable();
        }
        loadRequest(value); return value;
    }

    private EnrollmentTransaction.Requester withCurrentAliases(EnrollmentTransaction.Requester requester) {
        EnrollmentIdentityAliases.Snapshot current = requester.certificate().map(aliases::knownAliases)
                .orElseGet(() -> aliases.knownKeyHashes(requester.legacySpkiSha256()));
        return new EnrollmentTransaction.Requester(requester.type(), requester.actorId(), requester.authentication(), requester.certificate(),
                requester.canonicalKeySha256(), requester.legacySpkiSha256(), requester.aliases().union(current));
    }

    private static void validateIdentity(EnrollmentProfile profile, ParsedCertificationRequest parsed) {
        if (profile.subjectDnPattern().isPresent() && !EnrollmentSubjectPattern.compile(profile.subjectDnPattern().orElseThrow()).matches(parsed.subjectRef().value())) {
            throw unavailable();
        }
        for (String suffix : profile.requiredSanDomains()) {
            boolean found = false;
            for (SubjectAlternativeName name : parsed.subjectAlternativeNames()) {
                if (name instanceof SubjectAlternativeName.DnsName dns && (dns.value().equals(suffix) || dns.value().endsWith("." + suffix))) {
                    found = true;
                }
            }
            if (!found) {
                throw unavailable();
            }
        }
    }

    private CorrelatedEndEntityIssuanceRequest issuance(EnrollmentTransaction value, X509EnrollmentPayload payload) {
        return new CorrelatedEndEntityIssuanceRequest(new EndEntityIssuanceRequest(value.intent().authorityId(), payload,
                value.intent().profile().profileId(), value.intent().validity()), issuanceIntent(value));
    }
    private CorrelatedEndEntityRenewalRequest renewal(EnrollmentTransaction value) {
        return new CorrelatedEndEntityRenewalRequest(value.intent().authorityId(), new EndEntityRenewalRequest(value.intent().predecessorId().orElseThrow(),
                value.intent().validity()), value.intent().predecessorSha256().orElseThrow(), issuanceIntent(value), Optional.of(loadRequest(value)));
    }
    private static zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest replacement(EnrollmentTransaction value,
            X509EnrollmentPayload payload) {
        return new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(value.intent().authorityId(),
                new zeroecho.pki.api.issuance.EndEntityReplacementRequest(value.intent().predecessorId().orElseThrow(),
                        payload, value.intent().profile().profileId()), value.intent().predecessorSha256().orElseThrow(), issuanceIntent(value));
    }
    private static IssuanceIntent issuanceIntent(EnrollmentTransaction value) {
        return new IssuanceIntent(value.id(), value.intentCommitment(), value.intent().profile(), value.intent().issuerId(), value.intent().pathId(), value.intent().pathCommitment());
    }
    private SemanticSigningService signing() { return session.semanticSigning().orElseThrow(EnrollmentCoordinator::unavailable); }
    private zeroecho.pki.api.CertificationRequestService requests() { return session.requests().orElseThrow(EnrollmentCoordinator::unavailable); }
    private void requireRealm(EnrollmentTransaction value) { if (!realm.realmId().equals(value.intent().realmId())) {
        throw unavailable();
    } }
    private void requireOpen() { if (closed || fenced) {
        throw unavailable();
    } }
    private static Instant earlier(Instant first, Instant second) { return first.isBefore(second) ? first : second; }
    private static boolean unaccepted(EnrollmentTransaction.State state) {
        return state == EnrollmentTransaction.State.PENDING || state == EnrollmentTransaction.State.APPROVED
                || state == EnrollmentTransaction.State.DISPATCHING || state == EnrollmentTransaction.State.UNCERTAIN;
    }
    private static boolean contains(Permission.Scope grant, Permission.Scope request) {
        return grant.realmId().equals(request.realmId()) && grant.authorityId().map(value -> request.authorityId().filter(value::equals).isPresent()).orElse(true)
                && grant.issuerId().map(value -> request.issuerId().filter(value::equals).isPresent()).orElse(true)
                && grant.profileId().map(value -> request.profileId().filter(value::equals).isPresent()).orElse(true);
    }
    private static IllegalStateException unavailable() { return new IllegalStateException("Enrollment operation requires reconciliation or policy admission"); }
    private record Selection(EnrollmentTransaction.Source source, PkiId authorityId, String profileId) { }
}
