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

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Objects;
import java.util.OptionalLong;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pkix.Pkix;

/**
 * Restartable full-CRL projection over exactly one owned revocation snapshot.
 * Each pass independently resolves immutable credential/generation authority,
 * emits only the prepared Name/SPKI scope, and retains one output entry.
 * Traversal is O(R + S*G) for R snapshot records, S same-scope records and G
 * generations in the frozen CA membership list, plus point I/O and bounded
 * certificate parsing. It retains O(G) membership through the existing immutable
 * CA record, with O(1) additional per-record memory and no copied set or cache.
 * Snapshot creation may use the store's bounded-memory external sort.
 *
 * <p>The source and cursors are not thread-safe; callers coordinate their
 * lifecycle and close every cursor, preferably before closing the source.
 * A cursor owns and closes its underlying cursor. Source close is idempotent,
 * closes the snapshot and invalidates every adapter cursor without maintaining
 * a cursor registry. It does not replace the caller's obligation to close
 * cursors. No operation except repeated close is valid after close. A failed
 * cursor cannot resume. Before first advance, after EOF, failure or close,
 * current/ordinal throw IllegalStateException. Ordinals count emitted entries,
 * not filtered snapshot records. Count is unknown without scanning.</p>
 */
final class FullCrlEntrySource implements CrlEntrySource { // NOPMD - CyclomaticComplexity totals independent cohesive operations; method-level checks remain enabled.
    private static final int MAX_SERIAL_BITS = 159;
    private final PkiStore store;
    private final FullCrlPreparation.Prepared prepared;
    private final CancellationSignal cancellation;
    private final RevocationSnapshot snapshot;
    private boolean closed;

    /* default */ // Exceptional cleanup retains ownership and releases resources after failed validation or provider invocation.
                  // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
                  @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl" })
                  FullCrlEntrySource(PkiStore store, FullCrlPreparation.Prepared prepared, CancellationSignal cancellation)
            throws IOException {
        this.store = Objects.requireNonNull(store, "store");
        this.prepared = Objects.requireNonNull(prepared, "prepared");
        this.cancellation = Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancelled();
        this.snapshot = Objects.requireNonNull(store.openRevocationSnapshot(), "revocation snapshot");
        try {
            if (prepared.base().isPresent()) {
                zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance base = prepared.base().orElseThrow().provenance();
                if (!base.sourceStoreId().equals(snapshot.sourceStoreId()) || base.revision() > snapshot.revision()
                        || base.boundary() > snapshot.boundary()
                        || base.revision() == snapshot.revision() && (base.boundary() != snapshot.boundary()
                                || !base.commitment().equals(snapshot.commitment()))) {
                    throw invalid("DELTA_BASE_PREFIX_OUTSIDE_SNAPSHOT");
                }
                store.requireRevocationPrefix(new zeroecho.pki.spi.store.RevocationTransitionFeed.HighWatermark(
                        base.sourceStoreId(), base.revision(), base.commitment()), base.boundary(), cancellation);
            }
            cancellation.throwIfCancelled();
        } catch (IOException | RuntimeException | Error failure) {
            try { snapshot.close(); }
            catch (IOException | RuntimeException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    /* default */ String snapshotId() { requireOpen(); return snapshot.snapshotId(); }
    /* default */ zeroecho.pki.spi.store.MetadataStoreId sourceStoreId() { requireOpen(); return snapshot.sourceStoreId(); }
    /* default */ long revision() { requireOpen(); return snapshot.revision(); }
    /* default */ long boundary() { requireOpen(); return snapshot.boundary(); }
    /* default */ String commitment() { requireOpen(); return snapshot.commitment(); }
    /* default */ OptionalLong rawCount() { requireOpen(); return snapshot.count(); }

    @Override public Cursor openCursor() throws IOException {
        requireOpen();
        cancellation.throwIfCancelled();
        return new EntryCursor(snapshot.openCursor());
    }

    @Override public OptionalLong count() { requireOpen(); return OptionalLong.empty(); }

    @Override public void close() throws IOException {
        if (!closed) {
            closed = true;
            snapshot.close();
        }
    }

    private void requireOpen() {
        if (closed) { throw new IllegalStateException("Full CRL entry source is closed"); }
    }

    private CrlEntry project(RevocationRecord record, long globalRevision) throws IOException {
        RevocationTransition transition = record.transition();
        if (transition.time().isAfter(prepared.evaluationTime())) {
            throw invalid("TRANSITION_AFTER_EVALUATION");
        }
        RevocationReason reason = reason(transition);
        Credential credential = store.getCredential(record.credentialId())
                .orElseThrow(() -> invalid("CREDENTIAL_MISSING"));
        requireCredential(record, credential);
        IssuerGeneration generation = store.getIssuerGeneration(credential.issuerRef().issuerId())
                .orElseThrow(() -> invalid("GENERATION_MISSING"));
        requireGeneration(credential, generation);
        Credential issuer = store.getCredential(generation.credentialId())
                .orElseThrow(() -> invalid("ISSUER_CREDENTIAL_MISSING"));
        requireIssuer(generation, issuer);
        BigInteger serial = serial(credential.serialOrUniqueId());
        CrlScope scope = scope(issuer);
        if (!scope.equals(prepared.scope())) { return null; }
        if (!generation.authorityId().equals(prepared.authorityId())
                || !prepared.authority().issuerIds().contains(generation.issuerId())) {
            throw invalid("SCOPE_AUTHORITY_INCONSISTENT");
        }
        if (globalRevision <= 0 || globalRevision > snapshot.revision()) { throw invalid("GLOBAL_REVISION_OUTSIDE_SNAPSHOT"); }
        if (prepared.base().isPresent()) {
            if (globalRevision <= prepared.base().orElseThrow().provenance().revision()) { return null; }
            if (reason == null) { reason = RevocationReason.REMOVE_FROM_CRL; }
        }
        if (reason == null) { return null; }
        return new CrlEntry(serial, transition.time(), reason);
    }

    private static void requireCredential(RevocationRecord record, Credential credential) throws IOException {
        if (!record.credentialId().equals(credential.credentialId())
                || !credential.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) {
            throw invalid("CREDENTIAL_BINDING_INCONSISTENT");
        }
    }

    private static void requireGeneration(Credential credential, IssuerGeneration generation) throws IOException {
        if (!credential.issuerRef().issuerId().equals(generation.issuerId())
                || !credential.issuerRef().caId().equals(generation.authorityId())
                || !generation.issuerId().equals(IssuerGeneration.idFor(generation.authorityId(), generation.credentialId()))) {
            throw invalid("GENERATION_BINDING_INCONSISTENT");
        }
    }

    private void requireIssuer(IssuerGeneration generation, Credential issuer) throws IOException {
        if (!generation.credentialId().equals(issuer.credentialId())
                || !issuer.formatId().equals(BcX509CredentialFramework.FORMAT_ID)
                || !(issuer.profileBinding() instanceof CaProfileBinding profile)) {
            throw invalid("ISSUER_BINDING_INCONSISTENT");
        }
        String profileCommitment = HexFormat.of().formatHex(profile.reference().canonicalSha256());
        if (!generation.profilePolicyCommitment().equals(profileCommitment)
                || !generation.x509BindingCommitment().equals(profileCommitment)) {
            throw invalid("ISSUER_PROFILE_INCONSISTENT");
        }
        if (generation.issuerId().equals(prepared.generation().issuerId())
                && (!generation.equals(prepared.generation()) || !issuer.credentialId().equals(prepared.credentialId())
                        || !issuer.content().equals(prepared.issuerContent()))) {
            throw invalid("PREPARED_ISSUER_CHANGED");
        }
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private CrlScope scope(Credential issuer) throws IOException {
        try {
            byte[] der = CredentialContent.materializeForBc(store, issuer.content());
            if (!HexFormat.of().formatHex(sha256(der)).equals(issuer.content().sha256())) {
                throw invalid("ISSUER_COMMITMENT_MISMATCH");
            }
            new StreamingDerReader().validate(der, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
            X509Certificate certificate = Pkix.parseCertificate(der);
            if (certificate.getBasicConstraints() < 0
                    || !certificate.getSubjectX500Principal().equals(new X500Principal(issuer.subjectRef().value()))
                    || !certificate.getSerialNumber().equals(serial(issuer.serialOrUniqueId()))
                    || !certificate.getNotBefore().toInstant().equals(issuer.validity().notBefore())
                    || !certificate.getNotAfter().toInstant().equals(issuer.validity().notAfter())) {
                throw invalid("ISSUER_CERTIFICATE_INCONSISTENT");
            }
            // Historical issuers need not still be valid or enabled to contribute revocations.
            return CrlScope.of(certificate.getSubjectX500Principal().getEncoded(), Pkix.subjectPublicKeyInfo(certificate));
        } catch (IllegalArgumentException | PkiException malformed) {
            throw invalid("ISSUER_CONTENT_INVALID");
        }
    }

    private static BigInteger serial(String encoded) throws IOException {
        // Existing X.509 ingress admits only positive serials of at most 159 bits.
        if (encoded.isEmpty() || encoded.length() > 48 || encoded.charAt(0) < '1' || encoded.charAt(0) > '9') {
            throw invalid("SERIAL_INVALID");
        }
        for (int index = 1; index < encoded.length(); index++) {
            char digit = encoded.charAt(index);
            if (digit < '0' || digit > '9') { throw invalid("SERIAL_INVALID"); }
        }
        BigInteger serial = new BigInteger(encoded);
        if (serial.bitLength() > MAX_SERIAL_BITS) { throw invalid("SERIAL_INVALID"); }
        return serial;
    }

    private static RevocationReason reason(RevocationTransition transition) throws IOException {
        if (transition.permanentReason().orElse(null) == RevocationReason.REMOVE_FROM_CRL) {
            throw invalid("CURRENT_STATE_REMOVE_REASON_INVALID");
        }
        if (transition.state() == RevocationState.PERMANENTLY_REVOKED) {
            RevocationReason reason = transition.permanentReason().orElseThrow(() -> invalid("PERMANENT_REASON_MISSING"));
            if (reason == RevocationReason.CERTIFICATE_HOLD) { throw invalid("PERMANENT_REASON_INVALID"); }
            return reason;
        }
        if (transition.permanentReason().isPresent()) { throw invalid("NONPERMANENT_REASON_INVALID"); }
        return transition.state() == RevocationState.HELD ? RevocationReason.CERTIFICATE_HOLD : null;
    }

    private static byte[] sha256(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static IOException invalid(String code) { return new IOException("Full CRL entry rejected: code=" + code); }

    /** Validates each frozen revocation entry before exposing it to the CRL writer. */
    private final class EntryCursor implements Cursor {
        private final RevocationSnapshot.Cursor cursor;
        private CrlEntry current;
        private long ordinal = -1;
        private boolean exhausted;
        private boolean failed;
        private boolean cursorClosed;

        private EntryCursor(RevocationSnapshot.Cursor cursor) { this.cursor = Objects.requireNonNull(cursor, "cursor"); }

        // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
        @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
        @Override public boolean next() throws IOException {
            requireUsable();
            current = null; // NOPMD - UnusedAssignment: current() must reject access after exhaustion or filtered-empty input.
            try {
                cancellation.throwIfCancelled();
                if (exhausted) { return false; }
                while (cursor.next(cancellation)) {
                    CrlEntry entry = project(cursor.current(), cursor.currentGlobalRevision());
                    cancellation.throwIfCancelled();
                    if (entry != null) {
                        ordinal = Math.incrementExact(ordinal);
                        current = entry;
                        return true;
                    }
                }
                exhausted = true;
                return false;
            } catch (IOException | RuntimeException failure) {
                failed = true;
                throw failure;
            }
        }

        @Override public CrlEntry current() { requirePositioned(); return current; }
        @Override public long ordinal() { requirePositioned(); return ordinal; }

        @Override public void close() throws IOException {
            if (!cursorClosed) {
                cursorClosed = true;
                current = null;
                cursor.close();
            }
        }

        private void requireUsable() {
            requireOpen();
            if (cursorClosed || failed) { throw new IllegalStateException("Full CRL cursor is closed or failed"); }
        }

        private void requirePositioned() {
            requireUsable();
            if (current == null) { throw new IllegalStateException("Full CRL cursor is not positioned"); }
        }
    }
}
