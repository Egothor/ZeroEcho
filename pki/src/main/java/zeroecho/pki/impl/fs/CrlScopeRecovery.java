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

package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Startup proof of permanent claims against retained acceptance commands.
 * Streams claims and stores workflow expectations in temporary disk indexes.
 * Heap retains one bounded workflow at a time. Terminal
 * commands are checked without reopening deleted signing content or applying
 * current preparation policy. Orphan claims remain consumed authority. Each
 * scope owner must have its valid counter and vice versa; this pair proof uses
 * streaming scans and point reads without retaining a scope-population map or
 * reconstructing counters from configuration or published status objects.
 */
final class CrlScopeRecovery {
    private static final String CREATE_ROOT = "CREATE_ROOT";

    private CrlScopeRecovery() { }

    /* default */ static void validate(FilesystemPkiStore store, CrlScopeReservationStore reservations) throws IOException {
        try (zeroecho.pki.spi.store.TemporaryUniqueIndex pending = store.stagedContent().beginUniqueIndex();
                zeroecho.pki.spi.store.TemporaryUniqueIndex children = store.stagedContent().beginUniqueIndex();
                zeroecho.pki.spi.store.MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
            long[] pendingCount = { 0L };
            long[] childCount = { 0L };
            store.visitSnapshotSigningWorkflows(snapshot, workflow -> {
                if (workflow.envelope().outer().isEmpty()) { return; }
                SignWorkflowStore.OuterCommand outer = workflow.envelope().outer().orElseThrow();
                if (outer.kind() == DomainContinuationStore.Kind.STATUS
                        || outer.kind() == DomainContinuationStore.Kind.KEY_PROOF) { return; }
                DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command());
                if (outer.kind() == DomainContinuationStore.Kind.CA && !"x509".equals(command.field(0))) { return; }
                DomainContinuationStore.Record domain = store.getDomainContinuation(workflow.operationId())
                        .orElseThrow(() -> invalid("Accepted certificate continuation is missing"));
                require(domain.kind() == outer.kind() && domain.commandCommitment().equals(outer.commandCommitment()),
                        "Accepted certificate continuation differs from its envelope");
                if (pending.add(operationKey(workflow.operationId()))) { pendingCount[0]++; }
                if (outer.kind() == DomainContinuationStore.Kind.CA && !root(command)
                        && children.add(childKey(command.field(2), retainedSubject(store, workflow, domain, command), command.field(17)))) {
                    childCount[0]++;
                }
            });
            reservations.validateAuthority(owner -> {
                if (children.remove(childKey(owner.authorityId().value(), owner.scope().canonicalIssuerName(),
                        sha256(owner.scope().subjectPublicKeyInfoDer())))) { childCount[0]--; }
            }, (owner, reservation) -> {
                if (reservation.issuanceOwner() instanceof ScopeSerialReservation.SigningOwner signing) {
                    byte[] key = operationKey(signing.operationId());
                    if (pending.contains(key)) {
                        SignWorkflowStore.Workflow workflow = store.recoverySigningWorkflow(signing.operationId())
                                .orElseThrow(() -> invalid("Accepted signing workflow is missing"));
                        validateCommand(store, workflow, owner, reservation, signing);
                        pendingCount[0] -= pending.remove(key) ? 1 : 0;
                    } else if (store.recoverySigningWorkflow(signing.operationId()).isPresent()) {
                        throw invalid("Serial reservation has no matching retained certificate command");
                    } else if (store.getDomainContinuation(signing.operationId()).isPresent()) {
                        throw invalid("Retained certificate continuation has no signing envelope");
                    }
                }
            });
            require(pendingCount[0] == 0, "Accepted certificate serial reservation is missing");
            require(childCount[0] == 0, "Accepted intermediate subject scope owner is missing");
        }
    }

    private static byte[] operationKey(PkiId operationId) {
        return operationId.value().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // Older CREATE commands froze the BC display string instead of RFC 2253.
    // Recover the name from committed DER, never by trying two unrelated scope owners.
    private static String retainedSubject(FilesystemPkiStore store, SignWorkflowStore.Workflow workflow,
            DomainContinuationStore.Record domain, DomainCommandEncoding.Decoded command) throws IOException {
        if (domain.result().isEmpty() && domain.signingContent().isEmpty()) {
            // Failed/expired legacy commands without retained DER cannot be reinterpreted.
            return name(command.field(10));
        }
        try {
            RetainedCertificate retained = retainedCertificate(store, workflow, domain, command);
            java.security.cert.X509Certificate certificate = retained.certificate();
            byte[] tbs = retained.tbs();
            require(tbs.length == Long.parseLong(command.field(21))
                    && tbs.length == workflow.envelope().candidate().length()
                    && sha256(tbs).equals(command.field(22))
                    && sha256(tbs).equals(workflow.envelope().candidate().sha256())
                    && sha256(zeroecho.pkix.Pkix.subjectPublicKeyInfo(certificate)).equals(command.field(17))
                    && certificate.getSerialNumber().equals(new BigInteger(command.field(13)))
                    && certificate.getNotBefore().toInstant().equals(java.time.Instant.parse(command.field(11)))
                    && certificate.getNotAfter().toInstant().equals(java.time.Instant.parse(command.field(12))),
                    "Retained intermediate candidate commitment differs");
            X500Principal subject = certificate.getSubjectX500Principal();
            String legacy = zeroecho.pkix.Pkix.distinguishedNameString(
                    zeroecho.pkix.Pkix.parseDistinguishedName(subject.getEncoded()));
            require(command.field(10).equals(subject.getName(X500Principal.RFC2253)) || command.field(10).equals(legacy),
                    "Retained intermediate subject differs from its accepted command");
            return subject.getName(X500Principal.CANONICAL);
        } catch (java.security.GeneralSecurityException | IllegalArgumentException malformed) {
            throw invalid("Retained intermediate candidate is invalid"); // NOPMD PreserveStackTrace - Retained provider/command parse details are redacted at this recovery boundary.
        }
    }

    /** Certificate and exact accepted TBS bytes retained for legacy subject reconciliation. */
    private record RetainedCertificate(java.security.cert.X509Certificate certificate, byte[] tbs) { }

    private static RetainedCertificate retainedCertificate(FilesystemPkiStore store,
            SignWorkflowStore.Workflow workflow, DomainContinuationStore.Record domain,
            DomainCommandEncoding.Decoded command) throws IOException, java.security.GeneralSecurityException {
        java.security.cert.X509Certificate certificate;
        byte[] tbs;
        if (domain.result().isPresent()) {
            zeroecho.pki.api.EncodedObject result = domain.result().orElseThrow();
            require(result.encoding() == zeroecho.pki.api.Encoding.DER && result.byteLength() <= 1_048_576,
                    "Retained intermediate certificate is invalid");
            certificate = zeroecho.pkix.Pkix.parseCertificate(result.bytes());
            tbs = certificate.getTBSCertificate();
            require(domain.state() == DomainContinuationStore.State.COMPLETED
                    && (workflow.state() == SignWorkflowStore.State.SUCCEEDED || workflow.state() == SignWorkflowStore.State.RETIRED)
                    && workflow.detailCode().filter("SIGNED"::equals).isPresent()
                    && workflow.result().filter(value -> value.encoding() == zeroecho.pki.api.Encoding.BINARY).isPresent()
                    && java.util.Arrays.equals(result.bytes(), zeroecho.pkix.Pkix.assembleCertificateOrCrl(tbs,
                            workflow.result().orElseThrow().bytes(), false)),
                    "Retained intermediate signature differs from its accepted workflow");
            IssuerGeneration generation = store.getIssuerGeneration(new PkiId(command.field(3)))
                    .orElseThrow(() -> invalid("Retained intermediate issuer is missing"));
            Credential issuer = store.getCredential(generation.credentialId())
                    .orElseThrow(() -> invalid("Retained intermediate issuer credential is missing"));
            java.security.cert.X509Certificate issuerCertificate = store.certificateHolder(issuer);
            require(certificate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal()),
                    "Retained intermediate issuer differs");
        } else {
            try (RepeatableContent content = store.stagedContent().openContent(workflow.envelope().candidate());
                    java.io.InputStream input = content.openStream()) {
                tbs = input.readNBytes(1_048_577);
            }
            require(tbs.length <= 1_048_576, "Retained intermediate candidate exceeds its bound");
            certificate = zeroecho.pkix.Pkix.parseCertificate(
                    zeroecho.pkix.Pkix.assembleCertificateOrCrl(tbs, new byte[]{0}, false));
        }
        return new RetainedCertificate(certificate, tbs);
    }


    private static byte[] childKey(String authority, String canonicalName, String keyCommitment) {
        MessageDigest digest = FsBackupFiles.digest();
        for (String field : new String[] { authority, canonicalName, keyCommitment }) {
            byte[] encoded = field.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            digest.update(java.nio.ByteBuffer.allocate(Integer.BYTES).putInt(encoded.length).array());
            digest.update(encoded);
        }
        return digest.digest();
    }

    private static void validateCommand(FilesystemPkiStore store, SignWorkflowStore.Workflow workflow,
            CrlScopeOwner owner, ScopeSerialReservation reservation, ScopeSerialReservation.SigningOwner signing)
            throws IOException {
        SignWorkflowStore.OuterCommand outer = workflow.envelope().outer().orElseThrow();
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command());
        boolean issuance = outer.kind() == DomainContinuationStore.Kind.ISSUANCE;
        boolean root = !issuance && root(command);
        PkiId authority = new PkiId(command.field(root ? 13 : issuance ? 0 : 1));
        require(outer.commandCommitment().equals("domain:v1:" + signing.commandCommitment())
                && owner.authorityId().equals(authority)
                && workflow.envelope().fairnessAuthorityId().equals(authority)
                && reservation.serial().equals(new BigInteger(command.field(root ? 9 : issuance ? 10 : 13)))
                && workflow.envelope().keyRef().value().equals(command.field(root ? 3 : issuance ? 11 : 14)),
                "Retained signing reservation differs from its accepted command");
        if (root) { validateRootCommand(store, workflow, owner, reservation, command, authority); }
        else { validateIssuerCommand(store, workflow, reservation, command, authority, issuance); }
    }

    private static void validateRetainedRootCandidate(FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceEnvelope envelope, CrlScopeOwner owner,
            ScopeSerialReservation reservation) throws IOException {
        SignWorkflowStore.AcceptanceCommand accepted = new SignWorkflowStore.AcceptanceCommand(
                envelope.operationId(), envelope.providerNamespace(), envelope.providerConfigurationCommitment(),
                envelope.accessContext(), envelope.keyRef(), envelope.fairnessAuthorityId(), envelope.algorithmId(),
                envelope.signatureEncoding(), envelope.createdAt(), envelope.deadline(), envelope.candidate(),
                envelope.outer(), envelope.mode(), envelope.proofStep());
        try (RepeatableContent content = store.stagedContent().openContent(envelope.candidate())) {
            SignAcceptanceCrlScope exact = SignAcceptanceCrlScope.derive(store, accepted, content)
                    .orElseThrow(() -> invalid("Retained root candidate has no certificate scope"));
            require(exact.owners().size() == 1 && exact.owners().getFirst().equals(owner)
                    && exact.reservation().equals(reservation),
                    "Root signing scope differs from its retained accepted candidate");
        }
    }

    private static boolean root(DomainCommandEncoding.Decoded command) {
        return CREATE_ROOT.equals(command.operation()) || "ROLLOVER_ROOT".equals(command.operation());
    }

    private static String name(String name) {
        return new X500Principal(name).getName(X500Principal.CANONICAL);
    }

    private static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static void require(boolean valid, String message) {
        if (!valid) { throw invalid(message); }
    }

    private static IllegalStateException invalid(String message) { return new IllegalStateException(message); }

    private static void validateRootCommand(FilesystemPkiStore store, SignWorkflowStore.Workflow workflow,
            CrlScopeOwner owner, ScopeSerialReservation reservation, DomainCommandEncoding.Decoded command,
            PkiId authority) throws IOException {
        require(reservation.scope().canonicalIssuerName().equals(name(command.field(10))),
                "Root signing scope differs from its accepted subject");
        if (CREATE_ROOT.equals(command.operation())) {
            require(authority.equals(DomainCommandEncoding.rootAuthorityId(workflow.operationId())),
                    "Root signing scope authority differs from its operation");
        }
        if (workflow.state() != SignWorkflowStore.State.RETIRED
                && workflow.state() != SignWorkflowStore.State.EXPIRED) {
            validateRetainedRootCandidate(store, workflow.envelope(), owner, reservation);
        }
    }

    private static void validateIssuerCommand(FilesystemPkiStore store, SignWorkflowStore.Workflow workflow,
            ScopeSerialReservation reservation, DomainCommandEncoding.Decoded command, PkiId authority,
            boolean issuance) throws IOException {
        IssuerGeneration generation = store.getIssuerGeneration(new PkiId(command.field(issuance ? 1 : 3)))
                .orElseThrow(() -> invalid("Accepted certificate issuer generation is missing"));
        Credential issuer = store.getCredential(generation.credentialId())
                .orElseThrow(() -> invalid("Accepted certificate issuer credential is missing"));
        IssuerChainPath path = store.getIssuerChainPath(new PkiId(command.field(issuance ? 2 : 4)))
                .orElseThrow(() -> invalid("Accepted certificate issuer path is missing"));
        java.security.cert.X509Certificate certificate = store.certificateHolder(issuer);
        CrlScope expected = CrlScope.of(certificate.getSubjectX500Principal().getEncoded(),
                certificate.getPublicKey().getEncoded());
        require(generation.authorityId().equals(authority) && reservation.scope().equals(expected)
                && path.authorityId().equals(authority) && path.issuerId().equals(generation.issuerId())
                && path.pathCommitment().equals(command.field(issuance ? 3 : 5))
                && generation.signingKeyRef().equals(workflow.envelope().keyRef())
                && issuer.content().sha256().equals(command.field(issuance ? 13 : 16)),
                "Accepted certificate issuer scope differs");
    }

}
