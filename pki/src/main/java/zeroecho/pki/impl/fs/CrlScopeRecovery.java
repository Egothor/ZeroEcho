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

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
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
 * Streams claims once and retains only O(W) workflow expectations. Terminal
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
        Map<PkiId, SignWorkflowStore.Workflow> pending = new HashMap<>();
        Set<ChildScope> children = new HashSet<>();
        for (SignWorkflowStore.Workflow workflow : store.listSignWorkflows()) {
            if (workflow.envelope().outer().isEmpty()) { continue; }
            SignWorkflowStore.OuterCommand outer = workflow.envelope().outer().orElseThrow();
            if (outer.kind() == DomainContinuationStore.Kind.STATUS
                    || outer.kind() == DomainContinuationStore.Kind.KEY_PROOF) { continue; }
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command());
            if (outer.kind() == DomainContinuationStore.Kind.CA && !"x509".equals(command.field(0))) { continue; }
            DomainContinuationStore.Record domain = store.getDomainContinuation(workflow.operationId())
                    .orElseThrow(() -> invalid("Accepted certificate continuation is missing"));
            require(domain.kind() == outer.kind() && domain.commandCommitment().equals(outer.commandCommitment()),
                    "Accepted certificate continuation differs from its envelope");
            pending.put(workflow.operationId(), workflow);
            if (outer.kind() == DomainContinuationStore.Kind.CA && !root(command)) {
                children.add(new ChildScope(new PkiId(command.field(2)), name(command.field(10)), command.field(17)));
            }
        }
        reservations.validateAuthority(owner -> children.remove(new ChildScope(owner.authorityId(),
                owner.scope().canonicalIssuerName(), sha256(owner.scope().subjectPublicKeyInfoDer()))),
                (owner, reservation) -> {
                    if (reservation.issuanceOwner() instanceof ScopeSerialReservation.SigningOwner signing) {
                        SignWorkflowStore.Workflow workflow = pending.get(signing.operationId());
                        if (workflow != null) {
                            validateCommand(store, workflow, owner, reservation, signing);
                            pending.remove(signing.operationId());
                        } else if (store.getSignWorkflow(signing.operationId()).isPresent()) {
                            throw invalid("Serial reservation has no matching retained certificate command");
                        } else if (store.getDomainContinuation(signing.operationId()).isPresent()) {
                            throw invalid("Retained certificate continuation has no signing envelope");
                        }
                    }
                });
        require(pending.isEmpty(), "Accepted certificate serial reservation is missing");
        require(children.isEmpty(), "Accepted intermediate subject scope owner is missing");
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

    private record ChildScope(PkiId authority, String name, String keyCommitment) { }

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
