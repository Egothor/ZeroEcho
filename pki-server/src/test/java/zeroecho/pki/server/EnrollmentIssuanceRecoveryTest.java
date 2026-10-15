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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.server.acme.AcmeControlStore;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.est.KeygenPolicy;
import zeroecho.pkix.Pkix;

/** Real domain completion and signature verification across lost acknowledgement and reopen. */
class EnrollmentIssuanceRecoveryTest {
    @TempDir Path directory;

    @Test void approvedIssuanceCompletesOnceAndRetainsCredentialAfterSessionReopen() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                SemanticPreparationFixture real = SemanticPreparationFixture.open(directory.resolve("domain"))) {
            PkiId rootId = await(real.session().semanticSigning().orElseThrow(), real.acceptRoot().operationId()).completedCredentialId().orElseThrow();
            PkiId authority = real.session().repository().credential(rootId).orElseThrow().issuerRef().caId();
            BuiltInCertificateProfileTemplate leaf = BuiltInCertificateProfileCatalog.load(getClass().getClassLoader()).stream()
                    .filter(value -> value.definition().profileId().equals("server-tls")).findFirst().orElseThrow();
            real.session().profiles().importBuiltIn(leaf); real.session().profiles().activateProfile("server-tls", leaf.definition().profileVersion());
            EnrollmentProfileService profiles = new EnrollmentProfileService(opened.store());
            profiles.register(new EnrollmentProfile("policy", "Approved test issuance", EnrollmentProfileState.ACTIVE, "server-tls",
                    Set.of(authority.value()), Optional.of("CN=.*"), List.of("example.test"), true));
            EnrollmentEndpointRegistry endpoints = new EnrollmentEndpointRegistry(opened.store(), profiles);
            endpoints.register(new EstEndpoint("est", authority.value(), "server-tls", "policy", KeygenPolicy.DISABLED));
            ServerRealmConfiguration realm = mock(ServerRealmConfiguration.class);
            when(realm.realmId()).thenReturn(ServerTestSupport.REALM);
            when(realm.authorityExposure()).thenReturn(new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), false));
            when(realm.approvalPolicies()).thenReturn(Map.of(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE,
                    new ApprovalService.Policy("approve", 1, Set.of("approver"), Set.of(), true, Duration.ofMinutes(5), true)));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            EnrollmentRuntime runtime = mock(EnrollmentRuntime.class); when(runtime.configuration()).thenReturn(EnrollmentTestSupport.runtimeConfiguration());
            EnrollmentIdentityAliases aliases = new EnrollmentIdentityAliases(ServerTestSupport.REALM,
                    new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                            List.of(new PkiServerConfiguration.ClientCertificateMapping("admin", "approver", Optional.of("2".repeat(64)), Optional.empty(), Optional.empty())),
                            List.of(), List.of(), Set.of(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0));
            PkiSession wrapped = mock(PkiSession.class, delegatesTo(real.session()));
            SemanticSigningService delegate = real.session().semanticSigning().orElseThrow();
            SemanticSigningService uncertain = mock(SemanticSigningService.class, delegatesTo(delegate));
            AtomicInteger accepts = new AtomicInteger();
            doAnswer(invocation -> {
                accepts.incrementAndGet(); delegate.accept(invocation.getArgument(0, PreparedSemanticSigningRequest.class));
                throw new IllegalStateException("Lost acceptance acknowledgement");
            }).when(uncertain).accept(any());
            when(wrapped.semanticSigning()).thenReturn(Optional.of(uncertain));
            EnrollmentCoordinator.Admission admission = admission();
            EnrollmentTransaction completed;
            try (EnrollmentCoordinator coordinator = new EnrollmentCoordinator(opened.store(), realm, wrapped, endpoints, profiles,
                    new AcmeControlStore(opened.store()), runtime, aliases, ServerTestSupport.CLOCK)) {
                EnrollmentTransaction pending = coordinator.admit(admission);
                assertEquals(EnrollmentTransaction.State.PENDING, pending.state());
                coordinator.decide(pending.id(), pending.commitment(), new AdministrativeDecisionActor("approver", Optional.of(evidence("2"))), ApprovalService.Choice.APPROVE, "Verified subject and key");
                EnrollmentTransaction dispatched = coordinator.dispatch(pending.id());
                await(delegate, dispatched.receipt().orElseThrow().operationId());
                completed = coordinator.dispatch(pending.id());
                assertEquals(EnrollmentTransaction.State.ISSUED, completed.state());
                assertEquals(1, accepts.get());
                verifyCertificate(real.session(), completed.credentialId().orElseThrow(), rootId);
            }
            profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
            real.reopenSession();
            try (EnrollmentCoordinator reopened = new EnrollmentCoordinator(opened.store(), realm, real.session(), endpoints, profiles,
                    new AcmeControlStore(opened.store()), runtime, aliases, ServerTestSupport.CLOCK)) {
                EnrollmentTransaction recovered = reopened.admit(admission);
                assertEquals(completed.credentialId(), recovered.credentialId());
                assertEquals(completed.receipt(), reopened.dispatch(completed.id()).receipt());
                verifyCertificate(real.session(), recovered.credentialId().orElseThrow(), rootId);
                IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.decode(real.session().repository()
                        .credential(recovered.credentialId().orElseThrow()).orElseThrow().attributes()).orElseThrow();
                assertEquals(IssuanceExecutionEvidence.ActorType.EST_CLIENT, evidence.actorType());
                assertEquals(Optional.of(IssuanceExecutionEvidence.AuthorizationPath.APPROVAL), evidence.authorizationPath());
                assertEquals(Optional.of(completed.intentCommitment()), evidence.operationCommitment());
            }
        }
    }

    private static EnrollmentCoordinator.Admission admission() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); KeyPair keys = generator.generateKeyPair();
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, "host.example.test")));
        byte[] csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=host.example.test"), keys.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())).getEncoded();
        CertificateIdentityEvidence evidence = evidence("1");
        EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.EST_CLIENT,
                "est-client", IssuanceExecutionEvidence.Authentication.EST_MTLS, Optional.of(evidence), Optional.of(evidence.canonicalKeySha256()),
                evidence.legacySpkiSha256(), new EnrollmentIdentityAliases.Snapshot(ServerTestSupport.REALM, Set.of()));
        return new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.EST, "est", requester, "a".repeat(64), EnrollmentTransaction.Operation.ISSUE,
                new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, csr), Optional.empty(), Optional.empty());
    }

    private static CertificateIdentityEvidence evidence(String digit) {
        return new CertificateIdentityEvidence(ServerTestSupport.REALM, digit.repeat(64), digit.repeat(64), Set.of(digit.repeat(64)), digit.repeat(64));
    }

    private static SemanticSigningOperation await(SemanticSigningService service, PkiId id) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            SemanticSigningOperation value = service.find(id).orElseThrow();
            if (value.state() != SemanticSigningState.SIGNING && value.state() != SemanticSigningState.PUBLISHING) {
                assertEquals(SemanticSigningState.COMPLETED, value.state()); return value;
            }
            java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
        throw new AssertionError("Signing did not complete");
    }

    private static void verifyCertificate(PkiSession session, PkiId leaf, PkiId root) throws Exception {
        X509Certificate certificate; X509Certificate issuer;
        try (PkiRepositoryContent content = session.repository().openCredential(leaf); java.io.InputStream input = content.openStream()) {
            certificate = Pkix.parseCertificate(input.readNBytes(1_048_576));
        }
        try (PkiRepositoryContent content = session.repository().openCredential(root); java.io.InputStream input = content.openStream()) {
            issuer = Pkix.parseCertificate(input.readNBytes(1_048_576));
        }
        certificate.verify(issuer.getPublicKey());
        assertTrue(certificate.getSubjectX500Principal().getName().contains("host.example.test"));
    }
}
