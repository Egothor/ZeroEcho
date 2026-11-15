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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest;
import zeroecho.pki.api.profile.*;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.Pkix;

/** Real managed-key issuance proves canonical replay, changed-target rejection and restart-safe renewal. */
final class ManagedOcspResponderIssuanceTest {
    @Test void managedResponderRetainsOneCanonicalIssuanceAndExplicitRenewalAcrossRestart(@TempDir Path root) throws Exception {
        var mode = new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                HybridIssuanceFixture.key("alt").value());
        var fixture = new HybridIssuanceFixture(root, "EC384", "ECDSA", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                mode, "EC384", "ML-DSA-87");
        ManagedOcspResponderIssuanceRequest request;
        PkiId firstOperation;
        PkiId firstCredential;
        PkiId cancelledOperation;
        ManagedOcspResponderIssuanceRequest cancelledRequest;
        Duration horizon;
        try (var session = fixture.open()) {
            PkiId authority = fixture.create(session);
            var base = CertificateProfileDocumentCodec.parse(zeroecho.pki.testkit.H7ProfileDocuments.noSanOrEkuProfile());
            var leaf = base.leafPolicy();
            var profile = new CertificateProfileDefinition(CertificateProfileKind.END_ENTITY, "dedicated-responder", 1,
                    HybridIssuanceFixture.X509, "Dedicated responder", Duration.ofDays(1), IssuanceApprovalRequirement.NONE,
                    new SubjectPolicy(false, List.of(new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true))),
                    new LeafCertificatePolicy(leaf.subjectAlternativeNamePolicy(), Set.of(LeafKeyUsage.DIGITAL_SIGNATURE),
                            Set.of(new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.9")), true, false, true, Set.of("ECDSA")),
                    X509AlgorithmBindingPolicy.standardOnly(), base.confirmationPolicy(),
                    new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                            HybridIssuanceFixture.key("rotated-alt").value()));
            var reference = RootCreationFixture.install(fixture.store, profile);
            var ca = fixture.store.getCa(authority).orElseThrow();
            var path = fixture.store.listIssuerChainPaths(ca.currentIssuanceIssuerId()).getFirst();
            request = new ManagedOcspResponderIssuanceRequest(authority, HybridIssuanceFixture.key("rotated"),
                    HybridIssuanceFixture.key("rotated-alt"), List.of(new SubjectRdn(SubjectRdnType.COMMON_NAME, "Example OCSP Responder")),
                    new Validity(HybridIssuanceFixture.CLOCK.instant(), HybridIssuanceFixture.CLOCK.instant().plus(Duration.ofHours(12))),
                    new IssuanceIntent("caller-first", "0".repeat(64), reference, path.issuerId(), path.pathId(), path.pathCommitment()));
            var semantic = session.semanticSigning().orElseThrow();
            semantic.validateManagedOcspResponder(RootCreationFixture.ACCESS, request, Optional.empty(), CancellationSignal.NONE);
            var first = assertInstanceOf(CorrelatedIssuancePreparation.Prepared.class,
                    semantic.prepareManagedOcspResponder(RootCreationFixture.ACCESS, request, Optional.empty(), CancellationSignal.NONE));
            var competing = assertInstanceOf(CorrelatedIssuancePreparation.Prepared.class,
                    semantic.prepareManagedOcspResponder(RootCreationFixture.ACCESS, withCaller(request, "caller-competing"), Optional.empty(), CancellationSignal.NONE));
            var accepted = semantic.accept(first.prepared());
            var attached = semantic.accept(competing.prepared());
            assertEquals(accepted.receipt(), attached.receipt());
            firstOperation = accepted.receipt().operationId();
            session.localSigning().orElseThrow().complete(firstOperation, CancellationSignal.NONE);
            var completed = await(semantic, firstOperation, fixture);
            assertEquals(SemanticSigningState.COMPLETED, completed.state(), () -> completed.detailCode().toString());
            firstCredential = new PkiId("x509:" + zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(completed.result().orElseThrow().bytes()).sha256());
            var certificate = fixture.certificate(firstCredential);
            certificate.verify(fixture.rootKey.getPublic(), "BC");
            assertTrue(Pkix.verifyAlternativeSignatureCor3(certificate, fixture.altKey.getPublic()));
            assertArrayEquals(fixture.rotatedKey.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertArrayEquals(fixture.rotatedAltKey.getPublic().getEncoded(), zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate, "2.5.29.72"));
            var repeated = assertInstanceOf(CorrelatedIssuancePreparation.Existing.class,
                    semantic.prepareManagedOcspResponder(RootCreationFixture.ACCESS, withCaller(request, "caller-new"), Optional.empty(), CancellationSignal.NONE));
            assertEquals(firstOperation, repeated.operation().submissionId().id());
            var changed = new ManagedOcspResponderIssuanceRequest(request.authorityId(), request.primaryKeyRef(), request.alternativeKeyRef(),
                    request.subject(), new Validity(request.validity().notBefore(), request.validity().notAfter().plusSeconds(1)), request.intent());
            assertThrows(RuntimeException.class, () -> semantic.prepareManagedOcspResponder(RootCreationFixture.ACCESS, changed, Optional.empty(), CancellationSignal.NONE));
        }
        try (var session = fixture.open()) {
            var semantic = session.semanticSigning().orElseThrow();
            assertEquals(firstOperation, semantic.findManagedOcspResponder(withCaller(request, "after-restart")).orElseThrow().submissionId().id());
            var renewal = new ManagedOcspResponderIssuanceRequest(request.authorityId(), request.primaryKeyRef(), request.alternativeKeyRef(),
                    request.subject(), new Validity(request.validity().notBefore(), request.validity().notAfter().plusSeconds(60)), request.intent(), Optional.of(firstCredential));
            var prepared = assertInstanceOf(CorrelatedIssuancePreparation.Prepared.class,
                    semantic.prepareManagedOcspResponder(RootCreationFixture.ACCESS, renewal, Optional.empty(), CancellationSignal.NONE));
            var accepted = semantic.accept(prepared.prepared());
            assertNotEquals(firstOperation, accepted.receipt().operationId());
            session.localSigning().orElseThrow().complete(accepted.receipt().operationId(), CancellationSignal.NONE);
            assertEquals(SemanticSigningState.COMPLETED, await(semantic, accepted.receipt().operationId(), fixture).state());
            assertEquals(accepted.receipt().operationId(), semantic.findManagedOcspResponder(withCaller(renewal, "renewal-again")).orElseThrow().submissionId().id());
            cancelledRequest = new ManagedOcspResponderIssuanceRequest(request.authorityId(), HybridIssuanceFixture.key("child"),
                    request.alternativeKeyRef(), request.subject(), request.validity(), request.intent());
            var pending = assertInstanceOf(CorrelatedIssuancePreparation.Prepared.class,
                    semantic.prepareManagedOcspResponder(RootCreationFixture.ACCESS, cancelledRequest, Optional.empty(), CancellationSignal.NONE));
            cancelledOperation = semantic.accept(pending.prepared()).receipt().operationId();
            semantic.cancel(cancelledOperation);
            session.localSigning().orElseThrow().complete(cancelledOperation, CancellationSignal.NONE);
            assertEquals(SemanticSigningState.FAILED, await(semantic, cancelledOperation, fixture).state());
            assertTrue(fixture.store.getDomainContinuation(cancelledOperation).orElseThrow().result().isEmpty());
            horizon = fixture.store.signingHorizon();
        }
        fixture.clock = java.time.Clock.offset(HybridIssuanceFixture.CLOCK, horizon.plusSeconds(60));
        try (var session = fixture.open()) {
            fixture.store.purgeExpiredSignRecords();
            var semantic = session.semanticSigning().orElseThrow();
            assertEquals(firstOperation, semantic.findManagedOcspResponder(request).orElseThrow().submissionId().id());
            var failed = assertInstanceOf(CorrelatedIssuancePreparation.Existing.class,
                    semantic.prepareManagedOcspResponder(RootCreationFixture.ACCESS, withCaller(cancelledRequest, "cancelled-retry"),
                            Optional.empty(), CancellationSignal.NONE));
            assertEquals(cancelledOperation, failed.operation().submissionId().id());
            assertEquals(SemanticSigningState.FAILED, failed.operation().state());
            assertEquals(cancelledOperation, semantic.findManagedOcspResponderReceipt(cancelledRequest).orElseThrow().operationId());
        }
    }

    private static ManagedOcspResponderIssuanceRequest withCaller(ManagedOcspResponderIssuanceRequest request, String caller) {
        var prior = request.intent();
        return new ManagedOcspResponderIssuanceRequest(request.authorityId(), request.primaryKeyRef(), request.alternativeKeyRef(), request.subject(),
                request.validity(), new IssuanceIntent(caller, "a".repeat(64), prior.expectedProfile(), prior.expectedIssuerId(),
                        prior.expectedChainPathId(), prior.expectedChainPathCommitment()), request.expectedPredecessorCredentialId());
    }

    private static SemanticSigningOperation await(SemanticSigningService service, PkiId id, HybridIssuanceFixture fixture) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            var operation = service.find(id).orElseThrow();
            if (operation.state() != SemanticSigningState.SIGNING && operation.state() != SemanticSigningState.PUBLISHING) return operation;
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
        var workflow = fixture.store.getSignWorkflow(id).orElseThrow();
        var domain = fixture.store.getDomainContinuation(id).orElseThrow();
        throw new AssertionError("Managed responder issuance did not complete: workflow=" + workflow.state() + "/" + workflow.stage()
                + "; detail=" + workflow.detailCode() + "; reconciliation=" + workflow.reconciliationFailureClass()
                + "; domain=" + domain.state() + "/" + domain.detailCode());
    }
}
