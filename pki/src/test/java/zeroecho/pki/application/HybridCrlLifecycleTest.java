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
import static zeroecho.core.io.CancellationSignal.NONE;
import static zeroecho.pki.application.HybridIssuanceFixture.X509;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRotationSelection;
import zeroecho.pki.api.ca.RootTrustAnchorActivation;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand;
import zeroecho.pki.testkit.RootCreationFixture;

/**
 * Native filesystem/local-provider integration; trusted decisions here do not exercise HTTP approval.
 */
final class HybridCrlLifecycleTest {
    private static final String ALT = BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm();
    private static final String RSA = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm();
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "hybrid-crl"),
            new Purpose("STATUS_GENERATE"), Optional.empty(), Optional.empty());

    /**
     * Revocation full delta and download representations survive reopen.
     *
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void revocationFullDeltaAndDownloadRepresentationsSurviveReopen(@TempDir Path directory) throws Exception {
        var fixture = fixture(directory);
        PkiId fullId;
        PkiId deltaId;
        BigInteger serial;
        try (var session = fixture.open()) {
            var ca = fixture.create(session);
            var leaf = fixture.issueLeaf(session, ca);
            serial = fixture.certificate(leaf).getSerialNumber();
            var full = generate(fixture, session, ca, false, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            fullId = full.id();
            assertNull(full.crl().getRevokedCertificate(serial));
            // Native trusted component command; HTTP administrator evidence is outside this test.
            session.revocations().revokePermanently(new zeroecho.pki.api.revocation.RevocationCommand.RevokePermanently(
                    leaf, RevocationReason.KEY_COMPROMISE, new zeroecho.pki.impl.core.attr.SimpleAttributeSet()));
            var delta = generate(fixture, session, ca, true, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            deltaId = delta.id();
            assertEquals(full.number(), delta.base());
            assertEquals(fullId.value(), attribute(session, deltaId, CrlHybridSigningCommand.BASE_STATUS_ID));
            assertEquals(java.security.cert.CRLReason.KEY_COMPROMISE,
                    delta.crl().getRevokedCertificate(serial).getRevocationReason());
            var after = generate(fixture, session, ca, false, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            assertNotNull(after.crl().getRevokedCertificate(serial));
            assertTrue(after.number().compareTo(delta.number()) > 0);
        }
        try (var reopened = fixture.open()) {
            var full = read(reopened, fullId, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            var delta = read(reopened, deltaId, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            assertEquals(full.number(), delta.base());
            assertNotNull(delta.crl().getRevokedCertificate(serial));
        }
    }

    /**
     * Alternative rotation same key rollover and new a2 respect historical lineage.
     *
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void alternativeRotationSameKeyRolloverAndNewA2RespectHistoricalLineage(@TempDir Path directory) throws Exception {
        var fixture = fixture(directory);
        try (var session = fixture.open()) {
            var ca = fixture.create(session);
            var oldA = generation(fixture, ca);
            var fullA = generate(fixture, session, ca, false, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            var sameKeys = explicit(session, generation(fixture, ca), true, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            assertEquals(fullA.number(), sameKeys.base());
            assertEquals(attribute(session, fullA.id(), CrlHybridSigningCommand.SIGNER_LINEAGE),
                    attribute(session, sameKeys.id(), CrlHybridSigningCommand.SIGNER_LINEAGE));
            rotate(fixture, session, ca, Optional.empty(), Optional.of(change("rotated-alt", ALT)));
            requireNewFull(session, generation(fixture, ca));
            var fullB = generate(fixture, session, ca, false, fixture.rootKey.getPublic(), fixture.rotatedAltKey.getPublic());
            var deltaB = generate(fixture, session, ca, true, fixture.rootKey.getPublic(), fixture.rotatedAltKey.getPublic());
            assertEquals(fullB.number(), deltaB.base());
            assertTrue(fullB.number().compareTo(sameKeys.number()) > 0);
            assertNotEquals(attribute(session, fullA.id(), CrlHybridSigningCommand.SIGNER_LINEAGE),
                    attribute(session, fullB.id(), CrlHybridSigningCommand.SIGNER_LINEAGE));
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            var retainedB = fixture.certificate(fixture.current(ca));
            retainedB.verify(fixture.rootKey.getPublic(), "BC");
            assertTrue(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(retainedB, fixture.rotatedAltKey.getPublic()));
            assertArrayEquals(fixture.rotatedAltKey.getPublic().getEncoded(),
                    zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(retainedB,
                            zeroecho.pki.impl.hybrid.AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO));
            var rolledB = explicit(session, generation(fixture, ca), true,
                    fixture.rootKey.getPublic(), fixture.rotatedAltKey.getPublic());
            assertEquals(fullB.id().value(), attribute(session, rolledB.id(), CrlHybridSigningCommand.BASE_STATUS_ID));
            assertEquals(fullB.number(), rolledB.base());
            assertEquals(attribute(session, fullB.id(), CrlHybridSigningCommand.SIGNER_LINEAGE),
                    attribute(session, rolledB.id(), CrlHybridSigningCommand.SIGNER_LINEAGE));
            rotate(fixture, session, ca, Optional.empty(), Optional.of(change("alt", ALT)));
            requireNewFull(session, generation(fixture, ca));
            var newA = generate(fixture, session, ca, false, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            assertTrue(newA.number().compareTo(rolledB.number()) > 0);
            assertNotEquals(attribute(session, fullA.id(), CrlHybridSigningCommand.SIGNER_LINEAGE),
                    attribute(session, newA.id(), CrlHybridSigningCommand.SIGNER_LINEAGE));
            var historical = explicit(session, oldA, true, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            assertEquals(fullA.id().value(), attribute(session, historical.id(), CrlHybridSigningCommand.BASE_STATUS_ID));
            assertEquals(fullA.number(), historical.base());
        }
    }

    /**
     * Primary and both role rotations require their own full base.
     *
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void primaryAndBothRoleRotationsRequireTheirOwnFullBase(@TempDir Path directory) throws Exception {
        for (boolean both : new boolean[] {false, true}) {
            var fixture = fixture(directory.resolve(both ? "both" : "primary"));
            try (var session = fixture.open()) {
                var ca = fixture.create(session);
                var old = generate(fixture, session, ca, false, fixture.rootKey.getPublic(), fixture.altKey.getPublic());
                RootCreationFixture.install(fixture.store, fixture.profile("matrix-root", 2,
                        CertificateProfileKind.ROOT_CA, fixture.mode, Set.of("ECDSA", "RSA")));
                rotate(fixture, session, ca, Optional.of(change("child", RSA)),
                        both ? Optional.of(change("rotated-alt", ALT)) : Optional.empty());
                requireNewFull(session, generation(fixture, ca));
                PublicKey alternative = both ? fixture.rotatedAltKey.getPublic() : fixture.altKey.getPublic();
                var full = generate(fixture, session, ca, false, fixture.childKey.getPublic(), alternative);
                var delta = generate(fixture, session, ca, true, fixture.childKey.getPublic(), alternative);
                assertEquals("1.2.840.113549.1.1.12", full.crl().getSigAlgOID());
                assertEquals(full.number(), delta.base());
                read(session, old.id(), fixture.rootKey.getPublic(), fixture.altKey.getPublic());
            }
        }
    }

    /**
     * Intermediate CRL uses outgoing RSA and alternative keys rather than parent keys.
     *
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void intermediateCrlUsesOutgoingRsaAndAlternativeKeysRatherThanParentKeys(@TempDir Path directory) throws Exception {
        var fixture = fixture(directory);
        try (var session = fixture.open()) {
            var root = fixture.create(session);
            RootCreationFixture.install(fixture.store, fixture.profile("crl-child", 1,
                    CertificateProfileKind.INTERMEDIATE_CA,
                    new HybridCertificateMode.AltSignature(ALT, HybridIssuanceFixture.key("rotated-alt").value()),
                    Set.of("RSA")));
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(X509, root,
                    new SubjectRef("CN=Hybrid CRL Child,C=CZ"), "crl-child",
                    Optional.of(HybridIssuanceFixture.key("child")), Optional.of(RSA)));
            var child = fixture.store.listCas().stream().filter(ca -> !ca.caId().equals(root)).findFirst().orElseThrow().caId();
            var childCertificate = fixture.certificate(fixture.current(child));
            childCertificate.verify(fixture.rootKey.getPublic(), "BC");
            assertTrue(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(childCertificate, fixture.altKey.getPublic()));
            var full = generate(fixture, session, child, false, fixture.childKey.getPublic(), fixture.rotatedAltKey.getPublic());
            var delta = generate(fixture, session, child, true, fixture.childKey.getPublic(), fixture.rotatedAltKey.getPublic());
            assertEquals("1.2.840.113549.1.1.12", full.crl().getSigAlgOID());
            assertEquals(full.number(), delta.base());
            assertFalse(new X509CRLHolder(full.crl().getEncoded()).isAlternativeSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider("BC").build(fixture.altKey.getPublic())));
        }
    }

    private static HybridIssuanceFixture fixture(Path directory) throws Exception {
        return new HybridIssuanceFixture(directory, "EC384", "ECDSA",
                BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                new HybridCertificateMode.AltSignature(ALT, HybridIssuanceFixture.key("alt").value()), "RSA4096", "ML-DSA-87");
    }

    private static PkiId generation(HybridIssuanceFixture fixture, PkiId ca) {
        return fixture.store.getCa(ca).orElseThrow().currentIssuanceIssuerId();
    }

    private static CaRotationSelection.RoleChange change(String key, String algorithm) {
        return new CaRotationSelection.RoleChange(Optional.of(HybridIssuanceFixture.key(key)), Optional.of(algorithm));
    }

    private static void rotate(HybridIssuanceFixture fixture, PkiSession session, PkiId ca,
            Optional<CaRotationSelection.RoleChange> primary, Optional<CaRotationSelection.RoleChange> alternative) {
        var head = fixture.store.getCaHeadSnapshot(ca).orElseThrow();
        var semantic = session.semanticSigning().orElseThrow();
        var command = semantic.normalizeCaKeyRotation(new zeroecho.pki.api.ca.CaKeyRotationCommand.Root(ca,
                new CaRotationSelection(1, primary, alternative), Optional.of(head),
                new zeroecho.pki.impl.core.attr.SimpleAttributeSet()));
        var accepted = semantic.accept(semantic.prepareCaKeyRotation(ACCESS, command, NONE));
        var observation = session.localSigning().orElseThrow().complete(accepted.receipt().operationId(), NONE);
        var result = assertInstanceOf(LocalSigningResult.Completed.class, observation,
                () -> fixture.failureDescription(observation));
        assertEquals("PENDING_ACTIVATION", text(result.result().fields().get("activationState")));
        assertEquals(head, fixture.store.getCaHeadSnapshot(ca).orElseThrow());
        var transition = fixture.store.getRootTrustAnchorTransitionForIssuer(
                fixture.store.getCa(ca).orElseThrow().issuerIds().getLast()).orElseThrow();
        // A trusted native decision exercises activation fences, not HTTP administrator approval.
        var activation = new RootTrustAnchorActivation(1, transition.transitionId(), transition.commitment(), head,
                transition.candidateIssuerId(), transition.candidatePathId(), head.epoch() + 1,
                new PkiId("crl-activation-" + head.epoch()), "crl-test", "a".repeat(64), "b".repeat(64),
                fixture.store.signingNow(), true);
        fixture.store.activateRootCandidate(transition.transitionId(), head, activation);
    }

    private static void requireNewFull(PkiSession session, PkiId issuer) {
        var error = assertThrows(zeroecho.pki.api.PkiException.class, () -> session.semanticSigning().orElseThrow()
                .prepareDeltaCrl(ACCESS, new DeltaCrlRequest(issuer, Duration.ofHours(1)), NONE));
        assertTrue(error.getMessage().contains("DELTA_BASE_NEW_FULL_REQUIRED"), error::getMessage);
    }

    private static Crl generate(HybridIssuanceFixture fixture, PkiSession session, PkiId ca,
            boolean delta, PublicKey primary, PublicKey alternative) throws Exception {
        var result = fixture.execute(session, new PkiSigningOperation.GenerateStatus(ca,
                delta ? StatusObjectType.DELTA_CRL : StatusObjectType.CRL, X509));
        var id = new PkiId(text(result.result().fields().get("statusObjectId")));
        var repeated = assertInstanceOf(LocalSigningResult.Completed.class,
                session.localSigning().orElseThrow().complete(result.receipt().operationId(), NONE));
        assertEquals(id.value(), text(repeated.result().fields().get("statusObjectId")));
        return read(session, id, primary, alternative);
    }

    private static Crl explicit(PkiSession session, PkiId issuer, boolean delta,
            PublicKey primary, PublicKey alternative) throws Exception {
        var service = session.semanticSigning().orElseThrow();
        var prepared = delta ? service.prepareDeltaCrl(ACCESS, new DeltaCrlRequest(issuer, Duration.ofHours(1)), NONE)
                : service.prepareFullCrl(ACCESS, new FullCrlRequest(issuer, Duration.ofHours(1)), NONE);
        var accepted = service.accept(prepared);
        var completed = assertInstanceOf(LocalSigningResult.Completed.class,
                session.localSigning().orElseThrow().complete(accepted.receipt().operationId(), NONE));
        return read(session, new PkiId(text(completed.result().fields().get("statusObjectId"))), primary, alternative);
    }

    private static Crl read(PkiSession session, PkiId id, PublicKey primary, PublicKey alternative) throws Exception {
        byte[] der;
        try (var lease = session.repository().openStatusObject(id, "original", NONE); var input = lease.openStream()) {
            der = input.readAllBytes();
        }
        var holder = new X509CRLHolder(der);
        assertTrue(holder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(primary)));
        assertTrue(holder.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(alternative)));
        X509CRL pem;
        try (var lease = session.repository().openStatusObject(id, "pem", NONE); var input = lease.openStream()) {
            pem = (X509CRL) CertificateFactory.getInstance("X.509", "BC").generateCRL(input);
        }
        assertArrayEquals(der, pem.getEncoded());
        var parsed = (X509CRL) CertificateFactory.getInstance("X.509", "BC").generateCRL(new ByteArrayInputStream(der));
        assertEquals(CrlHybridSigningCommand.PROFILE, attribute(session, id, CrlHybridSigningCommand.SIGNATURE_PROFILE));
        var number = ASN1Integer.getInstance(holder.getExtension(Extension.cRLNumber).getParsedValue()).getValue();
        var indicator = holder.getExtension(Extension.deltaCRLIndicator);
        return new Crl(id, parsed, number, indicator == null ? null : ASN1Integer.getInstance(indicator.getParsedValue()).getValue());
    }

    private static String attribute(PkiSession session, PkiId id, AttributeId attribute) {
        return assertInstanceOf(AttributeValue.StringValue.class,
                session.repository().statusObject(id).orElseThrow().attributes().getAll(attribute).getFirst()).value();
    }

    private static String text(PkiOperationValue value) { return assertInstanceOf(PkiOperationValue.Text.class, value).value(); }
    private record Crl(PkiId id, X509CRL crl, BigInteger number, BigInteger base) { }
}
