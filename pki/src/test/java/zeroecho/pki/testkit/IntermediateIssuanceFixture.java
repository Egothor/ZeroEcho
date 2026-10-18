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

package zeroecho.pki.testkit;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.core.IntermediateSigningPreparation;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;

/** Directly seeds consistent authoritative metadata and a real multi-RDN intermediate certificate. */
public final class IntermediateIssuanceFixture {
    public static final PkiId SUBJECT = new PkiId("existing-intermediate");
    public static final String PROFILE = "selected-intermediate";
    public static final X500Principal PRINCIPAL = new X500Principal("O=Frozen Organization,C=CZ,CN=Existing Intermediate");
    public final IntermediateCreationFixture base = new IntermediateCreationFixture();

    public IntermediateIssuanceFixture() throws Exception { }

    public void initialize(PkiStore store) throws Exception {
        base.initialize(store, 2);
        CertificateProfileRef historical = RootCreationFixture.install(store, RootCreationFixture.definition("historical-intermediate",
                CertificateProfileKind.INTERMEDIATE_CA, Duration.ofDays(100), X509AlgorithmBindingPolicy.standardOnly()));
        RootCreationFixture.install(store, RootCreationFixture.definition(PROFILE, CertificateProfileKind.INTERMEDIATE_CA,
                Duration.ofDays(30), X509AlgorithmBindingPolicy.standardOnly()));
        CaRecord parent = store.getCa(IntermediateCreationFixture.CA).orElseThrow();
        IssuerChainPath parentPath = store.getIssuerChainPath(parent.issuanceChainPathId()).orElseThrow();
        Validity validity = new Validity(IntermediateCreationFixture.NOW.minusSeconds(3600),
                IntermediateCreationFixture.NOW.plus(Duration.ofDays(90)));
        byte[] tbs = Pkix.certificateBuilder().serialNumber(BigInteger.TWO).issuer(new X500Principal(parent.subjectRef().value()))
                .subject(PRINCIPAL).publicKeyInfo(base.childKey.getPublic().getEncoded())
                .validity(validity.notBefore(), validity.notAfter()).basicConstraints(BasicConstraints.ca(2), true)
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
                .buildTbs(Pkix.subjectPublicKeyAlgorithm(base.parentKey.getPublic().getEncoded()));
        byte[] der = Pkix.assembleCertificateOrCrl(tbs, base.signature(tbs, IntermediateCreationFixture.PARENT_KEY).bytes(), false);
        PkiId credentialId = new PkiId("x509:" + IntermediateCreationFixture.hash(der));
        PkiId generation = IssuerGeneration.idFor(SUBJECT, credentialId);
        IssuerChainPath path = IssuerChainPath.create(SUBJECT, generation, List.of(credentialId, parentPath.orderedCredentialIds().getFirst()));
        SubjectRef subject = new SubjectRef(PRINCIPAL.getName(X500Principal.RFC2253));
        store.putCredential(new Credential(credentialId, new FormatId("x509"),
                new IssuerRef(parent.caId(), parent.currentIssuanceIssuerId(), parent.issuanceChainPathId()), subject, validity, "2",
                new PkiId("spki:" + IntermediateCreationFixture.hash(base.childKey.getPublic().getEncoded())), new CaProfileBinding(historical),
                CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet()));
        String commitment = HexFormat.of().formatHex(historical.canonicalSha256());
        store.putIssuerGeneration(new IssuerGeneration(generation, SUBJECT, credentialId, IntermediateCreationFixture.CHILD_KEY,
                IssuerGenerationState.ACTIVE, commitment, commitment));
        store.putIssuerChainPath(path);
        store.putCa(new CaRecord(SUBJECT, CaKind.INTERMEDIATE, CaState.ACTIVE, IntermediateCreationFixture.CHILD_KEY,
                subject, List.of(generation), generation, path.pathId()));
    }

    public CertificateProfileRef activateLifecycleVersionTwo(PkiStore store) throws Exception {
        CertificateProfileDefinition old = store.requireActiveProfile("historical-intermediate").definition();
        return RootCreationFixture.install(store, new CertificateProfileDefinition(old.certificateType(), old.profileId(), 2,
                old.formatId(), old.displayName(), Duration.ofDays(30), old.subjectPolicy(), old.certificatePolicy(), old.algorithmBindingPolicy()));
    }

    public IntermediateCertIssueCommand command() {
        return new IntermediateCertIssueCommand(new FormatId("x509"), IntermediateCreationFixture.CA, SUBJECT, PROFILE,
                IntermediateCreationFixture.CHILD_KEY, Optional.empty(), new SimpleAttributeSet());
    }
    public IntermediateSigningPreparation preparer(PkiStore store, Clock clock) {
        return new IntermediateSigningPreparation(store, clock, base.provider, base.signing, base.bindings,
                IntermediateCreationFixture.ALGORITHM, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, base.proofPreparation(store));
    }
    public DefaultSemanticSigningService semantic(PkiStore store, Clock clock) {
        DefaultSigningService service = new DefaultSigningService(store, base.provider, base.signing.resolveIdentity(IntermediateCreationFixture.ALGORITHM),
                IntermediateCreationFixture.TTL, new SecureRandom(), () -> { },
                (command, custody) -> { custody.run(); return store.acceptSign(command); }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
        return new DefaultSemanticSigningService(store, service, PkiTestRuntime.endEntityPreparation(store, clock),
                ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, Optional.empty(), Optional.empty(), Optional.of(preparer(store, clock)));
    }
}
