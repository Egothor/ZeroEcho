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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.ManagedOcspResponderProofTarget;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole;

/**
 * Structural codec tests use public synthetic SPKIs, without claiming cryptographic proof validity.
 */
class OcspResponderCertificateCommandTest {
    private static final PkiId PARENT = id('0');
    private static final byte[] PRIMARY = HexFormat.of().parseHex("302a300506032b6570032100" + "00".repeat(32));
    private static final byte[] ALTERNATIVE = alternate();

    /**
     * Round trips both exact descriptors and rejects role target and version substitution.
     */
    @Test void roundTripsBothExactDescriptorsAndRejectsRoleTargetAndVersionSubstitution() {
        var fields = base();
        var parentFields = new ArrayList<>(fields); parentFields.add("123");
        String intent = "ocsp-intent:v1:" + hash(DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                OcspResponderCertificateCommand.OPERATION, parentFields.toArray(String[]::new)).command().bytes());
        String target = hash(DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                "OCSP_RESPONDER_FROZEN_TARGET_V1", parentFields.toArray(String[]::new)).command().bytes());
        var primary = proof(SubjectKeyRole.PRIMARY, id('1'), intent, target, PRIMARY, OcspResponderCertificateCommand.decodeKey(fields.get(12)));
        var alternative = proof(SubjectKeyRole.ALTERNATIVE, id('2'), intent, target, ALTERNATIVE, OcspResponderCertificateCommand.decodeKey(fields.get(13)));
        fields.add(id('1').value()); fields.add(OcspResponderCertificateCommand.encodeProof(primary.command()));
        fields.add(id('2').value()); fields.add(OcspResponderCertificateCommand.encodeProof(alternative.command()));
        fields.add("123");
        var command = new OcspResponderCertificateCommand(fields);
        assertEquals(command, OcspResponderCertificateCommand.decode(command.encode()));
        OcspResponderSubjectProofBindings.requireChallenge(command, PARENT, SubjectKeyRole.PRIMARY, primary);
        OcspResponderSubjectProofBindings.requireChallenge(command, PARENT, SubjectKeyRole.ALTERNATIVE, alternative);
        var swapped = new ArrayList<>(fields); swapped.set(21, fields.get(23)); swapped.set(23, fields.get(21));
        assertThrows(IllegalArgumentException.class, () -> OcspResponderSubjectProofBindings.requireCommand(
                new OcspResponderCertificateCommand(swapped), PARENT, SubjectKeyRole.PRIMARY));
        var changedTbs = new ArrayList<>(fields); changedTbs.set(16, "f".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> OcspResponderSubjectProofBindings.requireCommand(
                new OcspResponderCertificateCommand(changedTbs), PARENT, SubjectKeyRole.ALTERNATIVE));
        var unknown = new ArrayList<>(fields); unknown.set(0,"2");
        var changedSerial = new ArrayList<>(fields); changedSerial.set(24,"124");
        assertThrows(IllegalArgumentException.class, () -> OcspResponderSubjectProofBindings.requireCommand(
                new OcspResponderCertificateCommand(changedSerial), PARENT, SubjectKeyRole.PRIMARY));
        var invalidSerial = new ArrayList<>(fields); invalidSerial.set(24,"01");
        assertThrows(IllegalArgumentException.class, () -> new OcspResponderCertificateCommand(invalidSerial));
        assertThrows(IllegalArgumentException.class, () -> new OcspResponderCertificateCommand(unknown));
        var trailing = new ArrayList<>(fields); trailing.add("ignored");
        assertThrows(IllegalArgumentException.class, () -> new OcspResponderCertificateCommand(trailing));
    }
    private static ArrayList<String> base() {
        var primary = new IssuerKeyBinding(new KeyRef("responder-primary"), BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE, new EncodedObject(Encoding.DER, HexFormat.of().parseHex("300506032b6570")), hash(PRIMARY));
        var alternative = new IssuerKeyBinding(new KeyRef("responder-alternative"), BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE, new EncodedObject(Encoding.DER, HexFormat.of().parseHex("300b0609608648016503040313")), hash(ALTERNATIVE));
        return new ArrayList<>(List.of("1", "authority", "issuer", "credential", "path", "1".repeat(64), "ocsp", "1", "0".repeat(64),
                OcspResponderCertificateCommand.encodeSubject(List.of(new SubjectRdn(SubjectRdnType.COMMON_NAME, "Responder"))),
                Instant.EPOCH.toString(), Instant.ofEpochSecond(3600).toString(), OcspResponderCertificateCommand.encodeKey(primary),
                OcspResponderCertificateCommand.encodeKey(alternative), "2".repeat(64), "3".repeat(64), "4".repeat(64),
                "ocsp-prov:" + "5".repeat(64) + ":r1", "6".repeat(64), DomainAttributeEncoding.encode(new zeroecho.pki.impl.core.attr.SimpleAttributeSet(List.of()))));
    }
    private static ManagedKeyProofChallenge.Decoded proof(SubjectKeyRole role, PkiId id, String intent, String target,
            byte[] spki, IssuerKeyBinding binding) {
        var scope = new ManagedOcspResponderProofTarget(PARENT, intent, target, role);
        var request = new ManagedKeyProofRequest.OcspResponderCandidate(new PkiId("authority"), new CertificateProfileRef("ocsp",1,new byte[32]), binding.keyRef(), scope);
        var metadata = new ArrayList<>(ManagedKeyProofCommand.prefix(request));
        metadata.add("provider"); metadata.add("0".repeat(64)); metadata.add(binding.signatureAlgorithm().canonicalForm());
        metadata.add(HexFormat.of().formatHex(binding.signatureAlgorithmIdentifier().bytes()));
        var context = new ManagedKeyProofChallenge.ResponderCandidateContext(PARENT,intent,role,target);
        return ManagedKeyProofChallenge.decode(ManagedKeyProofChallenge.encodeCandidate(id, Instant.ofEpochSecond(60), context, metadata, new byte[32], spki));
    }
    private static PkiId id(char digit) { return new PkiId("zsign:v1:provider:0:" + String.valueOf(digit).repeat(32)); }
    private static String hash(byte[] bytes) { return ContentCommitment.sha256(bytes).sha256(); }
    private static byte[] alternate() {
        try { return new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19")), new byte[2592]).getEncoded("DER"); }
        catch (java.io.IOException impossible) { throw new IllegalStateException(impossible); }
    }
}
