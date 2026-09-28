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

package zeroecho.pki.testkit;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;

/** Real bounded X.509 fixtures for semantic acceptance, not a permissive store adapter. */
public final class SemanticIssuanceFixture {
    public static final PkiId AUTHORITY = new PkiId("authority");
    public static final KeyRef KEY = new KeyRef("test-key");
    public static final Instant BEFORE = Instant.parse("2025-01-01T00:00:00Z");
    public static final Instant AFTER = Instant.parse("2030-01-01T00:00:00Z");
    private static final KeyPair KEY_PAIR = keyPair();

    private SemanticIssuanceFixture() { }

    public static PkiId credentialId(int generation) { return new PkiId("fixture:root:" + generation); }
    public static PkiId issuerId(int generation) { return IssuerGeneration.idFor(AUTHORITY, credentialId(generation)); }
    public static IssuerChainPath path(int generation) {
        return IssuerChainPath.create(AUTHORITY, issuerId(generation), List.of(credentialId(generation)));
    }

    public static Credential issuer(PkiStore store, int generation) throws Exception {
        if (store.getCredential(credentialId(generation)).isPresent()) {
            return store.getCredential(credentialId(generation)).orElseThrow();
        }
        X509CertificateHolder certificate = certificate("CN=Acceptance Issuer", BigInteger.valueOf(generation), BEFORE, AFTER);
        Credential credential = new Credential(credentialId(generation), new FormatId("x509"),
                new IssuerRef(AUTHORITY, issuerId(generation), path(generation).pathId()),
                new SubjectRef("CN=Acceptance Issuer"), new Validity(BEFORE, AFTER), Integer.toString(generation),
                new PkiId("key:public"), new CaProfileBinding(new CertificateProfileRef("profile", 1, new byte[32])),
                CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, certificate.getEncoded()), new SimpleAttributeSet());
        store.putCredential(credential);
        store.putIssuerGeneration(new IssuerGeneration(issuerId(generation), AUTHORITY, credential.credentialId(), KEY,
                IssuerGenerationState.ACTIVE, "1".repeat(64), "1".repeat(64)));
        store.putIssuerChainPath(path(generation));
        return credential;
    }

    public static X509CertificateHolder certificate(String subject, BigInteger serial, Instant before, Instant after)
            throws Exception {
        return new JcaX509v3CertificateBuilder(new X500Name("CN=Acceptance Issuer"), serial,
                Date.from(before), Date.from(after), new X500Name(subject), KEY_PAIR.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(KEY_PAIR.getPrivate()));
    }

    public static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    public static String publicKeyDigest() throws Exception { return digest(KEY_PAIR.getPublic().getEncoded()); }

    private static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (java.security.GeneralSecurityException failure) {
            throw new ExceptionInInitializerError(failure);
        }
    }
}
