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
package zeroecho.pkix;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.pkix.cert.CertificateBuilder;
import zeroecho.sdk.util.BouncyCastleActivator;

/** Cross-checks both directions against the independent upstream BC certificate implementation. */
final class AlternativeSignatureInteropTest {
    private static final Instant START = Instant.parse("2026-10-01T00:00:00Z");
    private static final AlgorithmIdentifier PRIMARY = AlgorithmIdentifier.absent("1.3.101.112");
    private static final AlgorithmIdentifier ALTERNATIVE = AlgorithmIdentifier.absent("2.16.840.1.101.3.4.3.18");

    @BeforeAll static void providers() { BouncyCastleActivator.init(); }

    @Test void existingSpiImplementationsInheritUnsupportedDefaults() throws Throwable {
        java.lang.reflect.Method builderMethod = CertificateBuilder.class.getMethod("buildAlternativeSignatureTbs");
        java.lang.reflect.Method providerMethod = zeroecho.pkix.spi.PkixProvider.class.getMethod("verifyAlternativeSignature",
                X509Certificate.class, java.security.PublicKey.class);
        assertTrue(builderMethod.isDefault());
        assertTrue(providerMethod.isDefault());
        Object builder = java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{CertificateBuilder.class}, (proxy, method, args) ->
                        java.lang.reflect.InvocationHandler.invokeDefault(proxy, method, args));
        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
                () -> ((CertificateBuilder) builder).buildAlternativeSignatureTbs());
        Object provider = java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{zeroecho.pkix.spi.PkixProvider.class}, (proxy, method, args) ->
                        java.lang.reflect.InvocationHandler.invokeDefault(proxy, method, args));
        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
                () -> ((zeroecho.pkix.spi.PkixProvider) provider).verifyAlternativeSignature(null, null));
    }

    @Test void upstreamBuilderVerifiesThroughZeroEchoFacade() throws Exception {
        KeyPair primary = pair("Ed25519");
        KeyPair alternative = pair("ML-DSA-65");
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new X500Name("CN=Interop"), BigInteger.ONE,
                Date.from(START), Date.from(START.plusSeconds(3600)), new X500Name("CN=Interop"),
                SubjectPublicKeyInfo.getInstance(primary.getPublic().getEncoded()));
        builder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                SubjectPublicKeyInfo.getInstance(alternative.getPublic().getEncoded()));
        X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder("Ed25519").setProvider("BC")
                .build(primary.getPrivate()), false, new JcaContentSignerBuilder("ML-DSA-65").setProvider("BC")
                        .build(alternative.getPrivate()));
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        certificate.verify(primary.getPublic(), "BC");
        assertTrue(Pkix.verifyAlternativeSignature(certificate, alternative.getPublic()));
        assertFalse(Pkix.verifyAlternativeSignature(certificate, pair("ML-DSA-65").getPublic()));
    }

    @Test void zeroEchoBuilderVerifiesThroughUpstreamAndRejectsLegacyPlaceholder() throws Exception {
        KeyPair primary = pair("Ed25519");
        KeyPair alternative = pair("ML-DSA-65");
        byte[] preTbs = builder(primary, alternative).buildAlternativeSignatureTbs();
        byte[] signature = sign(alternative, preTbs);
        X509Certificate certificate = finish(builder(primary, alternative), signature, primary);
        assertTrue(independent(certificate, alternative));
        certificate.verify(primary.getPublic(), "BC");
        byte[] legacy = builder(primary, alternative).addExtension(value(new byte[3309])).buildTbs(PRIMARY);
        X509Certificate legacyCertificate = finish(builder(primary, alternative), sign(alternative, legacy), primary);
        legacyCertificate.verify(primary.getPublic(), "BC");
        assertFalse(independent(legacyCertificate, alternative));
        assertFalse(Pkix.verifyAlternativeSignature(legacyCertificate, alternative.getPublic()));
    }

    @Test void missingPartialTamperedAndWrongAlgorithmExtensionsFailClosed() throws Exception {
        KeyPair primary = pair("Ed25519");
        KeyPair alternative = pair("ML-DSA-65");
        X509Certificate plain = base(primary).build(Pkix.signer(primary.getPrivate(), PRIMARY));
        assertFalse(Pkix.verifyAlternativeSignature(plain, alternative.getPublic()));
        X509Certificate partial = builder(primary, alternative).build(Pkix.signer(primary.getPrivate(), PRIMARY));
        assertFalse(Pkix.verifyAlternativeSignature(partial, alternative.getPublic()));
        byte[] signature = sign(alternative, builder(primary, alternative).buildAlternativeSignatureTbs());
        signature[0] ^= 1;
        assertFalse(Pkix.verifyAlternativeSignature(finish(builder(primary, alternative), signature, primary), alternative.getPublic()));
        byte[] valid = sign(alternative, builder(primary, alternative).buildAlternativeSignatureTbs());
        X509Certificate wrongSubject = finish(builder(primary, pair("ML-DSA-65")), valid, primary);
        assertFalse(Pkix.verifyAlternativeSignature(wrongSubject, alternative.getPublic()));
        CertificateBuilder wrongAlgorithm = base(primary)
                .addExtension(new CertificateExtension("2.5.29.72", false, alternative.getPublic().getEncoded()))
                .addExtension(new CertificateExtension("2.5.29.73", false, Pkix.encodeAlgorithmIdentifier(PRIMARY)));
        assertFalse(Pkix.verifyAlternativeSignature(finish(wrongAlgorithm, valid, primary), alternative.getPublic()));
        assertFalse(Pkix.verifyAlternativeSignature(finish(builder(primary, alternative), new byte[0], primary), alternative.getPublic()));
        X509Certificate padded = builder(primary, alternative)
                .addExtension(new CertificateExtension("2.5.29.74", false, new DERBitString(new byte[]{2}, 1).getEncoded()))
                .build(Pkix.signer(primary.getPrivate(), PRIMARY));
        assertFalse(Pkix.verifyAlternativeSignature(padded, alternative.getPublic()));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> base(primary).buildAlternativeSignatureTbs());
    }

    private static boolean independent(X509Certificate certificate, KeyPair alternative) throws Exception {
        return new X509CertificateHolder(certificate.getEncoded()).isAlternativeSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider("BC").build(alternative.getPublic()));
    }

    private static CertificateBuilder base(KeyPair primary) {
        return Pkix.certificateBuilder().serialNumber(BigInteger.ONE).issuer(new X500Principal("CN=Interop"))
                .subject(new X500Principal("CN=Interop")).validity(START, START.plusSeconds(3600)).publicKey(primary.getPublic());
    }

    private static CertificateBuilder builder(KeyPair primary, KeyPair alternative) {
        return base(primary).addExtension(new CertificateExtension("2.5.29.72", false, alternative.getPublic().getEncoded()))
                .addExtension(new CertificateExtension("2.5.29.73", false, Pkix.encodeAlgorithmIdentifier(ALTERNATIVE)));
    }

    private static CertificateExtension value(byte[] signature) throws Exception {
        return new CertificateExtension("2.5.29.74", false, new DERBitString(signature).getEncoded());
    }

    private static X509Certificate finish(CertificateBuilder builder, byte[] signature, KeyPair primary) throws Exception {
        return builder.addExtension(value(signature)).build(Pkix.signer(primary.getPrivate(), PRIMARY));
    }

    private static KeyPair pair(String algorithm) throws Exception {
        return KeyPairGenerator.getInstance(algorithm, "BC").generateKeyPair();
    }

    private static byte[] sign(KeyPair alternative, byte[] input) throws Exception {
        Signature signer = Signature.getInstance("ML-DSA-65", "BC");
        signer.initSign(alternative.getPrivate());
        signer.update(input);
        return signer.sign();
    }
}
