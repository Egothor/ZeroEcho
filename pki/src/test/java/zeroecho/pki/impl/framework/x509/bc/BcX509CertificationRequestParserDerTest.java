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
package zeroecho.pki.impl.framework.x509.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.request.CertificationRequest;

final class BcX509CertificationRequestParserDerTest {

    @Test
    void acceptsOneBoundedChallengePasswordWithoutOpeningOtherAttributeGrammar() throws Exception {
        java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] {81, 41, 7});
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048, random);
        KeyPair key = generator.generateKeyPair();
        BcX509CertificationRequestParser parser = new BcX509CertificationRequestParser();
        for (String variant : java.util.List.of("valid", "duplicate", "wrong-type", "oversize", "other")) {
            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Challenge CSR"), key.getPublic());
            org.bouncycastle.asn1.ASN1ObjectIdentifier oid = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
            org.bouncycastle.asn1.ASN1Encodable value = "wrong-type".equals(variant) ? new org.bouncycastle.asn1.ASN1Integer(1)
                    : new org.bouncycastle.asn1.DERUTF8String("oversize".equals(variant) ? "x".repeat(256) : "distinctive-private-challenge");
            builder.addAttribute(oid, value);
            if ("duplicate".equals(variant)) builder.addAttribute(oid, value);
            if ("other".equals(variant)) builder.addAttribute(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4"), value);
            byte[] der = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
            if ("valid".equals(variant)) assertEquals(Encoding.DER, parser.parse(request(Encoding.DER, der)).publicKeyInfo().encoding());
            else {
                PkiException failure = assertThrows(PkiException.class, () -> parser.parse(request(Encoding.DER, der)), variant);
                org.junit.jupiter.api.Assertions.assertFalse(failure.toString().contains("distinctive-private-challenge"));
            }
        }
    }

    @Test
    void acceptsOnlyExactSingleCsrPemObject() throws Exception {
        System.out.println("acceptsOnlyExactSingleCsrPemObject");
        byte[] der = certificationRequest();
        BcX509CertificationRequestParser parser = new BcX509CertificationRequestParser();
        for (String label : new String[] { "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST" }) {
            byte[] pem = pem(label, der);
            assertEquals(Encoding.DER, parser.parse(request(Encoding.PEM, pem)).publicKeyInfo().encoding());
        }
        assertThrows(PkiException.class,
                () -> parser.parse(request(Encoding.PEM, pem("PUBLIC KEY", der))));
        String missingLineBreak = "-----BEGIN CERTIFICATE REQUEST-----"
                + Base64.getEncoder().encodeToString(der) + "\n-----END CERTIFICATE REQUEST-----\n";
        assertThrows(PkiException.class, () -> parser.parse(request(Encoding.PEM,
                missingLineBreak.getBytes(StandardCharsets.US_ASCII))));
        byte[] one = pem("CERTIFICATE REQUEST", der);
        byte[] two = new byte[one.length * 2];
        System.arraycopy(one, 0, two, 0, one.length);
        System.arraycopy(one, 0, two, one.length, one.length);
        assertThrows(PkiException.class, () -> parser.parse(request(Encoding.PEM, two)));
        System.out.println("...labels=2 rejected=wrong-label, missing-line-break, second-object");
        System.out.println("acceptsOnlyExactSingleCsrPemObject...ok");
    }

    @Test
    void rejectsOversizeAndNonCanonicalDerBeforePkcs10Parsing() throws Exception {
        System.out.println("rejectsOversizeAndNonCanonicalDerBeforePkcs10Parsing");
        BcX509CertificationRequestParser parser = new BcX509CertificationRequestParser();
        byte[] oversized = new byte[BcX509CertificationRequestParser.MAXIMUM_CSR_DER_BYTES + 1];
        assertThrows(PkiException.class, () -> parser.parse(request(Encoding.DER, oversized)));
        byte[] der = certificationRequest();
        byte[] trailing = java.util.Arrays.copyOf(der, der.length + 1);
        assertThrows(PkiException.class, () -> parser.parse(request(Encoding.DER, trailing)));
        assertThrows(PkiException.class,
                () -> parser.parse(request(Encoding.DER, new byte[] { 0x30, (byte) 0x80, 0x00, 0x00 })));
        assertThrows(PkiException.class,
                () -> parser.parse(request(Encoding.DER, new byte[] { 0x30, (byte) 0x81, 0x00 })));
        assertThrows(PkiException.class,
                () -> parser.parse(request(Encoding.DER, new byte[] { 0x05, 0x00 })));
        assertThrows(PkiException.class, () -> parser.parse(request(Encoding.DER, excessivelyNestedDer())));
        System.out.println("...rejected=limit, trailing, indefinite, nonminimal, type, depth");
        System.out.println("rejectsOversizeAndNonCanonicalDerBeforePkcs10Parsing...ok");
    }

    private static CertificationRequest request(Encoding encoding, byte[] encoded) {
        return new CertificationRequest(BcX509CredentialFramework.FORMAT_ID, new EncodedObject(encoding, encoded));
    }

    private static byte[] pem(String label, byte[] der) {
        String encoded = "\n-----BEGIN " + label + "-----\n" + Base64.getEncoder().encodeToString(der)
                + "\n-----END " + label + "-----\n\t";
        return encoded.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] certificationRequest() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Bounded CSR"), pair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        PKCS10CertificationRequest request = builder.build(signer);
        return request.getEncoded();
    }

    private static byte[] excessivelyNestedDer() {
        byte[] encoded = { 0x05, 0x00 };
        for (int depth = 0; depth < 65; depth++) {
            int headerLength = encoded.length < 128 ? 2 : 3;
            byte[] wrapped = new byte[headerLength + encoded.length];
            wrapped[0] = 0x30;
            if (headerLength == 2) {
                wrapped[1] = (byte) encoded.length;
            } else {
                wrapped[1] = (byte) 0x81;
                wrapped[2] = (byte) encoded.length;
            }
            System.arraycopy(encoded, 0, wrapped, headerLength, encoded.length);
            encoded = wrapped;
        }
        return encoded;
    }
}
