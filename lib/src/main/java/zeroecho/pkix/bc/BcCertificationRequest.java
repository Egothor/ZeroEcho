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
package zeroecho.pkix.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CsrAttribute;
import zeroecho.pkix.sign.ContentVerifier;

/** BouncyCastle-backed parsed {@link CertificationRequest}. */
final class BcCertificationRequest implements CertificationRequest {

    private final PKCS10CertificationRequest request;
    private final X500Principal subject;
    private PublicKey publicKey;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final List<GeneralName> requestedSans;
    private final List<CertificateExtension> requestedExtensions;
    private final List<CsrAttribute> attributes;

    /* default */ BcCertificationRequest(byte[] der) {
        try {
            this.request = new PKCS10CertificationRequest(der);
            this.subject = BcExtensions.toPrincipal(request.getSubject());
            this.signatureAlgorithm = BcAlgorithmIdentifiers.fromBc(request.getSignatureAlgorithm());
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid PKCS#10 certification request", failure);
        }
        Extensions extensions = extensionRequest(request);
        this.requestedSans = tolerantSans(extensions);
        this.requestedExtensions = BcExtensions.fromBc(extensions);
        this.attributes = otherAttributes(request);
    }

    // Provider parsing may throw several runtime subtypes; malformed SANs remain available as raw attributes.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static List<GeneralName> tolerantSans(Extensions extensions) {
        try {
            return BcExtensions.sansFromBc(extensions);
        } catch (RuntimeException tolerated) {
            // Malformed general names are surfaced to callers through rawAttributes()/parseGeneralNames();
            // the convenience accessor stays empty rather than failing the whole parse.
            return List.of();
        }
    }

    private static Extensions extensionRequest(PKCS10CertificationRequest request) {
        Attribute[] found = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (found.length != 1 || found[0].getAttrValues().size() != 1) {
            return null;
        }
        try {
            return Extensions.getInstance(found[0].getAttributeValues()[0]);
        } catch (IllegalArgumentException tolerated) {
            // A malformed extension-request is surfaced through rawAttributes() for
            // callers enforcing a strict grammar; the convenience accessors stay empty.
            return null;
        }
    }

    // Each encoded CSR attribute is an independent immutable result element.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static List<CsrAttribute> otherAttributes(PKCS10CertificationRequest request) {
        List<CsrAttribute> result = new ArrayList<>();
        for (Attribute attribute : request.getAttributes()) {
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attribute.getAttrType())) {
                continue;
            }
            List<byte[]> values = new ArrayList<>();
            for (ASN1Encodable value : attribute.getAttributeValues()) {
                try {
                    values.add(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
                } catch (IOException failure) {
                    throw new IllegalArgumentException("Cannot encode CSR attribute value", failure);
                }
            }
            result.add(new CsrAttribute(attribute.getAttrType().getId(), values));
        }
        return result;
    }

    @Override
    public X500Principal subject() {
        return subject;
    }

    @Override
    public PublicKey publicKey() {
        if (publicKey == null) {
            try {
                publicKey = new JcaPKCS10CertificationRequest(request).getPublicKey();
            } catch (java.security.NoSuchAlgorithmException | java.security.InvalidKeyException failure) {
                throw new IllegalArgumentException("Unsupported certification-request public key", failure);
            }
        }
        return publicKey;
    }

    @Override
    public AlgorithmIdentifier signatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public List<GeneralName> requestedSubjectAlternativeNames() {
        return List.copyOf(requestedSans);
    }

    @Override
    public List<CertificateExtension> requestedExtensions() {
        return List.copyOf(requestedExtensions);
    }

    @Override
    public List<CsrAttribute> attributes() {
        return List.copyOf(attributes);
    }

    // Defensive copies require one independent immutable result per raw attribute.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    @Override
    public List<CsrAttribute> rawAttributes() {
        List<CsrAttribute> result = new ArrayList<>();
        for (Attribute attribute : request.getAttributes()) {
            List<byte[]> values = new ArrayList<>();
            for (ASN1Encodable value : attribute.getAttributeValues()) {
                try {
                    values.add(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
                } catch (IOException failure) {
                    throw new IllegalArgumentException("Cannot encode CSR attribute value", failure);
                }
            }
            result.add(new CsrAttribute(attribute.getAttrType().getId(), values));
        }
        return result;
    }

    @Override
    public byte[] subjectPublicKeyInfo() {
        try {
            return request.getSubjectPublicKeyInfo().getEncoded(ASN1Encoding.DER);
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot encode SubjectPublicKeyInfo", failure);
        }
    }

    @Override
    public byte[] certificationRequestInfo() {
        try {
            return org.bouncycastle.asn1.pkcs.CertificationRequest.getInstance(request.getEncoded())
                    .getCertificationRequestInfo().getEncoded(ASN1Encoding.DER);
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot encode certificationRequestInfo", failure);
        }
    }

    @Override
    public byte[] signature() {
        return request.getSignature();
    }

    @Override
    public byte[] encoded() {
        try {
            return request.getEncoded();
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot encode certification request", failure);
        }
    }

    @Override
    public boolean verifySelfSignature() {
        ContentVerifier verifier = new JcaContentVerifier(publicKey(), signatureAlgorithm);
        try (OutputStream stream = verifier.contentStream()) {
            stream.write(certificationRequestInfo());
        } catch (IOException failure) {
            return false;
        }
        return verifier.verify(signature());
    }
}
