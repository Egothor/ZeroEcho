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
package zeroecho.pkix.bc;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CertificationRequestBuilder;
import zeroecho.pkix.csr.CsrAttribute;
import zeroecho.pkix.sign.ContentSigner;

/** BouncyCastle-backed {@link CertificationRequestBuilder}. */
final class BcCertificationRequestBuilder implements CertificationRequestBuilder {

    private X500Principal subject;
    private PublicKey publicKey;
    private final ExtensionsGenerator extensions = new ExtensionsGenerator();
    private boolean hasExtensions;
    private final List<CsrAttribute> attributes = new ArrayList<>();

    @Override
    public CertificationRequestBuilder subject(X500Principal subject) {
        this.subject = subject;
        return this;
    }

    @Override
    public CertificationRequestBuilder publicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @Override
    public CertificationRequestBuilder subjectAlternativeNames(List<GeneralName> names, boolean critical) {
        addExtension(BcExtensions.subjectAlternativeNames(names, critical));
        return this;
    }

    @Override
    public CertificationRequestBuilder requestExtension(CertificateExtension extension) {
        addExtension(BcExtensions.generic(extension));
        return this;
    }

    private void addExtension(Extension extension) {
        extensions.addExtension(extension);
        hasExtensions = true;
    }

    @Override
    public CertificationRequestBuilder addAttribute(CsrAttribute attribute) {
        attributes.add(Objects.requireNonNull(attribute, "attribute"));
        return this;
    }

    // Bouncy Castle requires a distinct ASN.1 attribute object for every requested attribute.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    @Override
    public CertificationRequest build(ContentSigner signer) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(signer, "signer");
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                BcExtensions.toX500Name(subject), publicKey);
        if (hasExtensions) {
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        }
        for (CsrAttribute attribute : attributes) {
            builder.addAttribute(new ASN1ObjectIdentifier(attribute.oid()), decode(attribute));
        }
        PKCS10CertificationRequest request = builder.build(new BcContentSignerAdapter(signer));
        try {
            return new BcCertificationRequest(request.getEncoded());
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot encode certification request", failure);
        }
    }

    private static org.bouncycastle.asn1.ASN1Encodable decode(CsrAttribute attribute) {
        try {
            org.bouncycastle.asn1.ASN1EncodableVector vector = new org.bouncycastle.asn1.ASN1EncodableVector();
            for (byte[] value : attribute.derValues()) {
                vector.add(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(value));
            }
            return new DERSet(vector).getObjectAt(0);
        } catch (IOException failure) {
            throw new IllegalArgumentException("Invalid CSR attribute value DER", failure);
        }
    }
}
