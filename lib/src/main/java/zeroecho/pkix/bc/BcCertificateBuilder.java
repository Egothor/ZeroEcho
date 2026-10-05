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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.ExtendedKeyUsage;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.cert.CertificateBuilder;
import zeroecho.pkix.sign.ContentSigner;

/** BouncyCastle-backed builder for canonical unsigned bodies and JDK certificates. */
final class BcCertificateBuilder implements CertificateBuilder {

    private BigInteger serialNumber;
    private X500Principal subject;
    private X500Principal issuer;
    private Instant notBefore;
    private Instant notAfter;
    private PublicKey publicKey;
    private byte[] publicKeyInfoDer;
    private boolean addSubjectKeyIdentifier;
    private final List<Extension> extensions = new ArrayList<>();

    @Override
    public CertificateBuilder serialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    @Override
    public CertificateBuilder subject(X500Principal subject) {
        this.subject = subject;
        return this;
    }

    @Override
    public CertificateBuilder issuer(X500Principal issuer) {
        this.issuer = issuer;
        return this;
    }

    @Override
    public CertificateBuilder validity(Instant notBefore, Instant notAfter) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        return this;
    }

    @Override
    public CertificateBuilder publicKey(PublicKey subjectPublicKey) {
        this.publicKey = subjectPublicKey;
        return this;
    }

    @Override
    public CertificateBuilder publicKeyInfo(byte[] subjectPublicKeyInfoDer) {
        this.publicKeyInfoDer = subjectPublicKeyInfoDer == null ? null : subjectPublicKeyInfoDer.clone();
        return this;
    }

    @Override
    public CertificateBuilder basicConstraints(BasicConstraints basicConstraints, boolean critical) {
        extensions.add(BcExtensions.basicConstraints(basicConstraints, critical));
        return this;
    }

    @Override
    public CertificateBuilder keyUsage(Set<KeyUsage> keyUsage, boolean critical) {
        extensions.add(BcExtensions.keyUsage(keyUsage, critical));
        return this;
    }

    @Override
    public CertificateBuilder extendedKeyUsage(ExtendedKeyUsage extendedKeyUsage, boolean critical) {
        extensions.add(BcExtensions.extendedKeyUsage(extendedKeyUsage, critical));
        return this;
    }

    @Override
    public CertificateBuilder subjectAlternativeNames(List<GeneralName> names, boolean critical) {
        extensions.add(BcExtensions.subjectAlternativeNames(names, critical));
        return this;
    }

    @Override
    public CertificateBuilder subjectKeyIdentifier() {
        this.addSubjectKeyIdentifier = true;
        return this;
    }

    @Override
    public CertificateBuilder authorityKeyIdentifier(byte[] keyIdentifier) {
        extensions.add(BcExtensions.authorityKeyIdentifier(keyIdentifier));
        return this;
    }

    @Override
    public CertificateBuilder addExtension(CertificateExtension extension) {
        extensions.add(BcExtensions.generic(extension));
        return this;
    }

    @Override
    public byte[] buildTbs(AlgorithmIdentifier signatureAlgorithm) {
        Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        return buildBody(signatureAlgorithm, false);
    }

    @Override
    public byte[] buildAlternativeSignatureTbs() {
        return buildBody(null, true);
    }

    private byte[] buildBody(AlgorithmIdentifier signatureAlgorithm, boolean alternative) {
        Objects.requireNonNull(serialNumber, "serialNumber");
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        if (serialNumber.signum() <= 0 || !notAfter.isAfter(notBefore)) {
            throw new IllegalArgumentException("Certificate serial and validity must be positive");
        }
        SubjectPublicKeyInfo spki = publicKeyInfoDer != null
                ? SubjectPublicKeyInfo.getInstance(publicKeyInfoDer)
                : BcExtensions.spki(Objects.requireNonNull(publicKey, "publicKey"));
        V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        generator.setSerialNumber(new ASN1Integer(serialNumber));
        generator.setIssuer(BcExtensions.toX500Name(issuer));
        generator.setSubject(BcExtensions.toX500Name(subject));
        generator.setStartDate(new Time(Date.from(notBefore)));
        generator.setEndDate(new Time(Date.from(notAfter)));
        generator.setSubjectPublicKeyInfo(spki);
        generator.setSignature(alternative ? null : BcAlgorithmIdentifiers.toBc(signatureAlgorithm));
        ExtensionsGenerator selectedExtensions = new ExtensionsGenerator();
        if (addSubjectKeyIdentifier) {
            selectedExtensions.addExtension(BcExtensions.subjectKeyIdentifier(spki));
        }
        for (Extension extension : extensions) {
            if (!alternative || !extension.getExtnId().equals(Extension.altSignatureValue)) {
                selectedExtensions.addExtension(extension);
            }
        }
        if (alternative) {
            validateAlternativeExtensions(selectedExtensions);
        }
        if (!selectedExtensions.isEmpty()) {
            generator.setExtensions(selectedExtensions.generate());
        }
        try {
            return alternative ? generator.generatePreTBSCertificate().getEncoded(ASN1Encoding.DER)
                    : generator.generateTBSCertificate().getEncoded(ASN1Encoding.DER);
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot encode certificate body", failure);
        }
    }

    private static void validateAlternativeExtensions(ExtensionsGenerator selectedExtensions) {
        org.bouncycastle.asn1.x509.Extensions selected = selectedExtensions.generate();
        Extension alternativeKey = selected.getExtension(Extension.subjectAltPublicKeyInfo);
        Extension alternativeAlgorithm = selected.getExtension(Extension.altSignatureAlgorithm);
        if (alternativeKey == null || alternativeAlgorithm == null) {
            throw new IllegalArgumentException("Alternative public key and algorithm extensions are required");
        }
        if (SubjectPublicKeyInfo.getInstance(alternativeKey.getParsedValue()).getPublicKeyData().getPadBits() != 0) {
            throw new IllegalArgumentException("Alternative public key must have zero unused bits");
        }
        org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(alternativeAlgorithm.getParsedValue());
    }

    @Override
    public X509Certificate build(ContentSigner signer) {
        Objects.requireNonNull(serialNumber, "serialNumber");
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(notAfter, "notAfter");
        Objects.requireNonNull(signer, "signer");
        SubjectPublicKeyInfo spki = publicKeyInfoDer != null
                ? SubjectPublicKeyInfo.getInstance(publicKeyInfoDer)
                : BcExtensions.spki(Objects.requireNonNull(publicKey, "publicKey"));
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(BcExtensions.toX500Name(issuer),
                serialNumber, Date.from(notBefore), Date.from(notAfter), BcExtensions.toX500Name(subject),
                spki);
        try {
            if (addSubjectKeyIdentifier) {
                builder.addExtension(BcExtensions.subjectKeyIdentifier(spki));
            }
            for (Extension extension : extensions) {
                builder.addExtension(extension);
            }
            X509CertificateHolder holder = builder.build(new BcContentSignerAdapter(signer));
            return toJdk(holder);
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot assemble certificate", failure);
        }
    }

    private static X509Certificate toJdk(X509CertificateHolder holder) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(holder.getEncoded()));
        } catch (CertificateException | IOException failure) {
            throw new IllegalStateException("Cannot materialize certificate", failure);
        }
    }
}
