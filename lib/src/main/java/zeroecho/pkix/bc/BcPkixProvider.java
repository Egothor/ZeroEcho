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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import zeroecho.pkix.cert.CertificateBuilder;
import zeroecho.pkix.crl.CrlBuilder;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CertificationRequestBuilder;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.OcspRequest;
import zeroecho.pkix.ocsp.OcspResponseBuilder;
import zeroecho.pkix.sign.ContentSigner;
import zeroecho.pkix.sign.ContentVerifier;
import zeroecho.pkix.spi.PkixProvider;

/**
 * The default {@link PkixProvider}, implemented with BouncyCastle. This is the
 * single place in the codebase that a concrete cryptographic toolkit is used for
 * X.509/PKIX operations; it is confined to the {@code lib} module and reached only
 * through {@link zeroecho.pkix.Pkix}.
 */
// This boundary intentionally centralizes the finite PKIX operation set behind one provider implementation.
@SuppressWarnings("PMD.CyclomaticComplexity")
public final class BcPkixProvider implements PkixProvider {

    /** Creates the provider, ensuring the BouncyCastle security providers are registered. */
    public BcPkixProvider() {
        zeroecho.sdk.util.BouncyCastleActivator.init();
    }

    @Override
    public String id() {
        return "bc";
    }

    @Override
    public CertificateBuilder certificateBuilder() {
        return new BcCertificateBuilder();
    }

    @Override
    public X509Certificate parseCertificate(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException failure) {
            throw new IllegalArgumentException("Invalid X.509 certificate", failure);
        }
    }

    @Override
    public CertificationRequestBuilder certificationRequestBuilder() {
        return new BcCertificationRequestBuilder();
    }

    @Override
    public CertificationRequest parseCertificationRequest(byte[] der) {
        return new BcCertificationRequest(der);
    }

    @Override
    public CrlBuilder crlBuilder() {
        return new BcCrlBuilder();
    }

    @Override
    public X509CRL parseCrl(byte[] der) {
        try {
            return (X509CRL) CertificateFactory.getInstance("X.509")
                    .generateCRL(new ByteArrayInputStream(der));
        } catch (CertificateException | CRLException failure) {
            throw new IllegalArgumentException("Invalid X.509 CRL", failure);
        }
    }

    @Override
    public OcspResponseBuilder ocspResponseBuilder() {
        return new BcOcspResponseBuilder();
    }

    @Override
    public OcspRequest parseOcspRequest(byte[] der) {
        return new BcOcspRequest(der);
    }

    @Override
    public ContentSigner signer(PrivateKey privateKey, zeroecho.pkix.AlgorithmIdentifier algorithm) {
        return new JcaContentSigner(privateKey, algorithm);
    }

    @Override
    public ContentVerifier verifier(PublicKey publicKey, zeroecho.pkix.AlgorithmIdentifier algorithm) {
        return new JcaContentVerifier(publicKey, algorithm);
    }

    @Override
    public ContentVerifier verifier(byte[] subjectPublicKeyInfoDer, zeroecho.pkix.AlgorithmIdentifier algorithm) {
        try {
            org.bouncycastle.operator.ContentVerifier bcVerifier =
                    new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                            .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                            .build(SubjectPublicKeyInfo.getInstance(subjectPublicKeyInfoDer))
                            .get(BcAlgorithmIdentifiers.toBc(algorithm));
            return new ContentVerifier() {
                @Override
                public java.io.OutputStream contentStream() {
                    return bcVerifier.getOutputStream();
                }

                @Override
                public boolean verify(byte[] expectedSignature) {
                    return bcVerifier.verify(expectedSignature);
                }
            };
        } catch (OperatorCreationException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Cannot create content verifier: " + algorithm.oid(), failure);
        }
    }

    @Override
    public byte[] subjectKeyIdentifier(PublicKey publicKey) {
        return BcExtensions.keyIdentifier(publicKey);
    }

    @Override
    public CertId computeCertId(X509Certificate issuer, BigInteger serialNumber, String digestAlgorithmOid) {
        try {
            DigestCalculator digest = new JcaDigestCalculatorProviderBuilder().build()
                    .get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithmOid)));
            CertificateID certificateId = new CertificateID(digest,
                    new X509CertificateHolder(issuer.getEncoded()), serialNumber);
            org.bouncycastle.asn1.ocsp.CertID asn1 = certificateId.toASN1Primitive();
            return new CertId(BcAlgorithmIdentifiers.fromBc(asn1.getHashAlgorithm()),
                    asn1.getIssuerNameHash().getOctets(), asn1.getIssuerKeyHash().getOctets(),
                    asn1.getSerialNumber().getValue());
        } catch (OperatorCreationException | OCSPException | CertificateException | IOException failure) {
            throw new IllegalArgumentException("Cannot compute OCSP CertID", failure);
        }
    }

    @Override
    public javax.security.auth.x500.X500Principal distinguishedName(
            java.util.List<zeroecho.pkix.RelativeDistinguishedName> relativeNames) {
        try {
            return new javax.security.auth.x500.X500Principal(buildX500Name(relativeNames).getEncoded());
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode distinguished name", failure);
        }
    }

    @Override
    public String distinguishedNameString(
            java.util.List<zeroecho.pkix.RelativeDistinguishedName> relativeNames) {
        return buildX500Name(relativeNames).toString();
    }

    // Each RDN and value is a distinct ASN.1 node in the resulting distinguished name.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static org.bouncycastle.asn1.x500.X500Name buildX500Name(
            java.util.List<zeroecho.pkix.RelativeDistinguishedName> relativeNames) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        for (zeroecho.pkix.RelativeDistinguishedName rdn : relativeNames) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(rdn.attributeTypeOid());
            org.bouncycastle.asn1.ASN1Encodable value = switch (rdn.stringType()) {
                case PRINTABLE -> new DERPrintableString(rdn.value(), true);
                case IA5 -> new DERIA5String(rdn.value(), true);
                case UTF8 -> new DERUTF8String(rdn.value());
            };
            builder.addRDN(oid, value);
        }
        return builder.build();
    }

    @Override
    public zeroecho.pkix.AlgorithmIdentifier parseAlgorithmIdentifier(byte[] der) {
        try {
            return BcAlgorithmIdentifiers.fromBc(AlgorithmIdentifier.getInstance(ASN1Primitive.fromByteArray(der)));
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid AlgorithmIdentifier DER", failure);
        }
    }

    @Override
    public zeroecho.pkix.AlgorithmIdentifier subjectPublicKeyAlgorithm(byte[] subjectPublicKeyInfoDer) {
        try {
            return BcAlgorithmIdentifiers.fromBc(
                    SubjectPublicKeyInfo.getInstance(subjectPublicKeyInfoDer).getAlgorithm());
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid SubjectPublicKeyInfo DER", failure);
        }
    }

    @Override
    public PublicKey publicKeyFromSubjectPublicKeyInfo(byte[] subjectPublicKeyInfoDer) {
        try {
            return new JcaPEMKeyConverter().getPublicKey(
                    SubjectPublicKeyInfo.getInstance(subjectPublicKeyInfoDer));
        } catch (IllegalArgumentException | IOException failure) {
            throw new IllegalArgumentException("Invalid SubjectPublicKeyInfo DER", failure);
        }
    }

    @Override
    public zeroecho.pkix.ocsp.OcspResponse parseOcspResponse(byte[] der) {
        return new BcOcspResponse(der);
    }

    @Override
    public java.util.List<zeroecho.pkix.RelativeDistinguishedName> parseDistinguishedName(byte[] nameDer) {
        org.bouncycastle.asn1.x500.X500Name name;
        try {
            name = org.bouncycastle.asn1.x500.X500Name.getInstance(
                    ASN1Primitive.fromByteArray(nameDer));
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid X.500 name DER", failure);
        }
        java.util.List<zeroecho.pkix.RelativeDistinguishedName> result = new java.util.ArrayList<>();
        for (org.bouncycastle.asn1.x500.RDN rdn : name.getRDNs()) {
            if (rdn == null || rdn.isMultiValued() || rdn.getFirst() == null) {
                throw new IllegalArgumentException("Multi-valued or empty relative distinguished name");
            }
            String oid = rdn.getFirst().getType().getId();
            org.bouncycastle.asn1.ASN1Encodable value = rdn.getFirst().getValue();
            zeroecho.pkix.DirectoryStringType type;
            if (value instanceof DERUTF8String) {
                type = zeroecho.pkix.DirectoryStringType.UTF8;
            } else if (value instanceof DERPrintableString) {
                type = zeroecho.pkix.DirectoryStringType.PRINTABLE;
            } else if (value instanceof DERIA5String) {
                type = zeroecho.pkix.DirectoryStringType.IA5;
            } else {
                throw new zeroecho.pkix.UnsupportedDirectoryStringException(
                        "Unsupported directory string type for attribute " + oid);
            }
            String text = ((org.bouncycastle.asn1.ASN1String) value).getString();
            result.add(new zeroecho.pkix.RelativeDistinguishedName(oid, text, type));
        }
        return java.util.List.copyOf(result);
    }

    @Override
    public java.util.List<zeroecho.pkix.RelativeDistinguishedName> parseDistinguishedNameString(String name) {
        try {
            return parseDistinguishedName(new org.bouncycastle.asn1.x500.X500Name(BCStyle.INSTANCE, name)
                    .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid distinguished name string", failure);
        }
    }

    @Override
    public byte[] subjectPublicKeyBytes(byte[] subjectPublicKeyInfoDer) {
        try {
            return SubjectPublicKeyInfo.getInstance(subjectPublicKeyInfoDer).getPublicKeyData().getBytes();
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid SubjectPublicKeyInfo DER", failure);
        }
    }

    @Override
    public byte[] subjectPublicKeyInfo(X509Certificate certificate) {
        try {
            return new X509CertificateHolder(certificate.getEncoded()).getSubjectPublicKeyInfo()
                    .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        } catch (IOException | CertificateException failure) {
            throw new IllegalArgumentException("Cannot read certificate SubjectPublicKeyInfo", failure);
        }
    }

    @Override
    public byte[] buildSubjectPublicKeyInfo(zeroecho.pkix.AlgorithmIdentifier algorithm, byte[] publicKeyBits) {
        try {
            return new SubjectPublicKeyInfo(BcAlgorithmIdentifiers.toBc(algorithm), publicKeyBits)
                    .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Cannot build SubjectPublicKeyInfo", failure);
        }
    }

    @Override
    public java.util.List<zeroecho.pkix.CertificateExtension> parseExtensions(byte[] der) {
        try {
            return BcExtensions.fromBc(org.bouncycastle.asn1.x509.Extensions.getInstance(
                    ASN1Primitive.fromByteArray(der)));
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid Extensions DER", failure);
        }
    }

    @Override
    public byte[] assembleCertificateOrCrl(byte[] tbs, byte[] signature, boolean crl) {
        try {
            org.bouncycastle.asn1.ASN1Sequence sequence = org.bouncycastle.asn1.ASN1Sequence.getInstance(
                    ASN1Primitive.fromByteArray(tbs));
            int algorithmIndex = crl ? 1
                    : sequence.getObjectAt(0) instanceof org.bouncycastle.asn1.ASN1TaggedObject ? 2 : 1;
            org.bouncycastle.asn1.ASN1Encodable algorithm = sequence.getObjectAt(algorithmIndex);
            byte[] encoded = new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                    sequence, algorithm, new org.bouncycastle.asn1.DERBitString(signature) }).getEncoded();
            if (crl) {
                parseCrl(encoded);
            } else {
                parseCertificate(encoded);
            }
            return encoded;
        } catch (IOException | IllegalArgumentException | ClassCastException failure) {
            throw new IllegalArgumentException("Cannot assemble signed object", failure);
        }
    }

    @Override
    public byte[] assembleOcspResponse(byte[] tbsResponseData, byte[] signatureAlgorithmDer, byte[] signature) {
        return assembleOcspResponse(tbsResponseData, signatureAlgorithmDer, signature, java.util.List.of());
    }

    @Override
    public byte[] assembleOcspResponse(byte[] tbsResponseData, byte[] signatureAlgorithmDer, byte[] signature,
            java.util.List<X509Certificate> chain) {
        byte[] encoded;
        try {
            AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(ASN1Primitive.fromByteArray(signatureAlgorithmDer));
            org.bouncycastle.asn1.ocsp.ResponseData data = org.bouncycastle.asn1.ocsp.ResponseData.getInstance(
                    ASN1Primitive.fromByteArray(tbsResponseData));
            encoded = BcOcspEncoding.assemble(data, algorithm, signature, BcOcspEncoding.certificates(chain));
        } catch (IOException | java.security.cert.CertificateEncodingException | IllegalArgumentException | ClassCastException failure) {
            throw new IllegalArgumentException("Cannot assemble OCSP response", failure);
        }
        zeroecho.pkix.ocsp.OcspResponse parsed = parseOcspResponse(encoded);
        if (!parsed.isSuccessful()) {
            throw new IllegalArgumentException("Assembled OCSP response is not successful");
        }
        return encoded;
    }

    @Override
    public byte[] encodeAlgorithmIdentifier(zeroecho.pkix.AlgorithmIdentifier algorithm) {
        try {
            return BcAlgorithmIdentifiers.toBc(algorithm).getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode AlgorithmIdentifier", failure);
        }
    }

    // Bouncy Castle reports malformed GeneralName encodings through several runtime subtypes.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    @Override
    public java.util.List<zeroecho.pkix.GeneralName> parseGeneralNames(byte[] der) {
        try {
            java.util.List<zeroecho.pkix.GeneralName> result = new java.util.ArrayList<>();
            for (org.bouncycastle.asn1.x509.GeneralName name : org.bouncycastle.asn1.x509.GeneralNames.getInstance(
                    ASN1Primitive.fromByteArray(der)).getNames()) {
                result.add(BcExtensions.fromBc(name));
            }
            return java.util.List.copyOf(result);
        } catch (IOException | RuntimeException failure) {
            throw new IllegalArgumentException("Invalid GeneralNames DER", failure);
        }
    }
}
