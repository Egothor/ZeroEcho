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

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

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
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.CouplingBetweenObjects" }) // The provider is the intentional BouncyCastle boundary adapter.
public final class BcPkixProvider implements PkixProvider {
    private static final int TLS_SIGNATURE_HEADER_BYTES = 4;

    // -------------------------------------------------------------------------
    // Certificate Transparency (RFC 9162) operations
    // -------------------------------------------------------------------------

    private static final ASN1ObjectIdentifier CT_POISON_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3");
    private static final ASN1ObjectIdentifier CT_SCT_LIST_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2");

    @Override
    public boolean verifyAlternativeSignature(X509Certificate certificate, PublicKey issuerAlternativeKey) {
        java.util.Objects.requireNonNull(certificate, "certificate");
        java.util.Objects.requireNonNull(issuerAlternativeKey, "issuerAlternativeKey");
        try {
            X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());
            if (holder.getExtension(Extension.subjectAltPublicKeyInfo) == null
                    || holder.getExtension(Extension.altSignatureAlgorithm) == null
                    || holder.getExtension(Extension.altSignatureValue) == null) {
                return false;
            }
            SubjectPublicKeyInfo alternativeKey = SubjectPublicKeyInfo.getInstance(
                    holder.getExtension(Extension.subjectAltPublicKeyInfo).getParsedValue());
            if (alternativeKey.getPublicKeyData().getPadBits() != 0) { return false; }
            org.bouncycastle.asn1.ASN1BitString alternativeValue = org.bouncycastle.asn1.ASN1BitString.getInstance(
                    holder.getExtension(Extension.altSignatureValue).getParsedValue());
            if (alternativeValue.getPadBits() != 0 || alternativeValue.getOctets().length == 0) { return false; }
            return holder.isAlternativeSignatureValid(
                    new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                            .setProvider("BC").build(issuerAlternativeKey));
        } catch (IOException | GeneralSecurityException | org.bouncycastle.cert.CertException
                | OperatorCreationException | IllegalArgumentException malformed) {
            return false;
        }
    }

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
            List<zeroecho.pkix.RelativeDistinguishedName> relativeNames) {
        try {
            return new javax.security.auth.x500.X500Principal(buildX500Name(relativeNames).getEncoded());
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode distinguished name", failure);
        }
    }

    @Override
    public String distinguishedNameString(
            List<zeroecho.pkix.RelativeDistinguishedName> relativeNames) {
        return buildX500Name(relativeNames).toString();
    }

    // Each RDN and value is a distinct ASN.1 node in the resulting distinguished name.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static org.bouncycastle.asn1.x500.X500Name buildX500Name(
            List<zeroecho.pkix.RelativeDistinguishedName> relativeNames) {
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
            return new JcaPEMKeyConverter().setProvider("BC").getPublicKey(
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
    public List<zeroecho.pkix.RelativeDistinguishedName> parseDistinguishedName(byte[] nameDer) {
        org.bouncycastle.asn1.x500.X500Name name;
        try {
            name = org.bouncycastle.asn1.x500.X500Name.getInstance(
                    ASN1Primitive.fromByteArray(nameDer));
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid X.500 name DER", failure);
        }
        List<zeroecho.pkix.RelativeDistinguishedName> result = new java.util.ArrayList<>();
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
        return List.copyOf(result);
    }

    @Override
    public List<zeroecho.pkix.RelativeDistinguishedName> parseDistinguishedNameString(String name) {
        try {
            return parseDistinguishedName(new org.bouncycastle.asn1.x500.X500Name(BCStyle.INSTANCE, name)
                    .getEncoded(ASN1Encoding.DER));
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
                    .getEncoded(ASN1Encoding.DER);
        } catch (IOException | CertificateException failure) {
            throw new IllegalArgumentException("Cannot read certificate SubjectPublicKeyInfo", failure);
        }
    }

    @Override
    public byte[] buildSubjectPublicKeyInfo(zeroecho.pkix.AlgorithmIdentifier algorithm, byte[] publicKeyBits) {
        try {
            return new SubjectPublicKeyInfo(BcAlgorithmIdentifiers.toBc(algorithm), publicKeyBits)
                    .getEncoded(ASN1Encoding.DER);
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Cannot build SubjectPublicKeyInfo", failure);
        }
    }

    @Override
    public List<zeroecho.pkix.CertificateExtension> parseExtensions(byte[] der) {
        try {
            return BcExtensions.fromBc(Extensions.getInstance(
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
            byte[] encoded = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
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
        return assembleOcspResponse(tbsResponseData, signatureAlgorithmDer, signature, List.of());
    }

    @Override
    public byte[] assembleOcspResponse(byte[] tbsResponseData, byte[] signatureAlgorithmDer, byte[] signature,
            List<X509Certificate> chain) {
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
            return BcAlgorithmIdentifiers.toBc(algorithm).getEncoded(ASN1Encoding.DER);
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode AlgorithmIdentifier", failure);
        }
    }

    // Bouncy Castle reports malformed GeneralName encodings through several runtime subtypes.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    @Override
    public List<zeroecho.pkix.GeneralName> parseGeneralNames(byte[] der) {
        try {
            List<zeroecho.pkix.GeneralName> result = new java.util.ArrayList<>();
            for (org.bouncycastle.asn1.x509.GeneralName name : org.bouncycastle.asn1.x509.GeneralNames.getInstance(
                    ASN1Primitive.fromByteArray(der)).getNames()) {
                result.add(BcExtensions.fromBc(name));
            }
            return List.copyOf(result);
        } catch (IOException | RuntimeException failure) {
            throw new IllegalArgumentException("Invalid GeneralNames DER", failure);
        }
    }

    // -------------------------------------------------------------------------
    // EST (RFC 7030) encoding operations
    // -------------------------------------------------------------------------

    @Override
    public byte[] encodeCertsOnly(List<X509Certificate> chain) {
        try {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new JcaCertStore(chain));
            return gen.generate(new CMSAbsentContent()).getEncoded();
        } catch (CMSException | java.security.cert.CertificateEncodingException | IOException failure) {
            throw new IllegalArgumentException("Cannot encode certs-only CMS message", failure);
        }
    }

    @Override
    public byte[] encodeCsrAttrs(List<zeroecho.pkix.csr.CsrAttribute> attributes) {
        try {
            ASN1EncodableVector seq = new ASN1EncodableVector();
            for (zeroecho.pkix.csr.CsrAttribute attr : attributes) {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(attr.oid()); // NOPMD AvoidInstantiatingObjectsInLoops - Each wire response/certificate/extension requires its own distinct immutable encoding object.
                if (attr.derValues().isEmpty()) {
                    seq.add(oid);
                } else {
                    ASN1EncodableVector vals = new ASN1EncodableVector(); // NOPMD AvoidInstantiatingObjectsInLoops - Each wire response/certificate/extension requires its own distinct immutable encoding object.
                    for (byte[] v : attr.derValues()) {
                        vals.add(ASN1Primitive.fromByteArray(v));
                    }
                    seq.add(new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{ // NOPMD AvoidInstantiatingObjectsInLoops - Each wire response/certificate/extension requires its own distinct immutable encoding object.
                            oid, new DERSet(vals) })); // NOPMD AvoidInstantiatingObjectsInLoops - Each wire response/certificate/extension requires its own distinct immutable encoding object.
                }
            }
            return new DERSequence(seq).getEncoded(ASN1Encoding.DER);
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Cannot encode CsrAttrs", failure);
        }
    }

    /**
     * {@inheritDoc}
     * @throws zeroecho.core.err.UnsupportedRoleException if the private key uses
     *         LMS/XMSS; rejection precedes CSR parsing and signing-engine initialization
     */
    @Override
    public byte[] buildServerKeygenCsr(byte[] originalCsrDer, PublicKey generatedPublicKey,
            PrivateKey generatedPrivateKey) {
        zeroecho.core.alg.common.sig.StatefulSigningGuard.requireStateless(null, generatedPrivateKey);
        try {
            org.bouncycastle.pkcs.PKCS10CertificationRequest original =
                    new org.bouncycastle.pkcs.PKCS10CertificationRequest(originalCsrDer);
            org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder builder =
                    new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                            original.getSubject(), generatedPublicKey);
            for (org.bouncycastle.asn1.pkcs.Attribute attribute : original.getAttributes()) {
                builder.addAttribute(attribute.getAttrType(), attribute.getAttributeValues());
            }
            String sigAlg = "EC".equalsIgnoreCase(java.util.Objects.requireNonNull(generatedPrivateKey.getAlgorithm()))
                    ? "SHA256withECDSA" : "SHA256withRSA";
            org.bouncycastle.operator.ContentSigner signer =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlg)
                            .setProvider("BC").build(generatedPrivateKey);
            return builder.build(signer).getEncoded();
        } catch (IOException | OperatorCreationException failure) {
            throw new IllegalArgumentException("Failed to build server-keygen CSR", failure);
        }
    }

    @Override
    public byte[] encryptPrivateKeyForRecipient(byte[] pkcs8PrivateKeyDer,
            X509Certificate recipientCertificate) {
        try {
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            String keyAlg = recipientCertificate.getPublicKey().getAlgorithm();
            if ("EC".equalsIgnoreCase(keyAlg) || "ECDH".equalsIgnoreCase(keyAlg)) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
                kpg.initialize(new ECGenParameterSpec("P-256"));
                java.security.KeyPair ephemeral = kpg.generateKeyPair();
                edGen.addRecipientInfoGenerator(
                        new JceKeyAgreeRecipientInfoGenerator(
                                CMSAlgorithm.ECDH_SHA256KDF,
                                ephemeral.getPrivate(),
                                ephemeral.getPublic(),
                                CMSAlgorithm.AES256_WRAP)
                                .addRecipient(recipientCertificate)
                                .setProvider("BC"));
            } else {
                edGen.addRecipientInfoGenerator(
                        new JceKeyTransRecipientInfoGenerator(recipientCertificate)
                                .setProvider("BC"));
            }
            org.bouncycastle.cms.CMSEnvelopedData enveloped = edGen.generate(
                    new CMSProcessableByteArray(pkcs8PrivateKeyDer),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM)
                            .setProvider("BC").build());
            return enveloped.toASN1Structure().getEncoded(ASN1Encoding.DER);
        } catch (CMSException | GeneralSecurityException | IOException failure) {
            throw new IllegalArgumentException("Cannot encrypt private key for recipient", failure);
        }
    }

    @Override
    public zeroecho.pkix.ct.PreCertificateResult buildPreCertificate(byte[] tbsCertificateDer,
            List<byte[]> issuerChainDer, ContentSigner signer) {
        try {
            TBSCertificate tbs = TBSCertificate.getInstance(ASN1Primitive.fromByteArray(tbsCertificateDer));

            ExtensionsGenerator extGen = new ExtensionsGenerator();
            Extensions existing = tbs.getExtensions();
            if (existing != null) {
                for (ASN1ObjectIdentifier oid : existing.getExtensionOIDs()) {
                    if (!oid.equals(CT_POISON_OID) && !oid.equals(CT_SCT_LIST_OID)) {
                        extGen.addExtension(existing.getExtension(oid));
                    }
                }
            }
            extGen.addExtension(CT_POISON_OID, true, DERNull.INSTANCE);

            byte[] preTbsDer = rebuildTbs(tbs, extGen.generate());

            try (java.io.OutputStream out = signer.contentStream()) {
                out.write(preTbsDer);
            }
            byte[] sig = signer.signature();
            byte[] preCertDer = assembleCertificateOrCrl(preTbsDer, sig, false);
            return new zeroecho.pkix.ct.PreCertificateResult(preCertDer, issuerChainDer);
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Cannot build CT pre-certificate", failure);
        }
    }

    @Override
    public byte[] embedScts(byte[] tbsCertificateDer,
            List<zeroecho.pkix.ct.SignedCertificateTimestamp> scts) {
        if (scts.isEmpty()) {
            throw new IllegalArgumentException("scts must contain at least one entry");
        }
        try {
            TBSCertificate tbs = TBSCertificate.getInstance(ASN1Primitive.fromByteArray(tbsCertificateDer));

            ExtensionsGenerator extGen = new ExtensionsGenerator();
            Extensions existing = tbs.getExtensions();
            if (existing != null) {
                for (ASN1ObjectIdentifier oid : existing.getExtensionOIDs()) {
                    if (!oid.equals(CT_POISON_OID) && !oid.equals(CT_SCT_LIST_OID)) {
                        extGen.addExtension(existing.getExtension(oid));
                    }
                }
            }
            extGen.addExtension(CT_SCT_LIST_OID, false, serializeSctList(scts));
            return rebuildTbs(tbs, extGen.generate());
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalArgumentException("Cannot embed SCTs in TBSCertificate", failure);
        }
    }

    private static byte[] rebuildTbs(TBSCertificate tbs, Extensions extensions) throws IOException {
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(tbs.getSerialNumber());
        tbsGen.setSignature(tbs.getSignature());
        tbsGen.setIssuer(tbs.getIssuer());
        tbsGen.setStartDate(tbs.getStartDate());
        tbsGen.setEndDate(tbs.getEndDate());
        tbsGen.setSubject(tbs.getSubject());
        tbsGen.setSubjectPublicKeyInfo(tbs.getSubjectPublicKeyInfo());
        if (tbs.getIssuerUniqueId() != null) {
            org.bouncycastle.asn1.ASN1BitString uid = tbs.getIssuerUniqueId();
            tbsGen.setIssuerUniqueID(
                    new org.bouncycastle.asn1.DERBitString(uid.getBytes(), uid.getPadBits()));
        }
        if (tbs.getSubjectUniqueId() != null) {
            org.bouncycastle.asn1.ASN1BitString sid = tbs.getSubjectUniqueId();
            tbsGen.setSubjectUniqueID(
                    new org.bouncycastle.asn1.DERBitString(sid.getBytes(), sid.getPadBits()));
        }
        tbsGen.setExtensions(extensions);
        return tbsGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER);
    }

    /** Serializes the SCT list as TLS {@code SignedCertificateTimestampList} bytes. */
    private static byte[] serializeSctList(
            List<zeroecho.pkix.ct.SignedCertificateTimestamp> scts) throws IOException {
        ByteArrayOutputStream allScts = new ByteArrayOutputStream();
        for (zeroecho.pkix.ct.SignedCertificateTimestamp sct : scts) {
            byte[] sctBytes = serializeSct(sct);
            allScts.write((sctBytes.length >> 8) & 0xFF);
            allScts.write(sctBytes.length & 0xFF);
            allScts.write(sctBytes);
        }
        byte[] listBytes = allScts.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream(2 + listBytes.length);
        result.write((listBytes.length >> 8) & 0xFF);
        result.write(listBytes.length & 0xFF);
        result.write(listBytes);
        return result.toByteArray();
    }

    /** Serializes a single SCT to its TLS wire format (RFC 6962 v1). */
    private static byte[] serializeSct(zeroecho.pkix.ct.SignedCertificateTimestamp sct)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sct.version());
        out.write(sct.logId());
        long ts = sct.timestamp().toEpochMilli();
        for (int i = 7; i >= 0; i--) {
            out.write((int) ((ts >> (i * 8)) & 0xFF));
        }
        byte[] exts = sct.extensions();
        out.write((exts.length >> 8) & 0xFF);
        out.write(exts.length & 0xFF);
        out.write(exts);
        int[] tlsCodes = jcaAlgToTlsCodes(sct.signatureAlgorithm());
        out.write(tlsCodes[0]);
        out.write(tlsCodes[1]);
        byte[] sig = sct.signature();
        out.write((sig.length >> 8) & 0xFF);
        out.write(sig.length & 0xFF);
        out.write(sig);
        return out.toByteArray();
    }

    @Override
    public zeroecho.pkix.ct.SignedCertificateTimestamp parseSct(byte[] jsonResponseBody) {
        String json = new String(jsonResponseBody, java.nio.charset.StandardCharsets.UTF_8).trim();
        int version = extractJsonInt(json, "sct_version");
        String idBase64 = extractJsonString(json, "id");
        long timestampMs = extractJsonLong(json, "timestamp");
        String extensionsBase64 = extractJsonString(json, "extensions");
        String sigBase64 = extractJsonString(json, "signature");

        byte[] logId = java.util.Base64.getDecoder().decode(idBase64);
        java.time.Instant timestamp = java.time.Instant.ofEpochMilli(timestampMs);
        byte[] extensions = extensionsBase64.isEmpty() ? new byte[0]
                : java.util.Base64.getDecoder().decode(extensionsBase64);
        byte[] digitallySigned = java.util.Base64.getDecoder().decode(sigBase64);

        if (digitallySigned.length < TLS_SIGNATURE_HEADER_BYTES) {
            throw new IllegalArgumentException("SCT DigitallySigned structure too short");
        }
        int sigLen = ((digitallySigned[2] & 0xFF) << 8) | (digitallySigned[3] & 0xFF);
        if (digitallySigned.length < 4 + sigLen) {
            throw new IllegalArgumentException("SCT DigitallySigned length mismatch");
        }
        byte[] sigBytes = java.util.Arrays.copyOfRange(digitallySigned, 4, 4 + sigLen);
        int hashCode = digitallySigned[0] & 0xFF;
        int sigCode = digitallySigned[1] & 0xFF;
        String jcaAlg = tlsCodesToJcaAlg(hashCode, sigCode);

        return new zeroecho.pkix.ct.SignedCertificateTimestamp(version, logId, timestamp, extensions,
                jcaAlg, sigBytes);
    }

    /** Extracts a quoted string value from a flat JSON object by key name. */
    private static String extractJsonString(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        if (keyIdx < 0) {
            throw new IllegalArgumentException("SCT JSON missing field: " + key);
        }
        int colonIdx = json.indexOf(':', keyIdx + search.length());
        if (colonIdx < 0) {
            throw new IllegalArgumentException("SCT JSON malformed at field: " + key);
        }
        int quoteStart = json.indexOf('"', colonIdx + 1);
        if (quoteStart < 0) {
            throw new IllegalArgumentException("SCT JSON field not a string: " + key);
        }
        int quoteEnd = json.indexOf('"', quoteStart + 1);
        if (quoteEnd < 0) {
            throw new IllegalArgumentException("SCT JSON unterminated string: " + key);
        }
        return json.substring(quoteStart + 1, quoteEnd);
    }

    /** Extracts an integer value from a flat JSON object by key name. */
    private static int extractJsonInt(String json, String key) {
        return (int) extractJsonLong(json, key);
    }

    /** Extracts a long value from a flat JSON object by key name. */
    private static long extractJsonLong(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        if (keyIdx < 0) {
            throw new IllegalArgumentException("SCT JSON missing field: " + key);
        }
        int colonIdx = json.indexOf(':', keyIdx + search.length());
        if (colonIdx < 0) {
            throw new IllegalArgumentException("SCT JSON malformed at field: " + key);
        }
        int valueStart = colonIdx + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }
        int valueEnd = valueStart;
        while (valueEnd < json.length() && (Character.isDigit(json.charAt(valueEnd))
                || json.charAt(valueEnd) == '-')) {
            valueEnd++;
        }
        try {
            return Long.parseLong(json.substring(valueStart, valueEnd));
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException("SCT JSON field not a number: " + key, failure);
        }
    }

    /** Maps TLS hash+sig codes back to a JCA algorithm name. */
    private static String tlsCodesToJcaAlg(int hashCode, int sigCode) {
        String hash = switch (hashCode) {
            case 2 -> "SHA1";
            case 3 -> "SHA224";
            case 4 -> "SHA256";
            case 5 -> "SHA384";
            case 6 -> "SHA512";
            default -> throw new IllegalArgumentException("Unknown TLS hash algorithm code: " + hashCode);
        };
        return hash + "with" + tlsSignatureName(sigCode);
    }

    private static String tlsSignatureName(int sigCode) {
        return switch (sigCode) {
            case 1 -> "RSA";
            case 2 -> "DSA";
            case 3 -> "ECDSA";
            default -> throw new IllegalArgumentException("Unknown TLS signature algorithm code: " + sigCode);
        };
    }

    @Override

    public boolean verifySct(zeroecho.pkix.ct.SignedCertificateTimestamp sct,
            PublicKey ctLogPublicKey, byte[] preCertDer) {
        try {
            // Signed data: sct fields + SHA-256(preCertDer) as a simplified verification input
            java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
            byte[] preCertHash = sha256.digest(preCertDer);

            ByteArrayOutputStream signed = new ByteArrayOutputStream();
            signed.write(sct.version());
            signed.write(sct.logId());
            long ts = sct.timestamp().toEpochMilli();
            for (int i = 7; i >= 0; i--) {
                signed.write((int) ((ts >> (i * 8)) & 0xFF));
            }
            byte[] exts = sct.extensions();
            signed.write((exts.length >> 8) & 0xFF);
            signed.write(exts.length & 0xFF);
            signed.write(exts);
            signed.write(preCertHash);

            java.security.Signature verifier = java.security.Signature.getInstance(sct.signatureAlgorithm());
            verifier.initVerify(ctLogPublicKey);
            verifier.update(signed.toByteArray());
            return verifier.verify(sct.signature());
        } catch (Exception failure) {
            throw new IllegalArgumentException("SCT verification failed: " + failure.getMessage(), failure);
        }
    }

    /** Maps a JCA algorithm name to TLS {hash_alg, sig_type} codes per RFC 5246 §7.4.1.4.1. */
    private static int[] jcaAlgToTlsCodes(String jcaAlgorithm) {
        String upper = jcaAlgorithm.toUpperCase(Locale.ROOT);
        int hash;
        if (upper.startsWith("SHA512")) {
            hash = 6;
        } else if (upper.startsWith("SHA384")) {
            hash = 5;
        } else if (upper.startsWith("SHA256")) {
            hash = 4;
        } else if (upper.startsWith("SHA224")) {
            hash = 3;
        } else if (upper.startsWith("SHA1") || upper.startsWith("SHA-1")) {
            hash = 2;
        } else {
            hash = 0;
        }
        int sig;
        if (upper.endsWith("ECDSA")) {
            sig = 3;
        } else if (upper.endsWith("RSA")) {
            sig = 1;
        } else if (upper.endsWith("DSA")) {
            sig = 2;
        } else {
            sig = 0;
        }
        return new int[]{hash, sig};
    }
}
