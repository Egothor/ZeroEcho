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

package zeroecho.pkix;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import zeroecho.pkix.cmp.CmpProtectedMessage;
import zeroecho.pkix.sign.ContentSigner;

/**
 * Strict RFC 7030 server-key-generation template and recipient validation.
 * Template public-key and signature values are never used as proof of possession;
 * callers separately enforce authenticated subject/SAN policy and verify the
 * generated certification request. Only asymmetric delivery to the authenticated
 * TLS certificate is supported.
 *
 * <p>This stateless facade retains no caller buffers. Requests are canonical DER
 * bounded at one MiB, with at most 32 attributes and 32 advertised capabilities.
 * Parsing takes linear time and bounded auxiliary storage in the encoded input.
 * Diagnostics omit request, recipient and key content.</p>
 */
public final class EstKeygen { // NOPMD CyclomaticComplexity - One closed EST negotiation/package facade; every individual validation and cryptographic step remains complexity-checked.
    private static final int REQUEST_FIELD_COUNT = 3;
    private static final int MAXIMUM_ATTRIBUTE_COUNT = 32;
    private static final int ATTRIBUTE_FIELD_COUNT = 2;
    private static final int ATTRIBUTE_VALUE_COUNT = 1;
    private static final int ECDH_CAPABILITY_FIELD_COUNT = 2;
    /** PKCS#9 client key-encipherment capabilities attribute. */
    public static final String CAPABILITIES_OID = "1.2.840.113549.1.9.15";
    /** RFC 7030 authenticated asymmetric recipient identifier attribute. */
    public static final String RECIPIENT_KEY_ID_OID = "1.2.840.113549.1.9.16.2.54";
    private static final String RSA = "1.2.840.113549.1.1.1";
    private static final String EC = "1.2.840.10045.2.1";
    private static final int MAXIMUM_REQUEST_BYTES = 1_048_576;

    private EstKeygen() { }

    /**
     * Validates the two required encryption attributes and the enclosing DER
     * request structure without evaluating its public key or signature.
     * This does not authorize requested subject names or negotiate a recipient.
     * @param templateDer exact original PKCS#10 template DER
     * @throws IllegalArgumentException for malformed, duplicate or missing attributes
     */
    public static void requireAttributes(byte[] templateDer) {
        attributes(templateDer);
    }

    /**
     * Requires the requested key identifier and an advertised supported transport
     * to match the actual authenticated TLS certificate. A certificate SKI is used
     * when present; otherwise SHA-256 of its exact SPKI is used. RSA transport
     * requires keyEncipherment and named P-256/P-384/P-521 ECDH requires
     * keyAgreement, unless the certificate has no KeyUsage restriction.
     *
     * <p>Supported capabilities are rsaEncryption with absent/NULL parameters or
     * ECDH-SHA256 with an AES-256-wrap AlgorithmIdentifier. No implicit recipient,
     * algorithm fallback or trust establishment is performed. Callers must check
     * certificate authentication and validity before invoking this method.</p>
     * @param templateDer exact original PKCS#10 template DER
     * @param authenticatedRecipient actual authenticated TLS end-client certificate
     * @throws IllegalArgumentException if structure, key identifier, usage or negotiation fails
     */
    public static void requireRecipient(byte[] templateDer, X509Certificate authenticatedRecipient) {
        Objects.requireNonNull(authenticatedRecipient, "authenticatedRecipient");
        Attributes attributes = attributes(templateDer);
        try {
            if (!MessageDigest.isEqual(attributes.keyId(), CmpProtectedMessage.certificateKeyId(authenticatedRecipient))) {
                throw invalid();
            }
            byte[] encoded = Pkix.subjectPublicKeyInfo(authenticatedRecipient);
            PublicKeyIdentity.fromSubjectPublicKeyInfo(encoded);
            SubjectPublicKeyInfo publicKey = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encoded));
            String algorithm = publicKey.getAlgorithm().getAlgorithm().getId();
            boolean[] usage = authenticatedRecipient.getKeyUsage();
            int requiredBit = RSA.equals(algorithm) ? 2 : EC.equals(algorithm) ? 4 : -1;
            if (requiredBit < 0 || usage != null && (usage.length <= requiredBit || !usage[requiredBit])) {
                throw invalid();
            }
            String capability = requiredBit == 2 ? RSA : CMSAlgorithm.ECDH_SHA256KDF.getId();
            if (!attributes.capabilities().contains(capability)) {
                throw invalid();
            }
        } catch (IOException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    /**
     * Signs one RFC 5958 asymmetric key package and encrypts that SignedData for
     * the exact negotiated TLS recipient. The package contains one version-zero
     * PKCS#8 private key; the outer CMS EnvelopedData uses AES-256-GCM and the
     * advertised RSA transport or ECDH-SHA256/AES-256-wrap mechanism. ECDH uses
     * the recipient's supported named curve. The resulting DER belongs in a
     * base64 MIME part with smime-type {@code server-generated-key}.
     *
     * <p>The supplied signer must come from lifecycle-owned stateless signing
     * custody (for example {@link Pkix#signer}); its signature is checked against
     * the first chain certificate. This method does not authorize or validate
     * that chain. Caller-owned input is neither retained nor cleared. Owned
     * plaintext encoding buffers are cleared; the caller must clear its PKCS#8
     * buffer after the call. Output is bounded at 16 MiB.</p>
     * @param templateDer exact original template, revalidated before cryptographic use
     * @param privateKeyDer generated PKCS#8 DER, at most one MiB
     * @param recipient authenticated TLS recipient certificate
     * @param generatorChain validated generator signer certificate first, at most 32 certificates
     * @param generatorSigner one-use signer bound to the generator certificate
     * @return caller-owned encrypted CMS DER
     * @throws IllegalArgumentException if negotiation, encoding, signature or encryption fails
     */
    public static byte[] signedEncryptedPackage(byte[] templateDer, byte[] privateKeyDer,
            X509Certificate recipient, List<X509Certificate> generatorChain, ContentSigner generatorSigner) {
        requireRecipient(templateDer, recipient);
        Objects.requireNonNull(privateKeyDer, "privateKeyDer");
        Objects.requireNonNull(generatorSigner, "generatorSigner");
        List<X509Certificate> chain = List.copyOf(generatorChain);
        if (privateKeyDer.length == 0 || privateKeyDer.length > MAXIMUM_REQUEST_BYTES || chain.isEmpty() || chain.size() > 32) {
            throw invalid();
        }
        byte[] packageDer = null;
        byte[] signedDer = null;
        try {
            validateChainSize(chain);
            packageDer = privateKeyPackage(privateKeyDer);
            CMSSignedDataGenerator signing = new CMSSignedDataGenerator();
            signing.addCertificates(new JcaCertStore(chain));
            signing.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                    .setSignedAttributeGenerator(parameters -> new org.bouncycastle.cms.DefaultSignedAttributeTableGenerator()
                            .getAttributes(parameters).remove(org.bouncycastle.asn1.cms.CMSAttributes.signingTime))
                    .build(signer(generatorSigner), chain.getFirst()));
            CMSSignedData signed = signing.generate(new CMSProcessableByteArray(new ASN1ObjectIdentifier("2.16.840.1.101.2.1.2.78.5"), packageDer), true);
            if (!signed.getSignerInfos().getSigners().iterator().next().verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(chain.getFirst()))) {
                throw invalid();
            }
            signedDer = signed.toASN1Structure().getContent().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            CMSEnvelopedDataGenerator encryption = new CMSEnvelopedDataGenerator();
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(Pkix.subjectPublicKeyInfo(recipient)));
            if (RSA.equals(spki.getAlgorithm().getAlgorithm().getId())) {
                encryption.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipient).setProvider("BC"));
            } else {
                String curve = ASN1ObjectIdentifier.getInstance(spki.getAlgorithm().getParameters()).getId();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
                generator.initialize(new ECGenParameterSpec(curve));
                KeyPair ephemeral = generator.generateKeyPair();
                encryption.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA256KDF,
                        ephemeral.getPrivate(), ephemeral.getPublic(), CMSAlgorithm.AES256_WRAP).addRecipient(recipient).setProvider("BC"));
            }
            byte[] result = encryption.generate(new CMSProcessableByteArray(CMSObjectIdentifiers.signedData, signedDer),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider("BC").build()).toASN1Structure().getEncoded(ASN1Encoding.DER);
            if (result.length > 16 * MAXIMUM_REQUEST_BYTES) {
                throw invalid();
            }
            return result;
        } catch (IOException | GeneralSecurityException | CMSException | OperatorCreationException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            throw invalid(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } finally {
            if (packageDer != null) {
                Arrays.fill(packageDer, (byte) 0);
            }
            if (signedDer != null) {
                Arrays.fill(signedDer, (byte) 0);
            }
        }
    }

    private static void validateChainSize(List<X509Certificate> chain) throws GeneralSecurityException {
        long chainBytes = 0;
        for (X509Certificate certificate : chain) {
            int length = certificate.getEncoded().length;
            if (length > MAXIMUM_REQUEST_BYTES || (chainBytes += length) > 4L * MAXIMUM_REQUEST_BYTES) {
                throw invalid();
            }
        }
    }

    private static byte[] privateKeyPackage(byte[] privateKeyDer) throws IOException {
        ASN1Sequence key = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(privateKeyDer));
        if (key.size() != 3 || !ASN1Integer.getInstance(key.getObjectAt(0)).hasValue(0)
                || !Arrays.equals(privateKeyDer, key.getEncoded(ASN1Encoding.DER))) {
            throw invalid();
        }
        PrivateKeyInfo.getInstance(key);
        return new DERSequence(key).getEncoded(ASN1Encoding.DER);
    }

    private static org.bouncycastle.operator.ContentSigner signer(ContentSigner delegate) {
        AlgorithmIdentifier algorithm = delegate.algorithm();
        org.bouncycastle.asn1.x509.AlgorithmIdentifier encoded;
        if ("1.2.840.113549.1.1.11".equals(algorithm.oid())
                && (algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.ABSENT || algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.DER_NULL)) {
            encoded = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm.oid()), DERNull.INSTANCE);
        } else if ("1.2.840.10045.4.3.2".equals(algorithm.oid()) && algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.ABSENT) {
            encoded = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm.oid()));
        } else {
            throw invalid();
        }
        return new org.bouncycastle.operator.ContentSigner() {
            @Override public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() { return encoded; }
            @Override public OutputStream getOutputStream() { return delegate.contentStream(); }
            @Override public byte[] getSignature() { return delegate.signature(); }
        };
    }

    private static Attributes attributes(byte[] encoded) {
        Objects.requireNonNull(encoded, "templateDer");
        if (encoded.length == 0 || encoded.length > MAXIMUM_REQUEST_BYTES) {
            throw invalid();
        }
        try {
            return readAttributes(templateAttributes(encoded));
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Provider and untrusted-input failures are normalized before crossing the public trust boundary.
            throw invalid(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private static ASN1Set templateAttributes(byte[] encoded) throws IOException {
        ASN1Primitive primitive = ASN1Primitive.fromByteArray(encoded);
        if (!Arrays.equals(encoded, primitive.getEncoded(ASN1Encoding.DER))) {
            throw invalid();
        }
        ASN1Sequence request = ASN1Sequence.getInstance(primitive);
        if (request.size() != REQUEST_FIELD_COUNT) {
            throw invalid();
        }
        ASN1Sequence proofAlgorithm = ASN1Sequence.getInstance(request.getObjectAt(1));
        if (proofAlgorithm.size() < 1 || proofAlgorithm.size() > 2
                || !(proofAlgorithm.getObjectAt(0) instanceof ASN1ObjectIdentifier)
                || ASN1BitString.getInstance(request.getObjectAt(2)).getPadBits() != 0) {
            throw invalid();
        }
        ASN1Sequence info = ASN1Sequence.getInstance(request.getObjectAt(0));
        if (info.size() != 4 || !ASN1Integer.getInstance(info.getObjectAt(0)).hasValue(0)) {
            throw invalid();
        }
        ASN1Sequence.getInstance(info.getObjectAt(1));
        SubjectPublicKeyInfo.getInstance(info.getObjectAt(2));
        ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(info.getObjectAt(3));
        if (!tagged.hasTag(BERTags.CONTEXT_SPECIFIC, 0)) {
            throw invalid();
        }
        return ASN1Set.getInstance(tagged, false);
    }

    private static Attributes readAttributes(ASN1Set values) {
        if (values.size() > MAXIMUM_ATTRIBUTE_COUNT) {
            throw invalid();
        }
        byte[] keyId = null;
        Set<String> capabilities = null;
        Set<String> seen = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            ASN1Sequence attribute = ASN1Sequence.getInstance(values.getObjectAt(index));
            if (attribute.size() != ATTRIBUTE_FIELD_COUNT) {
                throw invalid();
            }
            String oid = ASN1ObjectIdentifier.getInstance(attribute.getObjectAt(0)).getId();
            if (!seen.add(oid)) {
                throw invalid();
            }
            ASN1Set contents = ASN1Set.getInstance(attribute.getObjectAt(1));
            if (contents.size() != ATTRIBUTE_VALUE_COUNT) {
                throw invalid();
            }
            if (RECIPIENT_KEY_ID_OID.equals(oid)) {
                keyId = recipientKeyId(contents.getObjectAt(0));
            } else if (CAPABILITIES_OID.equals(oid)) {
                capabilities = capabilities(ASN1Sequence.getInstance(contents.getObjectAt(0)));
            } else if (!List.of("1.2.840.113549.1.9.14", "1.2.840.113549.1.9.7").contains(oid)) {
                throw invalid();
            }
        }
        if (keyId == null || capabilities == null) {
            throw invalid();
        }
        return new Attributes(keyId, capabilities);
    }

    private static byte[] recipientKeyId(ASN1Encodable value) {
        byte[] keyId = ASN1OctetString.getInstance(value).getOctets();
        if (keyId.length == 0 || keyId.length > 128) {
            throw invalid();
        }
        return keyId;
    }

    private static Set<String> capabilities(ASN1Sequence values) {
        if (values.size() == 0 || values.size() > MAXIMUM_ATTRIBUTE_COUNT) {
            throw invalid();
        }
        Set<String> all = new HashSet<>();
        Set<String> supported = new HashSet<>();
        for (int index = 0; index < values.size(); index++) {
            ASN1Sequence capability = ASN1Sequence.getInstance(values.getObjectAt(index));
            if (capability.size() < 1 || capability.size() > 2) {
                throw invalid();
            }
            String oid = ASN1ObjectIdentifier.getInstance(capability.getObjectAt(0)).getId();
            if (!all.add(oid)) {
                throw invalid();
            }
            if (supportedCapability(oid, capability)) {
                supported.add(oid);
            }
        }
        return Set.copyOf(supported);
    }

    private static boolean supportedCapability(String oid, ASN1Sequence capability) {
        if (RSA.equals(oid)) {
            if (capability.size() == 2 && !(capability.getObjectAt(1) instanceof ASN1Null)) {
                throw invalid();
            }
            return true;
        }
        if (CMSAlgorithm.ECDH_SHA256KDF.getId().equals(oid)) {
            if (capability.size() != ECDH_CAPABILITY_FIELD_COUNT) {
                throw invalid();
            }
            ASN1Sequence wrap = ASN1Sequence.getInstance(capability.getObjectAt(1));
            if (wrap.size() != 1 || !CMSAlgorithm.AES256_WRAP.equals(ASN1ObjectIdentifier.getInstance(wrap.getObjectAt(0)))) {
                throw invalid();
            }
            return true;
        }
        return false;
    }

    private record Attributes(byte[] keyId, Set<String> capabilities) { }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid EST key-generation template or recipient"); }
}
