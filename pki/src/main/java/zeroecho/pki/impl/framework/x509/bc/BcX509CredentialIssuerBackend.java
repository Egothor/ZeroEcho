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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Date;
import java.util.HexFormat;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.spi.store.ContentSink;

/**
 * Bouncy Castle backed X.509 credential issuance backend.
 *
 * <p>
 * This backend assembles X.509 certificate structures for end-entity and
 * intermediate CA issuance and delegates the actual signature operation to
 * {@link PkiSigningBus}. It is responsible for X.509-specific certificate
 * construction, extension population, issuer-material interpretation, and
 * normalization of the resulting PKI credential model.
 * </p>
 *
 * <p>
 * End-entity issuance derives all requester-influenced certificate material
 * exclusively from a profile-gated {@link ValidatedCertificateRequest}. CA
 * issuance derives certificate content exclusively from a proof-bound,
 * active-profile-validated request and separately supplied trusted issuer
 * material.
 * </p>
 *
 * <h2>Signing model</h2>
 * <p>
 * This backend never accesses private key material directly. Certificate
 * signing is delegated through {@link PkiSigningBus}, which bridges to the
 * configured PKI signing workflow boundary.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Issuer certificate bytes, subject public key data, and key references are
 * operationally sensitive and must not be logged unsafely.</li>
 * <li>Private key material is never returned or persisted by this class.</li>
 * <li>The correctness of produced credentials depends on the validity of the
 * provided issuer wiring attributes and on the downstream signing boundary
 * honoring the requested signature algorithm.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is immutable and is safe for concurrent use provided that the
 * supplied {@link PkiSigningBus} is safe for the intended runtime model.
 * </p>
 */
// PMD cannot infer that retaining backend causes would violate the redaction contract.
@SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.CyclomaticComplexity" })
public final class BcX509CredentialIssuerBackend implements CredentialIssuerBackend {

    private static final int MAXIMUM_CERTIFICATE_BYTES = 1024 * 1024;
    private static final int MAXIMUM_SPKI_BYTES = 1024 * 1024;

    private final PkiSigningBus signingBus;
    private final AlgorithmIdentity signatureIdentity;
    private final Duration signingTtl;

    /**
     * Creates the X.509 issuance backend.
     *
     * @param signingBus           signing bus used to delegate certificate signing;
     *                             must not be {@code null}
     * @param signatureAlgorithmId non-blank signature algorithm identifier in JCA
     *                             naming form; must not be {@code null} or blank
     * @param signingTtl           positive maximum signing TTL used for delegated
     *                             signing operations; must not be {@code null},
     *                             zero, or negative
     * @throws IllegalArgumentException if any argument violates the described
     *                                  contract
     */
    public BcX509CredentialIssuerBackend(PkiSigningBus signingBus, String signatureAlgorithmId, Duration signingTtl) {
        this(signingBus, signingBus.authority().resolveIdentity(signatureAlgorithmId), signingTtl);
    }

    /**
     * Creates the X.509 issuance backend with an exact signature identity.
     *
     * @param signingBus        signing bus used to delegate signing
     * @param signatureIdentity exact provider-independent signature identity
     * @param signingTtl        positive maximum signing TTL
     */
    public BcX509CredentialIssuerBackend(PkiSigningBus signingBus, AlgorithmIdentity signatureIdentity,
            Duration signingTtl) {
        this(signingBus, signatureIdentity, Optional.empty(), signingTtl);
    }

    /** Creates an issuance backend with an optional explicit certificate binding. */
    public BcX509CredentialIssuerBackend(PkiSigningBus signingBus, AlgorithmIdentity signatureIdentity,
            Optional<String> signatureBindingId, Duration signingTtl) {
        if (signingBus == null) {
            throw new IllegalArgumentException("signingBus must not be null");
        }
        if (signatureIdentity == null || signatureIdentity.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw new IllegalArgumentException("signatureIdentity must be a signature identity");
        }
        if (signingTtl == null || signingTtl.isZero() || signingTtl.isNegative()) {
            throw new IllegalArgumentException("signingTtl must be positive");
        }
        this.signingBus = signingBus;
        this.signatureIdentity = signatureIdentity;
        java.util.Objects.requireNonNull(signatureBindingId, "signatureBindingId");
        this.signingTtl = signingTtl;
    }

    /**
     * Issues an end-entity X.509 certificate and returns it as a credential bundle.
     *
     * <p>
     * The method consumes only validated identity and extension policy, trusted
     * issuer material, and an issuer-controlled serial. It delegates signing
     * through {@link PkiSigningBus}.
     * </p>
     *
     * @param request           gate-produced validated request
     * @param issuerCertificate trusted issuer certificate
     * @param issuerKeyRef      trusted issuer key reference
     * @param serial            issuer-controlled positive serial
     * @return issued X.509 credential bundle containing the leaf certificate and
     *         the issuer certificate as accompanying bundle material
     * @throws IllegalArgumentException if any argument violates the contract
     * @throws PkiException             if issuer wiring is missing or invalid,
     *                                  certificate construction fails, signing
     *                                  fails, or certificate encoding fails
     */
    @Override
    public CredentialBundle issueEndEntity(ValidatedCertificateRequest request,
            DurableContentReference issuerCertificate,
            KeyRef issuerKeyRef, BigInteger serial) {
        if (request == null || issuerCertificate == null || issuerKeyRef == null || serial == null
                || serial.signum() <= 0 || serial.toByteArray().length > 20) {
            throw new IllegalArgumentException("Invalid validated end-entity issuance input");
        }
        byte[] issuerDer = materialize(issuerCertificate);
        X509CertificateHolder issuer;
        try {
            issuer = parseIssuerCertificateOrThrow(issuerDer);
        } finally {
            java.util.Arrays.fill(issuerDer, (byte) 0);
        }
        X500Name issuerDn = issuer.getSubject();
        X500Name subjectDn = BcX509ProfileSupport.subject(request.subjectRdns());
        SubjectPublicKeyInfo spki = parseSubjectPublicKeyInfo(request.exactPublicKey());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuerDn, serial,
                Date.from(request.validity().notBefore()), Date.from(request.validity().notAfter()), subjectDn, spki);
        addLeafExtensions(builder, request);

        PkiBusContentSigner signer = signer(issuerKeyRef, request.algorithmBindingPolicy());
        X509CertificateHolder leaf;
        try {
            leaf = builder.build(signer);
        } catch (Exception ex) {
            throw new PkiException("Certificate signing failed: code=CERTIFICATE_SIGN_FAILED");
        }

        byte[] certDer;
        try {
            certDer = leaf.getEncoded();
        } catch (Exception ex) {
            throw new PkiException("Certificate encoding failed: code=CERTIFICATE_ENCODE_FAILED");
        }

        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));
        PkiId publicKeyId = new PkiId("spki:" + fingerprintEncoded(request.exactPublicKey()));

        try {
            DurableContentReference content = stageCertificate(certDer);
            validateGeneratedCertificate(content, signer);
            Credential credential = new Credential(credId, BcX509CredentialFramework.FORMAT_ID,
                    new IssuerRef(request.issuerCaId()), request.subjectRef(), request.validity(), serial.toString(),
                    publicKeyId, new EndEntityProfileBinding(request.profileReference()), CredentialStatus.ISSUED,
                    content, SimpleAttributeSet.builder().build());
            return new CredentialBundle(credential, java.util.List.of(issuerCertificate));
        } finally {
            java.util.Arrays.fill(certDer, (byte) 0);
        }
    }

    private static void addLeafExtensions(X509v3CertificateBuilder builder, ValidatedCertificateRequest request) {
        try {
            builder.addExtension(Extension.basicConstraints, request.basicConstraintsCritical(),
                    new BasicConstraints(false));
            if (!request.keyUsages().isEmpty()) {
                builder.addExtension(Extension.keyUsage, request.keyUsageCritical(),
                        new KeyUsage(toKeyUsageBits(request.keyUsages())));
            }
            if (!request.extendedKeyUsages().isEmpty()) {
                KeyPurposeId[] purposes = request.extendedKeyUsages().stream()
                        .map(value -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(value.oid())))
                        .toArray(KeyPurposeId[]::new);
                builder.addExtension(Extension.extendedKeyUsage, request.extendedKeyUsageCritical(),
                        new ExtendedKeyUsage(purposes));
            }
            if (!request.subjectAlternativeNames().isEmpty()) {
                GeneralName[] names = request.subjectAlternativeNames().stream()
                        .map(BcX509CredentialIssuerBackend::toGeneralName).toArray(GeneralName[]::new);
                builder.addExtension(Extension.subjectAlternativeName, request.subjectAlternativeNameCritical(),
                        new GeneralNames(names));
            }
        } catch (Exception exception) {
            throw new PkiException("X.509 extension construction failed: code=EXTENSION_BUILD_FAILED");
        }
    }

    private PkiBusContentSigner signer(KeyRef keyRef,
            zeroecho.pki.api.profile.X509AlgorithmBindingPolicy bindingPolicy) {
        Optional<String> bindingId = bindingPolicy.certificateSignature()
                .map(zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference::bindingId);
        return bindingId.isPresent()
                ? new PkiBusContentSigner(signingBus, keyRef, signatureIdentity,
                        bindingId.orElseThrow(), signingTtl)
                : new PkiBusContentSigner(signingBus, keyRef, signatureIdentity, signingTtl);
    }

    private static int toKeyUsageBits(java.util.Set<LeafKeyUsage> usages) {
        int bits = 0;
        for (LeafKeyUsage usage : usages) {
            bits |= switch (usage) {
                case DIGITAL_SIGNATURE -> KeyUsage.digitalSignature;
                case CONTENT_COMMITMENT -> KeyUsage.nonRepudiation;
                case KEY_ENCIPHERMENT -> KeyUsage.keyEncipherment;
                case DATA_ENCIPHERMENT -> KeyUsage.dataEncipherment;
                case KEY_AGREEMENT -> KeyUsage.keyAgreement;
                case ENCIPHER_ONLY -> KeyUsage.encipherOnly;
                case DECIPHER_ONLY -> KeyUsage.decipherOnly;
            };
        }
        return bits;
    }

    private static GeneralName toGeneralName(SubjectAlternativeName name) {
        return switch (name) {
            case SubjectAlternativeName.DnsName dns -> new GeneralName(GeneralName.dNSName, dns.value());
            case SubjectAlternativeName.IpAddress ip ->
                new GeneralName(GeneralName.iPAddress, new DEROctetString(ip.bytes()));
            case SubjectAlternativeName.UriName uri ->
                new GeneralName(GeneralName.uniformResourceIdentifier, uri.value());
            case SubjectAlternativeName.Rfc822Name email -> new GeneralName(GeneralName.rfc822Name, email.value());
        };
    }

    /**
     * Issues an intermediate CA X.509 certificate.
     *
     * <p>
     * The method consumes only the gate-produced validated CA request and trusted
     * issuer inputs, constructs an intermediate CA certificate with CA-oriented
     * extensions, delegates signing through {@link PkiSigningBus}, and returns the
     * resulting credential.
     * </p>
     *
     * @param request           gate-produced validated CA certificate request; must
     *                          not be {@code null}
     * @param issuerCertificate trusted issuer certificate; must not be {@code null}
     * @param issuerKeyRef      trusted issuer signing-key reference; must not be
     *                          {@code null}
     * @return issued intermediate CA credential
     * @throws IllegalArgumentException if {@code request} is {@code null} or uses
     *                                  an unsupported format identifier
     * @throws PkiException             if issuer wiring or subject wiring is
     *                                  missing or invalid, certificate construction
     *                                  fails, signing fails, or certificate
     *                                  encoding fails
     */
    @Override
    public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest request,
            DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
        if (request == null || issuerCertificate == null || issuerKeyRef == null) {
            throw new IllegalArgumentException("validated CA issuance inputs must not be null");
        }
        if (!BcX509CredentialFramework.FORMAT_ID.equals(request.formatId())) {
            throw new IllegalArgumentException("Unsupported formatId");
        }

        byte[] issuerDer = materialize(issuerCertificate);
        X509CertificateHolder issuer;
        try {
            issuer = parseIssuerCertificateOrThrow(issuerDer);
        } finally {
            java.util.Arrays.fill(issuerDer, (byte) 0);
        }
        byte[] subjectSpki = request.exactPublicKey().bytes();
        SubjectPublicKeyInfo spki;
        PkiId publicKeyId;
        try {
            spki = parseSubjectPublicKeyInfo(subjectSpki);
            publicKeyId = new PkiId("spki:" + sha256Hex(subjectSpki));
        } finally {
            java.util.Arrays.fill(subjectSpki, (byte) 0);
        }
        SubjectRef subjectRef = request.subjectRef();
        Validity validity = request.validity();
        BigInteger serial = request.serial();

        X500Name issuerDn = issuer.getSubject();
        X500Name subjectDn = BcX509ProfileSupport.subject(request.subjectRdns());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuerDn, serial,
                Date.from(validity.notBefore()), Date.from(validity.notAfter()), subjectDn, spki);
        try {
            builder.addExtension(Extension.basicConstraints, request.policy().basicConstraintsCritical(),
                    new BasicConstraints(request.policy().pathLengthConstraint()));
            builder.addExtension(Extension.keyUsage, request.policy().keyUsageCritical(),
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } catch (Exception ex) {
            throw new PkiException("X.509 extension construction failed: code=EXTENSION_BUILD_FAILED");
        }

        PkiBusContentSigner signer = signer(issuerKeyRef, request.algorithmBindingPolicy());
        X509CertificateHolder certificate;
        try {
            certificate = builder.build(signer);
        } catch (Exception ex) {
            throw new PkiException("Certificate signing failed: code=CERTIFICATE_SIGN_FAILED");
        }

        byte[] certDer;
        try {
            certDer = certificate.getEncoded();
        } catch (Exception ex) {
            throw new PkiException("Certificate encoding failed: code=CERTIFICATE_ENCODE_FAILED");
        }

        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));

        try {
            DurableContentReference content = stageCertificate(certDer);
            validateGeneratedCertificate(content, signer);
            return new Credential(credId, request.formatId(), new IssuerRef(request.issuerCaId()), subjectRef, validity,
                    serial.toString(), publicKeyId, new CaProfileBinding(request.profileReference()),
                    CredentialStatus.ISSUED, content,
                    SimpleAttributeSet.builder().build());
        } finally {
            java.util.Arrays.fill(certDer, (byte) 0);
        }
    }

    private DurableContentReference stageCertificate(byte[] certificate) {
        if (certificate.length > MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        try (ContentSink sink = signingBus.beginContent(Encoding.DER, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(certificate);
            return sink.complete();
        } catch (IOException exception) {
            throw new PkiException("Certificate staging failed: code=SPOOL_STORAGE_FAILED", exception);
        }
    }

    private void validateGeneratedCertificate(DurableContentReference reference, PkiBusContentSigner signer) {
        try (RepeatableContent content = signingBus.openContent(reference)) {
            new BcX509SignedObjectValidator(signingBus.authority()).validateGeneratedCertificate(content,
                    signer.executionPlan(), CancellationSignal.NONE);
        } catch (IOException | IllegalArgumentException exception) {
            signingBus.releaseContent(reference);
            throw new PkiException("Certificate postcondition failed: code=BACKEND_RESULT_SUBSTITUTION", exception);
        }
    }

    private byte[] materialize(DurableContentReference reference) {
        long length = reference.length();
        if (reference.encoding() != Encoding.DER || length <= 0L || length > MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        byte[] result = new byte[(int) length];
        try {
            readExact(reference, result);
            return result;
        } catch (IOException exception) {
            throw new PkiException("Certificate content failed: code=CONTENT_IO_FAILED", exception);
        }
    }

    private void readExact(DurableContentReference reference, byte[] result) throws IOException {
        try (RepeatableContent content = signingBus.openContent(reference); InputStream input = content.openStream()) {
            int offset = 0;
            while (offset != result.length) {
                int count = input.read(result, offset, result.length - offset);
                if (count < 0) {
                    throw new IOException("Certificate content is truncated");
                }
                offset += count;
            }
            if (input.read() >= 0) {
                throw new IOException("Certificate content has trailing bytes");
            }
        }
    }

    private X509CertificateHolder parseIssuerCertificateOrThrow(byte[] issuerCertDer) {
        try {
            new BcX509SignedObjectValidator(signingBus.authority()).validateCertificate(
                    new ImmutableByteContent(issuerCertDer), Optional.empty(), CancellationSignal.NONE);
            return new X509CertificateHolder(issuerCertDer);
        } catch (IOException | IllegalArgumentException ex) {
            throw new PkiException("Invalid issuer certificate: code=ISSUER_CERTIFICATE_INVALID");
        }
    }

    /**
     * Computes the SHA-256 digest of the supplied bytes and returns it as a
     * lowercase hexadecimal string.
     *
     * @param in input bytes; must not be {@code null}
     * @return hexadecimal SHA-256 digest
     * @throws IllegalStateException if SHA-256 is unexpectedly unavailable in the
     *                               runtime
     */
    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(in);
            try {
                return HexFormat.of().formatHex(digest);
            } finally {
                java.util.Arrays.fill(digest, (byte) 0);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 unavailable: code=DIGEST_UNAVAILABLE");
        }
    }

    private SubjectPublicKeyInfo parseSubjectPublicKeyInfo(EncodedObject encoded) {
        byte[] bytes = encoded.bytes();
        try {
            return parseSubjectPublicKeyInfo(bytes);
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    private SubjectPublicKeyInfo parseSubjectPublicKeyInfo(byte[] bytes) {
        try {
            new StreamingDerReader().validateSubjectPublicKeyInfo(bytes, MAXIMUM_SPKI_BYTES);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(bytes);
            new BcX509AlgorithmAdapter(signingBus.authority().bindings()).decode(spki.getAlgorithm(),
                    X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            return spki;
        } catch (IOException | IllegalArgumentException exception) {
            throw new PkiException("Invalid subject public key: code=SUBJECT_KEY_UNSUPPORTED");
        }
    }

    private static String fingerprintEncoded(EncodedObject encoded) {
        byte[] bytes = encoded.bytes();
        try {
            return sha256Hex(bytes);
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }
}
