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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.ExtendedKeyUsage;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;

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
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.DomainCommandEncoding;
import zeroecho.pki.impl.core.async.DomainContinuationTemplate;
import zeroecho.pki.impl.core.async.PendingSigningOperation;
import zeroecho.pki.spi.store.DomainContinuationStore;
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

    /**
     * Creates an issuance backend with an optional explicit certificate binding.
     *
     * @param signingBus signing bus used to delegate certificate signing
     * @param signatureIdentity exact provider-independent signature identity
     * @param signatureBindingId optional explicit certificate-signature binding identifier
     * @param signingTtl positive maximum duration allowed for delegated signing
     */
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
        return issueEndEntity(request, issuerCertificate, issuerKeyRef, serial, CancellationSignal.NONE);
    }

    @Override
    public CredentialBundle issueEndEntity(ValidatedCertificateRequest request,
            DurableContentReference issuerCertificate,
            KeyRef issuerKeyRef, BigInteger serial, CancellationSignal cancellation) {
        if (request == null || issuerCertificate == null || issuerKeyRef == null || serial == null
                || serial.signum() <= 0 || serial.toByteArray().length > 20) {
            throw new IllegalArgumentException("Invalid validated end-entity issuance input");
        }
        byte[] issuerDer = materialize(issuerCertificate);
        X509Certificate issuer;
        try {
            issuer = parseIssuerCertificateOrThrow(issuerDer);
        } finally {
            java.util.Arrays.fill(issuerDer, (byte) 0);
        }
        javax.security.auth.x500.X500Principal issuerDn = issuer.getSubjectX500Principal();
        javax.security.auth.x500.X500Principal subjectDn = BcX509ProfileSupport.subject(request.subjectRdns());
        byte[] spki = parseSubjectPublicKeyInfo(request.exactPublicKey());

        CertificateBuilder builder = Pkix.certificateBuilder().issuer(issuerDn).serialNumber(serial)
                .validity(request.validity().notBefore(), request.validity().notAfter()).subject(subjectDn)
                .publicKeyInfo(spki);
        addLeafExtensions(builder, request);

        DomainContinuationTemplate domain = leafContinuation(request, issuerCertificate, issuerKeyRef, serial);
        try (PkiBusContentSigner signer = signer(issuerKeyRef, request.algorithmBindingPolicy(), cancellation,
                domain)) {
            X509Certificate leaf;
            try {
                leaf = builder.build(signer);
            } catch (PendingSigningOperation | zeroecho.pki.api.SigningExecutionException signingFailure) {
                throw signingFailure;
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
                return new CredentialBundle(credential, List.of(issuerCertificate));
            } finally {
                java.util.Arrays.fill(certDer, (byte) 0);
            }
        }
    }

    private static void addLeafExtensions(CertificateBuilder builder, ValidatedCertificateRequest request) {
        try {
            builder.basicConstraints(BasicConstraints.endEntity(), request.basicConstraintsCritical());
            if (!request.keyUsages().isEmpty()) {
                builder.keyUsage(toKeyUsages(request.keyUsages()), request.keyUsageCritical());
            }
            if (!request.extendedKeyUsages().isEmpty()) {
                List<String> purposes = request.extendedKeyUsages().stream().map(ExtendedKeyUsageId::oid).toList();
                builder.extendedKeyUsage(new ExtendedKeyUsage(purposes), request.extendedKeyUsageCritical());
            }
            if (!request.subjectAlternativeNames().isEmpty()) {
                builder.subjectAlternativeNames(toGeneralNames(request.subjectAlternativeNames()),
                        request.subjectAlternativeNameCritical());
            }
        } catch (Exception exception) {
            throw new PkiException("X.509 extension construction failed: code=EXTENSION_BUILD_FAILED");
        }
    }

    private static List<GeneralName> toGeneralNames(List<SubjectAlternativeName> names) {
        List<GeneralName> result = new ArrayList<>(names.size());
        for (SubjectAlternativeName name : names) {
            result.add(toGeneralName(name));
        }
        return result;
    }

    private PkiBusContentSigner signer(KeyRef keyRef,
            zeroecho.pki.api.profile.X509AlgorithmBindingPolicy bindingPolicy,
            CancellationSignal cancellation, DomainContinuationTemplate domainContinuation) {
        Optional<String> bindingId = bindingPolicy.certificateSignature()
                .map(zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference::bindingId);
        return bindingId.isPresent()
                ? new PkiBusContentSigner(signingBus, keyRef, signatureIdentity,
                        bindingId.orElseThrow(), signingTtl, cancellation, domainContinuation)
                : new PkiBusContentSigner(signingBus, keyRef, signatureIdentity, signingTtl, cancellation,
                        domainContinuation);
    }

    private static DomainContinuationTemplate leafContinuation(ValidatedCertificateRequest request,
            DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
        ValidatedCertificateRequest.FrozenIssuance frozen = request.frozenIssuance()
                .orElseThrow(() -> new PkiException("Frozen issuance selection is unavailable: "
                        + "code=ISSUANCE_CONTINUATION_UNAVAILABLE"));
        zeroecho.pki.api.issuance.IssuanceIntent intent = frozen.intent().orElse(null);
        String[] fields = {
                request.issuerCaId().value(), frozen.issuerId().value(), frozen.chainPathId().value(),
                frozen.chainPathCommitment(), request.profileReference().profileId(),
                Long.toString(request.profileReference().profileVersion()),
                HexFormat.of().formatHex(request.profileReference().canonicalSha256()),
                request.subjectRef().value(), request.validity().notBefore().toString(),
                request.validity().notAfter().toString(), serial.toString(), issuerKeyRef.value(),
                issuerCertificate.contentId(), issuerCertificate.sha256(),
                fingerprintEncoded(request.exactPublicKey()), intent == null ? "" : intent.issuanceId(),
                intent == null ? "" : intent.commandCommitment(), request.subjectRdns().toString(),
                request.subjectAlternativeNames().toString(), request.keyUsages().toString(),
                request.extendedKeyUsages().toString(), request.algorithmBindingPolicy().toString(),
                zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(request.executionEvidence()) };
        return intent == null
                ? DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                        "ISSUE_END_ENTITY", fields)
                : DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE,
                        intent.issuanceId(), "ISSUE_END_ENTITY", fields);
    }

    private static DomainContinuationTemplate caContinuation(ValidatedCaCertificateRequest request,
            DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
        ValidatedCaCertificateRequest.FrozenPublication frozen = request.frozenPublication()
                .orElseThrow(() -> new PkiException("Frozen CA publication selection is unavailable: "
                        + "code=CA_CONTINUATION_UNAVAILABLE"));
        return DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, request.operation().name(),
                request.formatId().value(), request.issuerCaId().value(), request.subjectCaId().value(),
                frozen.parentIssuerId().value(), frozen.parentPathId().value(), frozen.parentPathCommitment(),
                frozen.subjectKeyRef().value(),
                request.profileReference().profileId(), Long.toString(request.profileReference().profileVersion()),
                HexFormat.of().formatHex(request.profileReference().canonicalSha256()),
                request.subjectRef().value(), request.validity().notBefore().toString(),
                request.validity().notAfter().toString(), request.serial().toString(), issuerKeyRef.value(),
                issuerCertificate.contentId(), issuerCertificate.sha256(),
                fingerprintEncoded(request.exactPublicKey()), request.subjectRdns().toString(),
                request.policy().toString(), request.algorithmBindingPolicy().toString());
    }

    private static java.util.Set<KeyUsage> toKeyUsages(java.util.Set<LeafKeyUsage> usages) {
        java.util.Set<KeyUsage> result = java.util.EnumSet.noneOf(KeyUsage.class);
        for (LeafKeyUsage usage : usages) {
            result.add(switch (usage) {
                case DIGITAL_SIGNATURE -> KeyUsage.DIGITAL_SIGNATURE;
                case CONTENT_COMMITMENT -> KeyUsage.NON_REPUDIATION;
                case KEY_ENCIPHERMENT -> KeyUsage.KEY_ENCIPHERMENT;
                case DATA_ENCIPHERMENT -> KeyUsage.DATA_ENCIPHERMENT;
                case KEY_AGREEMENT -> KeyUsage.KEY_AGREEMENT;
                case ENCIPHER_ONLY -> KeyUsage.ENCIPHER_ONLY;
                case DECIPHER_ONLY -> KeyUsage.DECIPHER_ONLY;
            });
        }
        return result;
    }

    private static GeneralName toGeneralName(SubjectAlternativeName name) {
        return switch (name) {
            case SubjectAlternativeName.DnsName dns -> new GeneralName.DnsName(dns.value());
            case SubjectAlternativeName.IpAddress ip -> new GeneralName.IpAddress(ipLiteral(ip.bytes()));
            case SubjectAlternativeName.UriName uri -> new GeneralName.UniformResourceIdentifier(uri.value());
            case SubjectAlternativeName.Rfc822Name email -> new GeneralName.Rfc822Name(email.value());
        };
    }

    private static String ipLiteral(byte[] octets) {
        try {
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (UnknownHostException exception) {
            throw new PkiException("Invalid IP subject alternative name: code=EXTENSION_BUILD_FAILED");
        }
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
        return issueIntermediateCertificate(request, issuerCertificate, issuerKeyRef, CancellationSignal.NONE);
    }

    @Override
    public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest request,
            DurableContentReference issuerCertificate, KeyRef issuerKeyRef, CancellationSignal cancellation) {
        if (request == null || issuerCertificate == null || issuerKeyRef == null) {
            throw new IllegalArgumentException("validated CA issuance inputs must not be null");
        }
        if (!BcX509CredentialFramework.FORMAT_ID.equals(request.formatId())) {
            throw new IllegalArgumentException("Unsupported formatId");
        }

        byte[] issuerDer = materialize(issuerCertificate);
        X509Certificate issuer;
        try {
            issuer = parseIssuerCertificateOrThrow(issuerDer);
        } finally {
            java.util.Arrays.fill(issuerDer, (byte) 0);
        }
        byte[] subjectSpki = request.exactPublicKey().bytes();
        byte[] spki;
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

        javax.security.auth.x500.X500Principal issuerDn = issuer.getSubjectX500Principal();
        javax.security.auth.x500.X500Principal subjectDn = BcX509ProfileSupport.subject(request.subjectRdns());
        CertificateBuilder builder = Pkix.certificateBuilder().issuer(issuerDn).serialNumber(serial)
                .validity(validity.notBefore(), validity.notAfter()).subject(subjectDn).publicKeyInfo(spki);
        try {
            builder.basicConstraints(BasicConstraints.ca(request.policy().pathLengthConstraint()),
                    request.policy().basicConstraintsCritical());
            builder.keyUsage(java.util.EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                    request.policy().keyUsageCritical());
        } catch (Exception ex) {
            throw new PkiException("X.509 extension construction failed: code=EXTENSION_BUILD_FAILED");
        }

        DomainContinuationTemplate domain = caContinuation(request, issuerCertificate, issuerKeyRef);
        try (PkiBusContentSigner signer = signer(issuerKeyRef, request.algorithmBindingPolicy(), cancellation,
                domain)) {
            X509Certificate certificate;
            try {
                certificate = builder.build(signer);
            } catch (PendingSigningOperation | zeroecho.pki.api.SigningExecutionException signingFailure) {
                throw signingFailure;
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
                return new Credential(credId, request.formatId(), new IssuerRef(request.issuerCaId()), subjectRef,
                        validity, serial.toString(), publicKeyId, new CaProfileBinding(request.profileReference()),
                        CredentialStatus.ISSUED, content, SimpleAttributeSet.builder().build());
            } finally {
                java.util.Arrays.fill(certDer, (byte) 0);
            }
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

    private X509Certificate parseIssuerCertificateOrThrow(byte[] issuerCertDer) {
        try {
            new BcX509SignedObjectValidator(signingBus.authority()).validateCertificate(
                    new ImmutableByteContent(issuerCertDer), Optional.empty(), CancellationSignal.NONE);
            return Pkix.parseCertificate(issuerCertDer);
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

    private byte[] parseSubjectPublicKeyInfo(EncodedObject encoded) {
        byte[] bytes = encoded.bytes();
        try {
            return parseSubjectPublicKeyInfo(bytes);
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    private byte[] parseSubjectPublicKeyInfo(byte[] bytes) {
        try {
            new StreamingDerReader().validateSubjectPublicKeyInfo(bytes, MAXIMUM_SPKI_BYTES);
            new BcX509AlgorithmAdapter(signingBus.authority().bindings()).decode(
                    Pkix.subjectPublicKeyAlgorithm(bytes), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            return bytes.clone();
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
