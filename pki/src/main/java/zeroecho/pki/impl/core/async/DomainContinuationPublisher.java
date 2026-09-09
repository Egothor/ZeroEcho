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
package zeroecho.pki.impl.core.async;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

import java.security.cert.X509Certificate;

import zeroecho.pkix.Pkix;

import zeroecho.pki.api.status.StatusObjectType;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;

/** Reconstructs, validates, and idempotently publishes one durable domain result. */
final class DomainContinuationPublisher {
    private static final int MAXIMUM_SIGNATURE_BYTES = 1_048_576;
    private static final ThreadLocal<PublicationFaultInjector> PUBLICATION_FAULTS = new ThreadLocal<>();
    private final PkiStore store;
    private final CaContinuationPublisher caPublisher;
    private final StatusContinuationPublisher statusPublisher;
    private final DomainContentAccess contentAccess;

    /* default */ DomainContinuationPublisher(PkiStore store) {
        this.store = Objects.requireNonNull(store, "store");
        this.contentAccess = new DomainContentAccess(store);
        this.caPublisher = new CaContinuationPublisher(store, this);
        this.statusPublisher = new StatusContinuationPublisher(store, this);
    }

    /* default */ void publish(DomainContinuationStore.Record domain, EncodedObject result) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
        switch (domain.kind()) {
            case ISSUANCE -> publishIssuance(command, result);
            case STATUS -> statusPublisher.publish(command, result);
            case CA -> caPublisher.publish(command, result);
        }
    }

    /* default */ EncodedObject reconstruct(DomainContinuationStore.Record domain, EncodedObject signature) {
        byte[] signatureBytes = signature.bytes();
        if (signature.encoding() != Encoding.BINARY || signatureBytes.length == 0
                || signatureBytes.length > MAXIMUM_SIGNATURE_BYTES) {
            Arrays.fill(signatureBytes, (byte) 0);
            throw new PostconditionFailure("SIGNATURE_RESULT_INVALID");
        }
        byte[] tbs = contentAccess.materialize(domain.signingContent().orElseThrow(
                () -> new PostconditionFailure("SIGNING_CONTENT_INVALID")), "SIGNING_CONTENT_INVALID");
        try {
            boolean status = domain.kind() == DomainContinuationStore.Kind.STATUS;
            if (status && isOcsp(domain)) {
                return reconstructOcsp(tbs, signatureBytes, domain);
            }
            byte[] encoded = Pkix.assembleCertificateOrCrl(tbs, signatureBytes, status);
            return new EncodedObject(Encoding.DER, encoded);
        } catch (IllegalArgumentException malformed) {
            throw new PostconditionFailure("SIGNED_OBJECT_INVALID", malformed);
        } finally {
            Arrays.fill(tbs, (byte) 0);
            Arrays.fill(signatureBytes, (byte) 0);
        }
    }

    private static boolean isOcsp(DomainContinuationStore.Record domain) {
        return StatusObjectType.OCSP.name().equals(
                DomainCommandEncoding.decode(domain.command()).field(1));
    }

    // OCSP tbsResponseData does not embed the signature algorithm (unlike a CRL TBSCertList),
    // so the durable OCSP command carries the DER-encoded AlgorithmIdentifier in field 9. The
    // signed BasicOCSPResponse and its OCSPResponse SUCCESSFUL wrapper are reassembled here.
    private static EncodedObject reconstructOcsp(byte[] tbs, byte[] signatureBytes,
            DomainContinuationStore.Record domain) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
        command.requireFields(10);
        try {
            byte[] encoded = Pkix.assembleOcspResponse(tbs, HexFormat.of().parseHex(command.field(9)),
                    signatureBytes);
            return new EncodedObject(Encoding.DER, encoded);
        } catch (IllegalArgumentException malformed) {
            throw new PostconditionFailure("SIGNED_OBJECT_INVALID", malformed);
        }
    }

    private void publishIssuance(DomainCommandEncoding.Decoded command, EncodedObject result) {
        if (!"ISSUE_END_ENTITY".equals(command.operation())) {
            throw new PostconditionFailure("ISSUANCE_OPERATION_INVALID");
        }
        command.requireFields(23);
        IssuancePublication frozen = IssuancePublication.decode(command);
        IssuerGeneration generation = store.getIssuerGeneration(frozen.issuerId())
                .orElseThrow(() -> new PostconditionFailure("ISSUER_GENERATION_UNAVAILABLE"));
        IssuerChainPath path = store.getIssuerChainPath(frozen.pathId())
                .orElseThrow(() -> new PostconditionFailure("ISSUER_PATH_UNAVAILABLE"));
        requireFrozenIssuer(generation, path, frozen.authorityId(), frozen.issuerId(), frozen.pathCommitment());
        X509Certificate certificate = certificate(result);
        requireIssuedMetadata(certificate, frozen.serial(), frozen.notBefore(), frozen.notAfter(),
                frozen.publicKeyFingerprint());
        Credential issuer = store.getCredential(generation.credentialId())
                .orElseThrow(() -> new PostconditionFailure("ISSUER_CREDENTIAL_UNAVAILABLE"));
        verifyIssuerSignature(certificate, issuer.content());
        byte[] der = result.bytes();
        PkiId credentialId = new PkiId("x509:" + sha256(der));
        Optional<Credential> existing = store.getCredential(credentialId);
        if (existing.isPresent()) {
            Credential exact = issuanceCredential(credentialId, existing.orElseThrow().content(), frozen);
            requireCredential(existing.orElseThrow(), exact, der);
            Arrays.fill(der, (byte) 0);
            return;
        }
        DurableContentReference content = persist(der);
        boolean published = false;
        try {
            Credential credential = issuanceCredential(credentialId, content, frozen);
            store.putCredential(credential);
            published = true;
            afterDurablePublication(PublicationFaultPoint.AFTER_CREDENTIAL);
        } finally {
            Arrays.fill(der, (byte) 0);
            releaseUnlessPublished(content, published);
        }
    }

    private static Credential issuanceCredential(PkiId credentialId, DurableContentReference content,
            IssuancePublication frozen) {
        SimpleAttributeSet.Builder attributes = SimpleAttributeSet.builder();
        // Merge the co-committed execution evidence first, then the idempotency intent so the intent keys win
        // on overlap, matching the synchronous issuance attribute-merge order in DefaultIssuanceService.
        attributes.putAll(frozen.executionEvidence());
        frozen.intent().ifPresent(value -> putIntent(attributes, value));
        return new Credential(credentialId, new FormatId("x509"),
                new IssuerRef(frozen.authorityId(), frozen.issuerId(), frozen.pathId()), frozen.subject(),
                new Validity(frozen.notBefore(), frozen.notAfter()), frozen.serial().toString(),
                new PkiId("spki:" + frozen.publicKeyFingerprint()),
                new EndEntityProfileBinding(frozen.profile()),
                CredentialStatus.ISSUED, content, attributes.build());
    }

    /* default */ static CertificateProfileRef profile(DomainCommandEncoding.Decoded command, int index) {
        return new CertificateProfileRef(command.field(index), Long.parseLong(command.field(index + 1)),
                HexFormat.of().parseHex(command.field(index + 2)));
    }

    private static Optional<IssuanceIntent> issuanceIntent(DomainCommandEncoding.Decoded command,
            CertificateProfileRef profile, PkiId issuerId, PkiId pathId, String pathCommitment) {
        return command.field(15).isEmpty() ? Optional.empty()
                : Optional.of(new IssuanceIntent(command.field(15), command.field(16), profile, issuerId,
                        pathId, pathCommitment));
    }

    private static void putIntent(SimpleAttributeSet.Builder attributes, IssuanceIntent intent) {
        attributes.put(IssuanceIntent.ID_ATTRIBUTE, new AttributeValue.StringValue(intent.issuanceId()));
        attributes.put(IssuanceIntent.COMMITMENT_ATTRIBUTE,
                new AttributeValue.StringValue(intent.commandCommitment()));
    }

    /** Exact immutable issuance fields needed for deterministic publication. */
    private record IssuancePublication(PkiId authorityId, PkiId issuerId, PkiId pathId,
            String pathCommitment, CertificateProfileRef profile, SubjectRef subject,
            Instant notBefore, Instant notAfter, BigInteger serial, String publicKeyFingerprint,
            Optional<IssuanceIntent> intent, AttributeSet executionEvidence) {

        private static IssuancePublication decode(DomainCommandEncoding.Decoded command) {
            PkiId issuerId = new PkiId(command.field(1));
            PkiId pathId = new PkiId(command.field(2));
            String pathCommitment = command.field(3);
            CertificateProfileRef profile = DomainContinuationPublisher.profile(command, 4);
            return new IssuancePublication(new PkiId(command.field(0)), issuerId, pathId, pathCommitment,
                    profile, new SubjectRef(command.field(7)), Instant.parse(command.field(8)),
                    Instant.parse(command.field(9)), new BigInteger(command.field(10)), command.field(14),
                    issuanceIntent(command, profile, issuerId, pathId, pathCommitment),
                    DomainAttributeEncoding.decode(command.field(22)));
        }
    }

    /* default */ static void requireFrozenIssuer(IssuerGeneration generation, IssuerChainPath path,
            PkiId authorityId, PkiId issuerId, String pathCommitment) {
        if (!generation.authorityId().equals(authorityId) || !path.authorityId().equals(authorityId)
                || !path.issuerId().equals(issuerId) || !path.pathCommitment().equals(pathCommitment)) {
            throw new PostconditionFailure("FROZEN_ISSUER_SELECTION_DIFFERS");
        }
    }

    /* default */ static void requireIssuedMetadata(X509Certificate certificate, BigInteger serial,
            Instant notBefore, Instant notAfter, String publicKeyFingerprint) {
        if (!certificate.getSerialNumber().equals(serial)
                || !certificate.getNotBefore().toInstant().equals(notBefore)
                || !certificate.getNotAfter().toInstant().equals(notAfter)
                || !sha256SubjectPublicKey(certificate).equals(publicKeyFingerprint)) {
            throw new PostconditionFailure("ISSUED_CERTIFICATE_DIFFERS");
        }
    }

    /* default */ void verifyIssuerSignature(X509Certificate certificate,
            DurableContentReference issuerContent) {
        byte[] issuerDer = contentAccess.materialize(issuerContent, "CONTENT_UNAVAILABLE");
        try {
            X509Certificate issuerCertificate = certificate(issuerDer);
            try {
                certificate.verify(issuerCertificate.getPublicKey());
            } catch (java.security.GeneralSecurityException failure) {
                throw new PostconditionFailure("CERTIFICATE_SIGNATURE_DIFFERS", failure);
            }
        } finally {
            Arrays.fill(issuerDer, (byte) 0);
        }
    }

    /* default */ static X509Certificate certificate(EncodedObject encoded) {
        if (encoded.encoding() != Encoding.DER) {
            throw new PostconditionFailure("CERTIFICATE_ENCODING_INVALID");
        }
        return certificate(encoded.bytes());
    }

    /* default */ static X509Certificate certificate(byte[] encoded) {
        try {
            return Pkix.parseCertificate(encoded);
        } catch (IllegalArgumentException malformed) {
            throw new PostconditionFailure("CERTIFICATE_INVALID", malformed);
        }
    }


    /* default */ DurableContentReference persist(byte[] bytes) {
        return contentAccess.persist(bytes);
    }

    /* default */ void releaseUnlessPublished(DurableContentReference content, boolean published) {
        contentAccess.releaseUnlessPublished(content, published);
    }

    /* default */ void requireCredential(Credential actual, Credential expected, byte[] der) {
        if (!actual.equals(expected)) {
            throw new PostconditionFailure("PUBLISHED_CREDENTIAL_DIFFERS");
        }
        contentAccess.requireExact(actual.content(), der, "PUBLISHED_CREDENTIAL_CONTENT_DIFFERS");
    }

    /* default */ static void afterDurablePublication(PublicationFaultPoint point) {
        PublicationFaultInjector faults = PUBLICATION_FAULTS.get();
        if (faults != null) {
            faults.fail(point);
        }
    }

    /* default */ static void installPublicationFault(PublicationFaultInjector faults) {
        PUBLICATION_FAULTS.set(Objects.requireNonNull(faults, "faults"));
    }

    /* default */ static void clearPublicationFault() {
        PUBLICATION_FAULTS.remove();
    }

    /* default */ static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    // Certificate providers may surface encoding failures through provider-specific runtime exceptions.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ static String sha256SubjectPublicKey(X509Certificate certificate) {
        try {
            return sha256(Pkix.subjectPublicKeyInfo(certificate));
        } catch (RuntimeException malformed) {
            throw new PostconditionFailure("CERTIFICATE_PUBLIC_KEY_INVALID", malformed);
        }
    }

    /** Typed frozen-postcondition failure; persistence failures are deliberately not this type. */
    /* default */ static final class PostconditionFailure extends RuntimeException {
        private static final long serialVersionUID = 5811300261127019403L;

        /* default */ PostconditionFailure(String detailCode) {
            super(detailCode);
        }

        /* default */ PostconditionFailure(String detailCode, Throwable cause) {
            super(detailCode, cause);
        }
    }

    /** Deterministic durable domain-publication crash boundaries. */
    /* default */ enum PublicationFaultPoint {
        AFTER_CREDENTIAL,
        AFTER_STATUS,
        AFTER_ISSUER_GENERATION,
        AFTER_CHAIN_PATH,
        AFTER_CA,
        BEFORE_CONTINUATION_DONE
    }

    /** Package-local deterministic publication failure seam. */
    /* default */
    @FunctionalInterface
    interface PublicationFaultInjector {
        /** Invoked at one deterministic durable-publication boundary. */
        void fail(PublicationFaultPoint point);
    }
}
