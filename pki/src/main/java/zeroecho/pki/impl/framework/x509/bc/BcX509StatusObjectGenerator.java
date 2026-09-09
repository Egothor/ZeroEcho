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
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import zeroecho.pkix.Pkix;
import zeroecho.pkix.crl.CrlBuilder;
import zeroecho.pkix.crl.CrlReason;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.ocsp.ResponderId;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.DomainCommandEncoding;
import zeroecho.pki.impl.core.async.DomainContinuationTemplate;
import zeroecho.pki.impl.core.async.DomainAttributeEncoding;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.impl.framework.x509.X509SignedObjectCompletion;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pki.spi.framework.StatusObjectGenerator;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;

/**
 * Generator of X.509 status objects (CRLs and single-certificate OCSP responses),
 * routed through the ZeroEcho PKIX library and signed via {@link PkiSigningBus}.
 */
// The generator centralizes the finite CRL and OCSP ASN.1 variants behind one framework boundary.
@SuppressWarnings("PMD.CyclomaticComplexity")
public final class BcX509StatusObjectGenerator implements StatusObjectGenerator {
    private static final int MAXIMUM_CERTIFICATE_BYTES = 1024 * 1024;
    private static final String SHA1_OID = "1.3.14.3.2.26";
    private static final String OCSP_GOOD = "GOOD";
    private static final String OCSP_REVOKED = "REVOKED";

    private final PkiSigningBus signingBus;
    private final AlgorithmIdentity signatureIdentity;
    private final Duration signingTtl;
    private final Optional<String> signatureBindingId;

    /**
     * Creates the X.509 status object generator.
     *
     * @param signingBus           signing bus used to delegate signing; must not be {@code null}
     * @param signatureAlgorithmId non-blank signature algorithm identifier; must not be blank
     * @param signingTtl           positive maximum signing TTL; must be positive
     */
    public BcX509StatusObjectGenerator(PkiSigningBus signingBus, String signatureAlgorithmId, Duration signingTtl) {
        this(signingBus, signingBus.authority().resolveIdentity(signatureAlgorithmId), signingTtl);
    }

    /**
     * Creates the generator with an exact signature identity.
     *
     * @param signingBus        signing bus
     * @param signatureIdentity exact provider-independent signature identity
     * @param signingTtl        positive signing TTL
     */
    public BcX509StatusObjectGenerator(PkiSigningBus signingBus, AlgorithmIdentity signatureIdentity,
            Duration signingTtl) {
        this(signingBus, signatureIdentity, Optional.empty(), signingTtl);
    }

    /**
     * Creates a generator with an optional explicit signature binding.
     *
     * @param signingBus signing bus used to delegate status-object signing
     * @param signatureIdentity exact provider-independent signature identity
     * @param signatureBindingId optional explicit status-object signature binding identifier
     * @param signingTtl positive maximum duration allowed for delegated signing
     */
    public BcX509StatusObjectGenerator(PkiSigningBus signingBus, AlgorithmIdentity signatureIdentity,
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
        this.signatureBindingId = java.util.Objects.requireNonNull(signatureBindingId, "signatureBindingId");
        this.signingTtl = signingTtl;
    }

    @Override
    public X509SignedObjectCompletion generate(StatusObjectGenerateCommand command, CrlEntrySource crlEntries) {
        return generate(command, crlEntries, CancellationSignal.NONE);
    }

    @Override
    public X509SignedObjectCompletion generate(StatusObjectGenerateCommand command, CrlEntrySource crlEntries,
            CancellationSignal cancellation) {
        validateCommandOrThrow(command);
        if (crlEntries == null) {
            throw new IllegalArgumentException("crlEntries must not be null");
        }
        IssuerMaterial issuerMaterial = extractIssuerMaterialOrThrow(command.attributes());
        if (command.type() == StatusObjectType.OCSP) {
            return generateOcsp(command, issuerMaterial, cancellation);
        }
        BigInteger crlNumber = requiredCrlNumber(command.attributes(), BcX509Attributes.CRL_NUMBER, "CRL number");
        Optional<BigInteger> baseCrlNumber = command.type() == StatusObjectType.DELTA_CRL
                ? Optional.of(requiredCrlNumber(command.attributes(), BcX509Attributes.BASE_CRL_NUMBER,
                        "base CRL number"))
                : Optional.empty();
        Instant thisUpdate = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant nextUpdate = thisUpdate.plus(Duration.ofDays(7));
        DurableContentReference crl = null;
        DurableContentReference entriesRef = null;
        boolean accepted = false;
        try {
            List<zeroecho.pkix.crl.CrlEntry> entries = collectEntries(crlEntries);
            entriesRef = stageEntries(entries);
            DomainContinuationTemplate domain = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.STATUS, "GENERATE_STATUS",
                    command.issuerCaId().value(), command.type().name(), command.formatId().value(),
                    thisUpdate.toString(), nextUpdate.toString(), issuerMaterial.keyRef().value(),
                    entriesRef.contentId(), entriesRef.sha256(), DomainAttributeEncoding.encode(command.attributes()));
            X509SignedObjectCompletion completion;
            try (PkiBusContentSigner signer = signer(issuerMaterial.keyRef(), cancellation, domain)) {
                java.security.cert.X509CRL builtCrl = buildCrl(issuerMaterial.certificate(), thisUpdate, nextUpdate,
                        entries, crlNumber, baseCrlNumber, signer);
                byte[] crlDer;
                try {
                    crlDer = builtCrl.getEncoded();
                } catch (java.security.cert.CRLException exception) {
                    throw new PkiException("CRL encoding failed: code=STATUS_OBJECT_GENERATION_FAILED", exception);
                }
                crl = persistDer(crlDer);
                Arrays.fill(crlDer, (byte) 0);
                requireValidCrl(crl, signer, issuerMaterial.certificate(), thisUpdate, nextUpdate);
                StatusObject result = new StatusObject(new PkiId("crl:" + crl.sha256()), command.formatId(),
                        command.issuerCaId(), command.type(), thisUpdate, Optional.of(nextUpdate), crl,
                        command.attributes());
                completion = signingBus.authority().completeStatusObject(result, signer.executionPlan());
            }
            accepted = true;
            return completion;
        } catch (IOException exception) {
            throw new PkiException("CRL generation failed: code=SPOOL_STORAGE_FAILED", exception);
        } finally {
            releaseTemporary(entriesRef);
            if (!accepted) {
                releaseTemporary(crl);
            }
        }
    }

    private DurableContentReference stageEntries(List<zeroecho.pkix.crl.CrlEntry> entries) throws IOException {
        try (ContentSink sink = signingBus.beginContent(Encoding.DER, DurableContentReference.Lifecycle.TEMPORARY);
                OutputStream output = sink.outputStream()) {
            for (zeroecho.pkix.crl.CrlEntry entry : entries) {
                output.write((entry.serialNumber().toString() + '|' + entry.revocationTime().getEpochSecond() + '|'
                        + entry.reason().code() + '\n').getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            return sink.complete();
        }
    }

    private PkiBusContentSigner signer(KeyRef keyRef, CancellationSignal cancellation,
            DomainContinuationTemplate domain) {
        return signatureBindingId.isPresent()
                ? new PkiBusContentSigner(signingBus, keyRef, signatureIdentity, signatureBindingId.orElseThrow(),
                        signingTtl, cancellation, domain)
                : new PkiBusContentSigner(signingBus, keyRef, signatureIdentity, signingTtl, cancellation, domain);
    }

    private java.security.cert.X509CRL buildCrl(X509Certificate issuer, Instant thisUpdate, Instant nextUpdate,
            List<zeroecho.pkix.crl.CrlEntry> entries, BigInteger crlNumber, Optional<BigInteger> baseCrlNumber,
            PkiBusContentSigner signer) {
        CrlBuilder builder = Pkix.crlBuilder().issuer(issuer.getSubjectX500Principal())
                .thisUpdate(thisUpdate).nextUpdate(nextUpdate).crlNumber(crlNumber)
                .authorityKeyIdentifier(Pkix.subjectKeyIdentifier(issuer.getPublicKey()));
        baseCrlNumber.ifPresent(builder::deltaCrlIndicator);
        builder.addEntries(entries.iterator());
        return builder.build(signer);
    }

    private List<zeroecho.pkix.crl.CrlEntry> collectEntries(CrlEntrySource source) throws IOException {
        List<zeroecho.pkix.crl.CrlEntry> entries = new ArrayList<>();
        try (CrlEntrySource.Cursor cursor = source.openCursor(); TemporaryUniqueIndex serials =
                signingBus.beginUniqueIndex()) {
            long expectedOrdinal = 0L;
            while (cursor.next()) {
                if (cursor.ordinal() != expectedOrdinal) {
                    throw new PkiException("CRL entry order invalid: code=MALFORMED_SIGNED_OBJECT");
                }
                CrlEntry entry = cursor.current();
                if (!serials.add(unsignedSerial(entry))) {
                    throw new PkiException("Duplicate CRL serial: code=MALFORMED_SIGNED_OBJECT");
                }
                entries.add(new zeroecho.pkix.crl.CrlEntry(entry.serialNumber(),
                        entry.transitionTime().truncatedTo(ChronoUnit.SECONDS), toCrlReason(entry.reason())));
                expectedOrdinal = Math.addExact(expectedOrdinal, 1L);
            }
        }
        return entries;
    }

    private static byte[] unsignedSerial(CrlEntry entry) {
        byte[] encoded = entry.serialNumber().toByteArray();
        if (encoded.length > 1 && encoded[0] == 0) {
            return Arrays.copyOfRange(encoded, 1, encoded.length);
        }
        return encoded;
    }

    private void requireValidCrl(DurableContentReference crl, PkiBusContentSigner signer, X509Certificate issuer,
            Instant thisUpdate, Instant nextUpdate) throws IOException {
        requireAuthorizedSigningPlan(signingBus.authority(), signer.executionPlan(), signatureIdentity);
        try (RepeatableContent content = signingBus.openContent(crl)) {
            new BcX509SignedObjectValidator(signingBus.authority()).validateGeneratedCrl(content,
                    signer.executionPlan(), issuer, thisUpdate, Optional.of(nextUpdate), CancellationSignal.NONE);
        }
    }

    /*
     * The status-object postcondition accepts only the exact live plan minted by its runtime authority.
     */
    /* default */ static void requireAuthorizedSigningPlan(X509AuthoritySnapshot authority,
            X509ExecutionPlan<SignatureWorkflow> signingPlan, AlgorithmIdentity expectedIdentity) {
        authority.authorize(signingPlan, signingPlan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        if (!expectedIdentity.equals(signingPlan.selection().requested())) {
            throw new PkiException("CRL signing-plan substitution: code=BACKEND_RESULT_SUBSTITUTION");
        }
    }

    private X509SignedObjectCompletion generateOcsp(StatusObjectGenerateCommand command, IssuerMaterial issuerMaterial,
            CancellationSignal cancellation) {
        BigInteger serial = requiredCrlNumber(command.attributes(), BcX509Attributes.OCSP_TARGET_SERIAL,
                "OCSP target serial");
        if (serial.signum() <= 0) {
            throw new PkiException("Invalid OCSP target serial");
        }
        OcspTargetStatus target = resolveOcspTargetStatus(command.attributes());
        Instant thisUpdate = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant nextUpdate = thisUpdate.plus(Duration.ofDays(7));
        byte[] algorithm = probeSignatureAlgorithm(issuerMaterial.keyRef(), cancellation);
        DomainContinuationTemplate domain = DomainCommandEncoding.template(
                DomainContinuationStore.Kind.STATUS, "GENERATE_STATUS",
                command.issuerCaId().value(), command.type().name(), command.formatId().value(),
                thisUpdate.toString(), nextUpdate.toString(), issuerMaterial.keyRef().value(),
                "", "", DomainAttributeEncoding.encode(command.attributes()),
                java.util.HexFormat.of().formatHex(algorithm));
        DurableContentReference response = null;
        boolean accepted = false;
        try {
            X509SignedObjectCompletion completion;
            try (PkiBusContentSigner signer = signer(issuerMaterial.keyRef(), cancellation, domain)) {
                zeroecho.pkix.ocsp.CertId certId = Pkix.computeCertId(issuerMaterial.certificate(), serial, SHA1_OID);
                CertStatus status = target.revoked()
                        ? CertStatus.revoked(target.revocationTime().orElseThrow(), target.reason().orElseThrow())
                        : CertStatus.good();
                byte[] der = Pkix.ocspResponseBuilder()
                        .responderId(ResponderId.byName(issuerMaterial.certificate().getSubjectX500Principal()))
                        .producedAt(thisUpdate).addResponse(certId, status, thisUpdate, nextUpdate)
                        .build(signer, List.of());
                response = persistDer(der);
                requireAuthorizedSigningPlan(signingBus.authority(), signer.executionPlan(), signatureIdentity);
                try (RepeatableContent content = signingBus.openContent(response)) {
                    new BcX509SignedObjectValidator(signingBus.authority()).validateGeneratedOcsp(content,
                            signer.executionPlan(), issuerMaterial.certificate(), thisUpdate,
                            Optional.of(nextUpdate), CancellationSignal.NONE);
                }
                StatusObject result = new StatusObject(new PkiId("status:" + response.sha256()), command.formatId(),
                        command.issuerCaId(), command.type(), thisUpdate, Optional.of(nextUpdate), response,
                        command.attributes());
                completion = signingBus.authority().completeStatusObject(result, signer.executionPlan());
            }
            accepted = true;
            return completion;
        } catch (IOException exception) {
            throw new PkiException("OCSP status generation failed: code=SPOOL_STORAGE_FAILED", exception);
        } finally {
            if (!accepted) {
                releaseTemporary(response);
            }
        }
    }

    // Resolves the DER-encoded signature AlgorithmIdentifier without submitting a signing operation, so it
    // can be frozen into the durable OCSP command before the real signer runs.
    private byte[] probeSignatureAlgorithm(KeyRef keyRef, CancellationSignal cancellation) {
        try (PkiBusContentSigner probe = signatureBindingId.isPresent()
                ? new PkiBusContentSigner(signingBus, keyRef, signatureIdentity,
                        signatureBindingId.orElseThrow(), signingTtl, cancellation)
                : new PkiBusContentSigner(signingBus, keyRef, signatureIdentity, signingTtl, cancellation)) {
            return Pkix.encodeAlgorithmIdentifier(probe.algorithm());
        }
    }

    private DurableContentReference persistDer(byte[] der) throws IOException {
        try (ContentSink sink = signingBus.beginContent(Encoding.DER, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(der);
            return sink.complete();
        }
    }

    private static CrlReason toCrlReason(RevocationReason reason) {
        return switch (reason) {
            case UNSPECIFIED -> CrlReason.UNSPECIFIED;
            case KEY_COMPROMISE -> CrlReason.KEY_COMPROMISE;
            case CA_COMPROMISE -> CrlReason.CA_COMPROMISE;
            case AFFILIATION_CHANGED -> CrlReason.AFFILIATION_CHANGED;
            case SUPERSEDED -> CrlReason.SUPERSEDED;
            case CESSATION_OF_OPERATION -> CrlReason.CESSATION_OF_OPERATION;
            case CERTIFICATE_HOLD -> CrlReason.CERTIFICATE_HOLD;
            case REMOVE_FROM_CRL -> throw new IllegalArgumentException("REMOVE_FROM_CRL is not an active CRL entry");
            case PRIVILEGE_WITHDRAWN -> CrlReason.PRIVILEGE_WITHDRAWN;
            case AA_COMPROMISE -> CrlReason.AA_COMPROMISE;
        };
    }

    private static OcspTargetStatus resolveOcspTargetStatus(AttributeSet attributes) {
        String status = requiredString(attributes, BcX509Attributes.OCSP_CERT_STATUS, "OCSP certificate status");
        if (OCSP_GOOD.equals(status)) {
            return new OcspTargetStatus(false, Optional.empty(), Optional.empty());
        }
        if (!OCSP_REVOKED.equals(status)) {
            throw new PkiException("Invalid OCSP certificate status");
        }
        Instant time = requiredInstant(attributes, BcX509Attributes.OCSP_REVOCATION_TIME, "OCSP revocation time")
                .truncatedTo(ChronoUnit.SECONDS);
        RevocationReason reason = requiredReason(attributes);
        return new OcspTargetStatus(true, Optional.of(time), Optional.of(ocspReason(reason)));
    }

    private static String requiredString(AttributeSet attributes, AttributeId id, String label) {
        return attributes.get(id).filter(AttributeValue.StringValue.class::isInstance)
                .map(AttributeValue.StringValue.class::cast).map(AttributeValue.StringValue::value)
                .orElseThrow(() -> new PkiException("Missing " + label));
    }

    private static Instant requiredInstant(AttributeSet attributes, AttributeId id, String label) {
        return attributes.get(id).filter(AttributeValue.InstantValue.class::isInstance)
                .map(AttributeValue.InstantValue.class::cast).map(AttributeValue.InstantValue::value)
                .orElseThrow(() -> new PkiException("Missing " + label));
    }

    private static RevocationReason requiredReason(AttributeSet attributes) {
        String reason = requiredString(attributes, BcX509Attributes.OCSP_REVOCATION_REASON, "OCSP revocation reason");
        try {
            return RevocationReason.valueOf(reason);
        } catch (IllegalArgumentException ex) {
            throw new PkiException("Invalid OCSP revocation reason", ex);
        }
    }

    private static CrlReason ocspReason(RevocationReason reason) {
        return toCrlReason(reason == RevocationReason.REMOVE_FROM_CRL ? RevocationReason.UNSPECIFIED : reason);
    }

    /** Immutable resolved OCSP target status snapshot conveyed from the core service. */
    private record OcspTargetStatus(boolean revoked, Optional<Instant> revocationTime, Optional<CrlReason> reason) {
    }

    private static BigInteger requiredCrlNumber(AttributeSet attributes, AttributeId id, String label) {
        Optional<AttributeValue> value = attributes.get(id);
        if (value.isEmpty() || !(value.orElseThrow() instanceof AttributeValue.StringValue text)) {
            throw new PkiException("Missing " + label);
        }
        try {
            BigInteger number = new BigInteger(text.value());
            if (number.signum() < 0) {
                throw new PkiException("Invalid " + label);
            }
            return number;
        } catch (NumberFormatException ex) {
            throw new PkiException("Invalid " + label, ex);
        }
    }

    private void releaseTemporary(DurableContentReference reference) {
        if (reference != null) {
            signingBus.releaseContent(reference);
        }
    }

    private static void validateCommandOrThrow(StatusObjectGenerateCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        if (command.type() != StatusObjectType.CRL && command.type() != StatusObjectType.DELTA_CRL
                && command.type() != StatusObjectType.OCSP) {
            throw new IllegalArgumentException("Unsupported status object type: " + command.type());
        }
        FormatId formatId = command.formatId();
        if (!BcX509CredentialFramework.FORMAT_ID.equals(formatId)) {
            throw new IllegalArgumentException("Unsupported formatId: " + formatId.value());
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private IssuerMaterial extractIssuerMaterialOrThrow(AttributeSet attributes) {
        Optional<AttributeValue> issuerCertAttr = attributes.get(BcX509Attributes.ISSUER_CERT_DER);
        Optional<AttributeValue> issuerKeyAttr = attributes.get(BcX509Attributes.ISSUER_KEYREF);
        if (issuerCertAttr.isEmpty() || !(issuerCertAttr.get() instanceof AttributeValue.BytesValue)) {
            throw new PkiException("Missing issuer certificate");
        }
        if (issuerKeyAttr.isEmpty() || !(issuerKeyAttr.get() instanceof AttributeValue.StringValue)) {
            throw new PkiException("Missing issuer keyRef");
        }
        byte[] issuerDer = ((AttributeValue.BytesValue) issuerCertAttr.get()).value().clone();
        if (issuerDer.length > MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Invalid issuer certificate");
        }
        KeyRef keyRef = new KeyRef(((AttributeValue.StringValue) issuerKeyAttr.get()).value());
        X509Certificate issuer;
        try {
            new BcX509SignedObjectValidator(signingBus.authority()).validateCertificate(
                    new zeroecho.core.io.ImmutableByteContent(issuerDer), Optional.empty(), CancellationSignal.NONE);
            issuer = Pkix.parseCertificate(issuerDer);
        } catch (IOException | IllegalArgumentException ex) {
            throw new PkiException("Invalid issuer certificate");
        } finally {
            Arrays.fill(issuerDer, (byte) 0);
        }
        return new IssuerMaterial(issuer, keyRef);
    }

    /** Immutable issuer-side material required for status generation. */
    private record IssuerMaterial(X509Certificate certificate, KeyRef keyRef) {
    }
}
