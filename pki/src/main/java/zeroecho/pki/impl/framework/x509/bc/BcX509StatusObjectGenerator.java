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
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ContentSlice;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.framework.x509.StreamingDerWriter;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.StreamingDerReader.SignedObjectKind;
import zeroecho.pki.impl.framework.x509.StreamingDerReader.SignedObjectLayout;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SignedObjectCompletion;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pki.spi.framework.StatusObjectGenerator;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;

/**
 * Bouncy Castle backed generator of X.509 status objects.
 *
 * <p>
 * The current implementation supports only generation of X.509 certificate
 * revocation lists (CRLs). It assembles a version 2 CRL from issuer-side wiring
 * attributes, structured {@link CrlEntry} values, and delegated signing
 * performed via {@link PkiSigningBus}.
 * </p>
 *
 * <p>
 * The generator expects the following framework-specific issuer attributes to
 * be present in the supplied {@link StatusObjectGenerateCommand}:
 * </p>
 * <ul>
 * <li>{@link BcX509Attributes#ISSUER_CERT_DER} as an
 * {@link AttributeValue.BytesValue} containing the issuer certificate in DER
 * form,</li>
 * <li>{@link BcX509Attributes#ISSUER_KEYREF} as an
 * {@link AttributeValue.StringValue} identifying the issuer signing key.</li>
 * </ul>
 *
 * <p>
 * The produced {@link StatusObject} always carries:
 * </p>
 * <ul>
 * <li>type {@link StatusObjectType#CRL},</li>
 * <li>format {@link BcX509CredentialFramework#FORMAT_ID},</li>
 * <li>DER-encoded CRL content,</li>
 * <li>a deterministic object identifier derived from the SHA-256 digest of the
 * resulting CRL bytes.</li>
 * </ul>
 *
 * <h2>Revoked-entry handling</h2>
 * <p>
 * Structured entries preserve the full positive {@code BigInteger} serial,
 * authoritative transition instant, and exact supported revocation reason.
 * X.509 {@code Date} carries millisecond precision; this generator deliberately
 * truncates each transition instant to whole seconds only at the DER CRL-entry
 * boundary.
 * </p>
 *
 * <h2>Update semantics</h2>
 * <p>
 * The generated CRL uses the current instant as {@code thisUpdate} and a fixed
 * {@code nextUpdate} of seven days later.
 * </p>
 *
 * <h2>Signing model</h2>
 * <p>
 * This class never accesses private key material directly. Signing is delegated
 * to {@link PkiSigningBus} through {@link PkiBusContentSigner}.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Issuer certificate bytes, issuer key references, and revoked-serial input
 * values are operationally sensitive and must not be logged unsafely.</li>
 * <li>This generator produces CRL content only. It does not evaluate revocation
 * policy, validate issuer authorization, or determine revoked serials on its
 * own.</li>
 * <li>The correctness of the produced CRL depends on the validity of issuer
 * wiring attributes and on the downstream signing boundary honoring the
 * requested signature algorithm.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is immutable and safe for concurrent use provided that the
 * supplied {@link PkiSigningBus} is safe for the intended runtime model.
 * </p>
 */
public final class BcX509StatusObjectGenerator implements StatusObjectGenerator {

    private static final long EMPTY_CONTENT_LENGTH = 0L;

    private final PkiSigningBus signingBus;
    private final AlgorithmIdentity signatureIdentity;
    private final Duration signingTtl;

    /**
     * Creates the X.509 status object generator.
     *
     * @param signingBus           signing bus used to delegate CRL signing; must
     *                             not be {@code null}
     * @param signatureAlgorithmId non-blank signature algorithm identifier in JCA
     *                             naming form; must not be {@code null} or blank
     * @param signingTtl           positive maximum signing TTL used for delegated
     *                             signing operations; must not be {@code null},
     *                             zero, or negative
     * @throws IllegalArgumentException if any argument violates the described
     *                                  contract
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
        this.signingTtl = signingTtl;
    }

    /**
     * Generates an X.509 CRL status object.
     *
     * <p>
     * The supplied command must request {@link StatusObjectType#CRL} and must use
     * the X.509 format identifier {@link BcX509CredentialFramework#FORMAT_ID}. The
     * method validates the command, resolves issuer material, assembles the CRL,
     * adds revoked entries and authority key identifier, delegates signing, and
     * returns the resulting status object.
     * </p>
     *
     * <p>
     * The returned {@link StatusObject} contains:
     * </p>
     * <ul>
     * <li>a deterministic identifier of the form
     * {@code crl:&lt;sha256-of-crl-der&gt;},</li>
     * <li>the original issuer CA identifier from the command,</li>
     * <li>the current instant as {@code thisUpdate},</li>
     * <li>a {@code nextUpdate} seven days later,</li>
     * <li>the DER-encoded CRL,</li>
     * <li>the original command attributes unchanged.</li>
     * </ul>
     *
     * @param command    status object generation command; must not be {@code null}
     * @param crlEntries structured current CRL entries; must not be {@code null}
     * @return generated CRL status object
     * @throws IllegalArgumentException if {@code command} is {@code null}, if the
     *                                  requested status object type is unsupported,
     *                                  or if the requested format identifier is
     *                                  unsupported
     * @throws PkiException             if issuer wiring attributes are missing or
     *                                  invalid, if the issuer certificate cannot be
     *                                  parsed, if CRL extension construction fails,
     *                                  if signing fails, or if CRL encoding fails
     */
    @Override
    public X509SignedObjectCompletion generate(StatusObjectGenerateCommand command, CrlEntrySource crlEntries) {
        validateCommandOrThrow(command);
        if (crlEntries == null) {
            throw new IllegalArgumentException("crlEntries must not be null");
        }

        IssuerMaterial issuerMaterial = extractIssuerMaterialOrThrow(command.attributes());
        Instant thisUpdate = Instant.now();
        Instant nextUpdate = thisUpdate.plus(Duration.ofDays(7));
        DurableContentReference entries = null;
        DurableContentReference tbs = null;
        DurableContentReference crl = null;
        boolean accepted = false;
        try {
            entries = encodeEntries(crlEntries);
            PkiBusContentSigner signer = new PkiBusContentSigner(signingBus, issuerMaterial.keyRef(),
                    signatureIdentity, signingTtl);
            byte[] algorithm = signer.getAlgorithmIdentifier().getEncoded();
            tbs = encodeTbs(issuerMaterial.issuerHolder(), thisUpdate, nextUpdate, entries, algorithm);
            copyToSigner(tbs, signer);
            byte[] signature = signer.getSignature();
            crl = encodeOuter(tbs, algorithm, signature);
            requireValidResult(crl, tbs, signer.executionPlan(), signer.getAlgorithmIdentifier(), signature,
                    issuerMaterial.issuerHolder());
            StatusObject result = new StatusObject(new PkiId("crl:" + crl.sha256()), command.formatId(),
                    command.issuerCaId(),
                    command.type(), thisUpdate, Optional.of(nextUpdate), crl, command.attributes());
            X509SignedObjectCompletion completion = signingBus.authority().completeStatusObject(result,
                    signer.executionPlan());
            accepted = true;
            return completion;
        } catch (IOException | ArithmeticException exception) {
            throw new PkiException("CRL generation failed: code=SPOOL_STORAGE_FAILED", exception);
        } finally {
            if (!accepted) {
                releaseTemporary(crl);
            }
            releaseTemporary(tbs);
            releaseTemporary(entries);
        }
    }

    private void requireValidResult(DurableContentReference crl, DurableContentReference tbs,
            X509ExecutionPlan<SignatureWorkflow> signingPlan,
            org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm, byte[] signature, X509CertificateHolder issuer)
            throws IOException {
        requireAuthorizedSigningPlan(signingBus.authority(), signingPlan, signatureIdentity);
        try (RepeatableContent complete = signingBus.openContent(crl)) {
            StreamingDerReader reader = new StreamingDerReader();
            SignedObjectLayout layout = reader.inspectSignedObject(complete, SignedObjectKind.CRL,
                    CancellationSignal.NONE);
            byte[] expectedAlgorithm = algorithm.getEncoded();
            ContentComparison.requireExactSlice(complete, layout.tbsAlgorithmOffset(), layout.tbsAlgorithmLength(),
                    expectedAlgorithm, "CRL TBS binding mismatch");
            ContentComparison.requireExactSlice(complete, layout.outerAlgorithmOffset(), layout.outerAlgorithmLength(),
                    expectedAlgorithm, "CRL outer binding mismatch");
            ContentComparison.requireExactSlice(complete, layout.signatureOffset(), layout.signatureLength(), signature,
                    "CRL signature result mismatch");
            try (RepeatableContent expectedTbs = signingBus.openContent(tbs)) {
                if (!ContentComparison.contentEquals(complete, layout.tbsOffset(), layout.tbsLength(), expectedTbs)) {
                    throw new PkiException("CRL TBS substitution: code=BACKEND_RESULT_SUBSTITUTION");
                }
            }

            BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(signingBus.authority().bindings());
            AlgorithmIdentity actualSignature = adapter.decode(algorithm, X509AlgorithmRole.SIGNATURE_ALGORITHM);
            if (!signingPlan.selection().requested().equals(actualSignature)) {
                throw new PkiException("CRL binding mismatch: code=STATUS_OBJECT_BINDING_MISMATCH");
            }
            AlgorithmIdentity issuerKey = adapter.decode(issuer.getSubjectPublicKeyInfo().getAlgorithm(),
                    X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509ExecutionPlan<BcX509VerificationExecutor> plan = signingBus.authority().plan(actualSignature,
                    issuerKey, AlgorithmExecutionCapability.Direction.VERIFY,
                    Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID), "crl-postcondition",
                    BcX509VerificationExecutor.class);
            try (RepeatableContent signedContent = new ContentSlice(complete, layout.tbsOffset(),
                    layout.tbsLength())) {
                if (!plan.executor().verify(signingBus.authority(), plan, issuer.getSubjectPublicKeyInfo(), algorithm,
                        signedContent, signature)) {
                    throw new PkiException("CRL signature invalid: code=SIGNATURE_VERIFICATION_FAILED");
                }
            }
        } catch (java.security.GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException ex) {
            throw new PkiException("CRL verification failed: code=SIGNATURE_VERIFICATION_FAILED", ex);
        }
    }

    /*
     * The status-object postcondition accepts only the exact live plan minted by
     * its runtime authority. An equal public fingerprint cannot substitute for
     * opaque process-local provenance.
     */
    /* default */ static void requireAuthorizedSigningPlan(X509AuthoritySnapshot authority,
            X509ExecutionPlan<SignatureWorkflow> signingPlan, AlgorithmIdentity expectedIdentity) {
        authority.authorize(signingPlan, signingPlan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        if (!expectedIdentity.equals(signingPlan.selection().requested())) {
            throw new PkiException("CRL signing-plan substitution: code=BACKEND_RESULT_SUBSTITUTION");
        }
    }

    private DurableContentReference encodeEntries(CrlEntrySource source) throws IOException {
        try (ContentSink sink = signingBus.beginContent(Encoding.DER, DurableContentReference.Lifecycle.TEMPORARY);
                OutputStream output = sink.outputStream();
                CrlEntrySource.Cursor cursor = source.openCursor();
                TemporaryUniqueIndex serials = signingBus.beginUniqueIndex()) {
            long expectedOrdinal = 0L;
            while (cursor.next()) {
                if (cursor.ordinal() != expectedOrdinal) {
                    throw new PkiException("CRL entry order invalid: code=MALFORMED_SIGNED_OBJECT");
                }
                CrlEntry entry = cursor.current();
                if (!serials.add(unsignedSerial(entry))) {
                    throw new PkiException("Duplicate CRL serial: code=MALFORMED_SIGNED_OBJECT");
                }
                output.write(encodeEntry(entry));
                expectedOrdinal = Math.addExact(expectedOrdinal, 1L);
            }
            return sink.complete();
        }
    }

    private static byte[] unsignedSerial(CrlEntry entry) {
        byte[] encoded = entry.serialNumber().toByteArray();
        if (encoded.length > 1 && encoded[0] == 0) {
            return Arrays.copyOfRange(encoded, 1, encoded.length);
        }
        return encoded;
    }

    private static byte[] encodeEntry(CrlEntry entry) throws IOException {
        if (entry == null) {
            throw new IllegalArgumentException("CRL entry must not be null");
        }
        ASN1EncodableVector values = new ASN1EncodableVector(3);
        values.add(new ASN1Integer(entry.serialNumber()));
        values.add(new Time(Date.from(entry.transitionTime().truncatedTo(ChronoUnit.SECONDS))));
        int reason = CrlReasonAdapter.code(entry.reason());
        if (reason != CRLReason.unspecified) {
            Extension reasonExtension = Extension.create(Extension.reasonCode, false, CRLReason.lookup(reason));
            values.add(new Extensions(reasonExtension));
        }
        return new DERSequence(values).getEncoded();
    }

    private DurableContentReference encodeTbs(X509CertificateHolder issuer, Instant thisUpdate, Instant nextUpdate,
            DurableContentReference entries, byte[] algorithm) throws IOException {
        byte[] version = new ASN1Integer(1L).getEncoded();
        byte[] issuerName = issuer.getSubject().getEncoded();
        byte[] thisUpdateDer = new Time(Date.from(thisUpdate)).getEncoded();
        byte[] nextUpdateDer = new Time(Date.from(nextUpdate)).getEncoded();
        byte[] extensions = crlExtensions(issuer);
        long entriesLength = entries.length() == EMPTY_CONTENT_LENGTH
                ? EMPTY_CONTENT_LENGTH : StreamingDerWriter.encodedLength(entries.length());
        long valueLength = checkedSum(version.length, algorithm.length, issuerName.length, thisUpdateDer.length,
                nextUpdateDer.length, entriesLength, extensions.length);
        try (ContentSink sink = signingBus.beginContent(Encoding.DER, DurableContentReference.Lifecycle.TEMPORARY);
                OutputStream output = sink.outputStream()) {
            StreamingDerWriter.writeTagAndLength(output, StreamingDerWriter.SEQUENCE_TAG, valueLength);
            output.write(version);
            output.write(algorithm);
            output.write(issuerName);
            output.write(thisUpdateDer);
            output.write(nextUpdateDer);
            if (entries.length() != EMPTY_CONTENT_LENGTH) {
                StreamingDerWriter.writeTagAndLength(output, StreamingDerWriter.SEQUENCE_TAG, entries.length());
                try (RepeatableContent content = signingBus.openContent(entries);
                        InputStream input = content.openStream()) {
                    requireLength(entries.length(),
                            StreamingDerWriter.copy(input, output, CancellationSignal.NONE));
                }
            }
            output.write(extensions);
            return sink.complete();
        }
    }

    private static byte[] crlExtensions(X509CertificateHolder issuer) {
        try {
            AuthorityKeyIdentifier authorityKeyIdentifier = new JcaX509ExtensionUtils()
                    .createAuthorityKeyIdentifier(issuer.getSubjectPublicKeyInfo());
            Extensions extensions = new Extensions(
                    Extension.create(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier));
            return new DERTaggedObject(true, 0, extensions).getEncoded();
        } catch (Exception exception) {
            throw new PkiException("Failed to build CRL extensions", exception);
        }
    }

    private void copyToSigner(DurableContentReference tbs, PkiBusContentSigner signer) throws IOException {
        try (RepeatableContent content = signingBus.openContent(tbs);
                InputStream input = content.openStream();
                OutputStream output = signer.getOutputStream()) {
            requireLength(tbs.length(), StreamingDerWriter.copy(input, output, CancellationSignal.NONE));
        }
    }

    private DurableContentReference encodeOuter(DurableContentReference tbs, byte[] algorithm, byte[] signature)
            throws IOException {
        long bitStringValueLength = Math.addExact(1L, signature.length);
        long valueLength = checkedSum(tbs.length(), algorithm.length,
                StreamingDerWriter.encodedLength(bitStringValueLength));
        try (ContentSink sink = signingBus.beginContent(Encoding.DER, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            StreamingDerWriter.writeTagAndLength(output, StreamingDerWriter.SEQUENCE_TAG, valueLength);
            try (RepeatableContent content = signingBus.openContent(tbs);
                    InputStream input = content.openStream()) {
                requireLength(tbs.length(), StreamingDerWriter.copy(input, output, CancellationSignal.NONE));
            }
            output.write(algorithm);
            StreamingDerWriter.writeTagAndLength(output, StreamingDerWriter.BIT_STRING_TAG, bitStringValueLength);
            output.write(0);
            output.write(signature);
            return sink.complete();
        }
    }

    private static long checkedSum(long... values) {
        long total = 0L;
        for (long value : values) {
            total = Math.addExact(total, value);
        }
        return total;
    }

    private static void requireLength(long expected, long actual) throws IOException {
        if (expected != actual) {
            throw new IOException("Staged content length changed");
        }
    }

    private void releaseTemporary(DurableContentReference reference) {
        if (reference != null) {
            signingBus.releaseContent(reference);
        }
    }

    /**
     * Validates the high-level command contract for CRL generation.
     *
     * @param command command to validate; must not be {@code null}
     * @throws IllegalArgumentException if {@code command} is {@code null}, if the
     *                                  requested status object type is unsupported,
     *                                  or if the requested format identifier is
     *                                  unsupported
     */
    private static void validateCommandOrThrow(StatusObjectGenerateCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        if (command.type() != StatusObjectType.CRL) {
            throw new IllegalArgumentException("Unsupported status object type: " + command.type());
        }

        FormatId formatId = command.formatId();
        if (!BcX509CredentialFramework.FORMAT_ID.equals(formatId)) {
            throw new IllegalArgumentException("Unsupported formatId: " + formatId.value());
        }
    }

    /**
     * Resolves issuer material required for CRL generation from framework
     * attributes.
     *
     * @param attributes source attributes; must not be {@code null}
     * @return resolved issuer material
     * @throws PkiException if required issuer attributes are missing, use an
     *                      unexpected type, or contain an invalid issuer
     *                      certificate
     */
    private static IssuerMaterial extractIssuerMaterialOrThrow(AttributeSet attributes) {
        Optional<AttributeValue> issuerCertAttr = attributes.get(BcX509Attributes.ISSUER_CERT_DER);
        Optional<AttributeValue> issuerKeyAttr = attributes.get(BcX509Attributes.ISSUER_KEYREF);

        if (issuerCertAttr.isEmpty() || !(issuerCertAttr.get() instanceof AttributeValue.BytesValue)) {
            throw new PkiException("Missing issuer certificate");
        }
        if (issuerKeyAttr.isEmpty() || !(issuerKeyAttr.get() instanceof AttributeValue.StringValue)) {
            throw new PkiException("Missing issuer keyRef");
        }

        byte[] issuerDer = ((AttributeValue.BytesValue) issuerCertAttr.get()).value();
        KeyRef keyRef = new KeyRef(((AttributeValue.StringValue) issuerKeyAttr.get()).value());

        X509CertificateHolder issuerHolder;
        try {
            issuerHolder = new X509CertificateHolder(issuerDer);
        } catch (Exception ex) {
            throw new PkiException("Invalid issuer certificate", ex);
        }

        return new IssuerMaterial(issuerHolder, keyRef);
    }

    /**
     * Immutable issuer-side material required for CRL generation.
     *
     * @param issuerHolder parsed issuer certificate holder
     * @param keyRef       issuer signing key reference
     */
    private record IssuerMaterial(X509CertificateHolder issuerHolder, KeyRef keyRef) {
    }

    /**
     * Maps one bounded revocation-reason element to the standard CRL code.
     */
    private static final class CrlReasonAdapter {
        private static int code(RevocationReason reason) {
            return switch (reason) {
                case UNSPECIFIED -> CRLReason.unspecified;
                case KEY_COMPROMISE -> CRLReason.keyCompromise;
                case CA_COMPROMISE -> CRLReason.cACompromise;
                case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
                case SUPERSEDED -> CRLReason.superseded;
                case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
                case CERTIFICATE_HOLD -> CRLReason.certificateHold;
                case REMOVE_FROM_CRL ->
                    throw new IllegalArgumentException("REMOVE_FROM_CRL is not an active CRL entry");
                case PRIVILEGE_WITHDRAWN -> CRLReason.privilegeWithdrawn;
                case AA_COMPROMISE -> CRLReason.aACompromise;
            };
        }
    }

    /**
     * Incremental comparison of immutable signed-object slices.
     */
    private static final class ContentComparison {
        private static final int BUFFER_LENGTH = 8192;

        private static void requireExactSlice(RepeatableContent content, long offset, long length, byte[] expected,
                String message) throws IOException {
            if (length != expected.length) {
                throw new PkiException(message + ": code=STATUS_OBJECT_BINDING_MISMATCH");
            }
            try (InputStream input = new ContentSlice(content, offset, length).openStream()) {
                byte[] buffer = new byte[BUFFER_LENGTH];
                int expectedOffset = 0;
                while (expectedOffset != expected.length) {
                    int count = input.read(buffer, 0, Math.min(buffer.length, expected.length - expectedOffset));
                    if (count < 0 || !Arrays.equals(buffer, 0, count, expected, expectedOffset,
                            expectedOffset + count)) {
                        throw new PkiException(message + ": code=STATUS_OBJECT_BINDING_MISMATCH");
                    }
                    expectedOffset += count;
                }
                if (input.read() >= 0) {
                    throw new PkiException(message + ": code=STATUS_OBJECT_BINDING_MISMATCH");
                }
            }
        }

        private static boolean contentEquals(RepeatableContent content, long offset, long length,
                RepeatableContent expected) throws IOException {
            if (expected.length().isEmpty() || length != expected.length().getAsLong()) {
                return false;
            }
            try (InputStream left = new ContentSlice(content, offset, length).openStream();
                    InputStream right = expected.openStream()) {
                byte[] leftBuffer = new byte[BUFFER_LENGTH];
                byte[] rightBuffer = new byte[BUFFER_LENGTH];
                while (true) {
                    int leftCount = readBlock(left, leftBuffer);
                    int rightCount = readBlock(right, rightBuffer);
                    if (leftCount != rightCount) {
                        return false;
                    }
                    if (leftCount < 0) {
                        return true;
                    }
                    if (!Arrays.equals(leftBuffer, 0, leftCount, rightBuffer, 0, rightCount)) {
                        return false;
                    }
                }
            }
        }

        private static int readBlock(InputStream input, byte[] buffer) throws IOException {
            int total = 0;
            while (total != buffer.length) {
                int count = input.read(buffer, total, buffer.length - total);
                if (count < 0) {
                    return total == 0 ? -1 : total;
                }
                if (count != 0) {
                    total += count;
                }
            }
            return total;
        }
    }
}
