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

package zeroecho.pki.impl.core.continuation;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ContentSlice;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.StreamingCrlSignatureVerifier;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.StreamingDerWriter;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.Pkix;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Streams one full CRL in O(B) I/O and bounded heap, except pure EdDSA provider buffering.
 */
final class FullCrlContinuationPublisher {
    private static final int MAXIMUM_SIGNATURE_BYTES = 1_048_576;
    private static final AttributeId COMMAND =
            new AttributeId("zeroecho.pki.full-crl.command-sha256");
    private final PkiStore store;
    private final X509BindingCatalog bindings;
    private final long pureEdDsaMaximumTbsBytes;

    /**
     * Creates a streaming CRL publisher with a finite pure-EdDSA buffering limit.
     *
     * @param store borrowed PKI store; must not be null
     * @param bindings borrowed immutable X.509 binding catalogue
     * @param maximum maximum pure-EdDSA TBS message length in bytes
     */
    /* default */ FullCrlContinuationPublisher(PkiStore store, X509BindingCatalog bindings, long maximum) {
        this.store = store;
        this.bindings = bindings;
        this.pureEdDsaMaximumTbsBytes = maximum;
    }

    /**
     * Assembles, verifies, and idempotently publishes a full or delta CRL from retained signing output.
     *
     * @param domain frozen durable domain continuation record; must not be null
     * @param signature completed bounded binary signature result; must not be null
     * @return bounded encoded publication result
     * @throws DomainContinuationPublisher.PostconditionFailure if frozen content or result postconditions differ
     * @throws zeroecho.pki.api.PkiException if content or metadata persistence fails
     */
    /* default */ EncodedObject publish(DomainContinuationStore.Record domain, EncodedObject signature) {
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(new DomainContinuationTemplate(
                domain.kind(), domain.correlationId(), domain.command(), domain.commandCommitment()));
        DurableContentReference tbs = domain.signingContent().orElseThrow();
        FullCrlSigningCommand.requireTbs(command, tbs);
        byte[] bytes = signature.bytes();
        DurableContentReference assembled = null;
        boolean published = false;
        try {
            if (signature.encoding() != Encoding.BINARY || bytes.length == 0 || bytes.length > MAXIMUM_SIGNATURE_BYTES) {
                throw invalid("FULL_CRL_SIGNATURE_INVALID");
            }
            FullCrlSigningCommand.requireAdmission(command.field(8), tbs.length(), pureEdDsaMaximumTbsBytes);
            byte[] algorithm = HexFormat.of().parseHex(command.field(9));
            X509Certificate issuer = issuer(command);
            assembled = assemble(tbs, algorithm, bytes);
            validate(assembled, command, issuer, algorithm, bytes);
            PkiId id = new PkiId("crl:" + assembled.sha256());
            Optional<StatusObject> existing = store.getStatusObject(id);
            if (existing.isPresent()) {
                requirePublished(existing.orElseThrow(), domain, assembled);
                if (store.supportsStatusScheduling()) {
                    store.putStatusObjectFromSigning(existing.orElseThrow(), domain.operationId(), domain.commandCommitment());
                }
            } else {
                store.putStatusObjectFromSigning(status(id, assembled, domain), domain.operationId(), domain.commandCommitment());
                published = true;
                DomainContinuationPublisher.afterDurablePublication(DomainContinuationPublisher.PublicationFaultPoint.AFTER_STATUS);
            }
            return new EncodedObject(Encoding.BINARY, id.value().getBytes(StandardCharsets.US_ASCII));
        } catch (IOException failure) {
            throw new PkiException("Full CRL content processing failed", failure);
        } catch (IllegalArgumentException failure) {
            throw new DomainContinuationPublisher.PostconditionFailure(
                    "FULL_CRL_ADMISSION_INVALID", failure);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (assembled != null && !published) {
                new DomainContentAccess(store).releaseUnlessPublished(assembled, false);
            }
        }
    }

    /**
     * Verifies captured parent/child bindings and publishes the completed hybrid CRL.
     *
     * @param domain frozen durable domain continuation record; must not be null
     * @param execution captured hybrid execution linking parent and native child
     * @param parent retained alternative-signature parent workflow
     * @param child completed native-signature child workflow
     * @return encoded hybrid CRL publication result
     * @throws DomainContinuationPublisher.PostconditionFailure if frozen content or result
     *     postconditions differ
     * @throws PkiException if hybrid signatures, content processing or finite admission validation
     *     fails
     */
    /* default */ EncodedObject publishHybrid(
            DomainContinuationStore.Record domain,
            zeroecho.pki.spi.store.CrlHybridExecution execution,
            zeroecho.pki.spi.store.SignWorkflowStore.Workflow parent,
            zeroecho.pki.spi.store.SignWorkflowStore.Workflow child) {
        return new HybridPublication().publish(domain, execution, parent, child);
    }

    private X509Certificate issuer(DomainCommandEncoding.Decoded command) {
        IssuerGeneration generation = store.getIssuerGeneration(new PkiId(command.field(6)))
                .orElseThrow(() -> invalid("FULL_CRL_ISSUER_UNAVAILABLE"));
        if (!generation.authorityId().value().equals(command.field(0))
                || !generation.credentialId().value().equals(command.field(7))
                || !CrlHybridSigningCommand.isHybrid(command) && !generation.signingKeyRef().value().equals(command.field(5))
                || !generation.profilePolicyCommitment().equals(command.field(15))
                || !generation.x509BindingCommitment().equals(command.field(16))) {
            throw invalid("FULL_CRL_ISSUER_DIFFERS");
        }
        DurableContentReference content = store.getCredential(generation.credentialId())
                .orElseThrow(() -> invalid("FULL_CRL_ISSUER_UNAVAILABLE")).content();
        if (content.encoding() != Encoding.DER || content.length() != Long.parseLong(command.field(25))
                || !content.sha256().equals(command.field(26))) {
            throw invalid("FULL_CRL_ISSUER_DIFFERS");
        }
        byte[] der = new DomainContentAccess(store).materialize(content, "FULL_CRL_ISSUER_INVALID");
        try { return DomainContinuationPublisher.certificate(der); }
        finally { Arrays.fill(der, (byte) 0); }
    }

    private DurableContentReference assemble(DurableContentReference tbs, byte[] algorithm, byte[] signature)
            throws IOException {
        long signatureLength = Math.addExact(1L, signature.length);
        long bodyLength = Math.addExact(Math.addExact(tbs.length(), algorithm.length),
                StreamingDerWriter.encodedLength(signatureLength));
        long expectedLength = StreamingDerWriter.encodedLength(bodyLength);
        try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream();
                RepeatableContent content = store.stagedContent().openContent(tbs);
                InputStream input = content.openStream()) {
            StreamingDerWriter.writeTagAndLength(output, StreamingDerWriter.SEQUENCE_TAG, bodyLength);
            if (StreamingDerWriter.copy(input, output, CancellationSignal.NONE) != tbs.length()) {
                throw invalid("FULL_CRL_TBS_LENGTH_DIFFERS");
            }
            output.write(algorithm);
            StreamingDerWriter.writeTagAndLength(output, StreamingDerWriter.BIT_STRING_TAG, signatureLength);
            output.write(0);
            output.write(signature);
            if (sink.length() != expectedLength) { throw invalid("FULL_CRL_OUTER_LENGTH_DIFFERS"); }
            return sink.complete();
        }
    }

    private void validate(DurableContentReference content, DomainCommandEncoding.Decoded command,
            X509Certificate issuer, byte[] algorithm, byte[] signature) throws IOException {
        try (RepeatableContent crl = store.stagedContent().openContent(content)) {
            StreamingDerReader.SignedObjectLayout layout = new StreamingDerReader().inspectSignedObject(crl,
                    StreamingDerReader.SignedObjectKind.CRL, CancellationSignal.NONE);
            if (layout.tbsLength() != Long.parseLong(command.field(27))
                    || !layout.thisUpdate().equals(Optional.of(Instant.parse(command.field(3))))
                    || !layout.nextUpdate().equals(Optional.of(Instant.parse(command.field(4))))
                    || layout.signatureLength() != signature.length) {
                throw invalid("FULL_CRL_LAYOUT_DIFFERS");
            }
            requireSlice(crl, layout.tbsAlgorithmOffset(), layout.tbsAlgorithmLength(), algorithm);
            requireSlice(crl, layout.outerAlgorithmOffset(), layout.outerAlgorithmLength(), algorithm);
            requireSlice(crl, layout.issuerOffset(), layout.issuerLength(), issuer.getSubjectX500Principal().getEncoded());
            requireSlice(crl, layout.signatureOffset(), layout.signatureLength(), signature);
            X509AlgorithmIdentifier identifier = BcX509AlgorithmAdapter.fromLib(Pkix.parseAlgorithmIdentifier(algorithm));
            AlgorithmIdentity identity = bindings.reverse(identifier, X509AlgorithmRole.SIGNATURE_ALGORITHM);
            if (!identity.canonicalForm().equals(command.field(8))
                    || !bindings.resolve(command.field(17), identity, X509AlgorithmRole.SIGNATURE_ALGORITHM).equals(identifier)
                    || bindings.rules().stream().flatMap(rule -> rule.bindings().stream())
                            .noneMatch(binding -> binding.bindingId().equals(command.field(17))
                                    && binding.semanticCommitment().equals(command.field(18)))) {
                throw invalid("FULL_CRL_ALGORITHM_DIFFERS");
            }
            try (RepeatableContent tbs = new ContentSlice(crl, layout.tbsOffset(), layout.tbsLength())) {
                if (!StreamingCrlSignatureVerifier.verify(tbs, command.field(8), issuer, signature, bindings,
                        CancellationSignal.NONE).equals(command.field(28))) {
                    throw invalid("FULL_CRL_TBS_DIGEST_DIFFERS");
                }
            }
        } catch (GeneralSecurityException | IllegalArgumentException | IOException failure) {
            throw new DomainContinuationPublisher.PostconditionFailure(
                    "FULL_CRL_SIGNATURE_INVALID", failure);
        }
    }

    private static void requireSlice(RepeatableContent source, long offset, long length, byte[] expected)
            throws IOException {
        if (length != expected.length) { throw invalid("FULL_CRL_SIGNED_METADATA_DIFFERS"); }
        try (RepeatableContent slice = new ContentSlice(source, offset, length); InputStream input = slice.openStream()) {
            if (!MessageDigest.isEqual(input.readNBytes(expected.length), expected) || input.read() != -1) {
                throw invalid("FULL_CRL_SIGNED_METADATA_DIFFERS");
            }
        }
    }

    /**
     * Reconstructs deterministic status metadata from the frozen CRL command and provenance.
     *
     * @param id deterministic status-object identity
     * @param content durable content reference selected for publication
     * @param domain frozen durable domain continuation record; must not be null
     * @return status object referencing the completed persisted content
     * @throws NullPointerException if a hybrid command has no signer lineage
     * @throws IllegalArgumentException if command or provenance fields are malformed
     */
    /* default */ static StatusObject status(PkiId id, DurableContentReference content, DomainContinuationStore.Record domain) {
        return status(id, content, domain, null);
    }

    /**
     * Reconstructs deterministic status metadata from the frozen CRL command and provenance.
     *
     * @param id deterministic status-object identity
     * @param content durable content reference selected for publication
     * @param domain frozen durable domain continuation record; must not be null
     * @param lineage native signer lineage; required for hybrid CRLs and otherwise unused
     * @return status object referencing the completed persisted content
     * @throws NullPointerException if a hybrid command has no signer lineage
     * @throws IllegalArgumentException if command or provenance fields are malformed
     */
    /* default */ static StatusObject status(PkiId id, DurableContentReference content, DomainContinuationStore.Record domain, PkiId lineage) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
        SimpleAttributeSet.Builder attributes =
                SimpleAttributeSet.builder()
                        .put(COMMAND, new AttributeValue.StringValue(domain.commandCommitment()))
                        .putAll(FullCrlSnapshotProvenance.from(command).attributes());
        if (CrlHybridSigningCommand.isHybrid(command)) {
            CrlHybridSigningCommand.Descriptor descriptor =
                    CrlHybridSigningCommand.descriptor(command);
            attributes
                    .put(
                            CrlHybridSigningCommand.ISSUER_GENERATION,
                            new AttributeValue.StringValue(command.field(6)))
                    .put(
                            CrlHybridSigningCommand.ISSUER_BINDING,
                            new AttributeValue.StringValue(descriptor.issuerBindingCommitment()))
                    .put(
                            CrlHybridSigningCommand.ROLE_TUPLE,
                            new AttributeValue.StringValue(descriptor.roleTupleCommitment()))
                    .put(
                            CrlHybridSigningCommand.SIGNATURE_PROFILE,
                            new AttributeValue.StringValue(CrlHybridSigningCommand.PROFILE))
                    .put(
                            CrlHybridSigningCommand.SIGNER_LINEAGE,
                            new AttributeValue.StringValue(
                                    java.util.Objects.requireNonNull(lineage).value()));
            if (FullCrlSigningCommand.DELTA_OPERATION.equals(command.operation())) {
                attributes.put(
                        CrlHybridSigningCommand.BASE_STATUS_ID,
                        new AttributeValue.StringValue(command.field(31)));
            }
        }
        return new StatusObject(id, new FormatId(command.field(2)), new PkiId(command.field(0)), StatusObjectType.valueOf(command.field(1)),
                Instant.parse(command.field(3)), Optional.of(Instant.parse(command.field(4))), content, attributes.build());
    }

    /**
     * Requires a stored status object to match the frozen command, provenance, and expected content.
     *
     * @param actual stored status object selected by deterministic identity
     * @param domain frozen durable domain continuation record; must not be null
     * @param expectedContent exact expected content reference
     * @throws DomainContinuationPublisher.PostconditionFailure if frozen content or result postconditions differ
     */
    /* default */ static void requirePublished(StatusObject actual, DomainContinuationStore.Record domain,
            DurableContentReference expectedContent) {
        PublicationChecks.requirePublished(actual, domain, expectedContent);
    }

    private static DomainContinuationPublisher.PostconditionFailure invalid(String code) {
        return new DomainContinuationPublisher.PostconditionFailure(code);
    }

    /** Retained publication metadata and exact status-object postconditions. */
    private static final class PublicationChecks {
        private static void requirePublished(
                StatusObject actual,
                DomainContinuationStore.Record domain,
                DurableContentReference expectedContent) {

        DurableContentReference content = actual.content();
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
        PkiId lineage = null;
        if (CrlHybridSigningCommand.isHybrid(command)) {
                List<AttributeValue> values =
                        actual.attributes().getAll(CrlHybridSigningCommand.SIGNER_LINEAGE);
                if (values.size() != 1
                        || !(values.getFirst() instanceof AttributeValue.StringValue value)) {
                    throw invalid("HYBRID_CRL_LINEAGE_METADATA_INVALID");
                }
            lineage = new PkiId(value.value());
        }
        StatusObject expected = status(actual.statusObjectId(), content, domain, lineage);
            // Attribute identifiers have no ordering contract; each identifier's typed value list
            // does.
            if (!FullCrlSnapshotProvenance.decode(actual.attributes())
                            .equals(FullCrlSnapshotProvenance.decode(expected.attributes()))
                    || !actual.attributes().ids().equals(expected.attributes().ids())
                    || expected.attributes().ids().stream()
                            .anyMatch(
                                    id ->
                                            !actual.attributes()
                                                    .getAll(id)
                                                    .equals(expected.attributes().getAll(id)))) {
                throw invalid("FULL_CRL_PUBLISHED_STATUS_DIFFERS");
            }
            requireStoredFields(actual, expected, expectedContent, content);
        }

        private static void requireStoredFields(
                StatusObject actual,
                StatusObject expected,
                DurableContentReference expectedContent,
                DurableContentReference content) {
            if (!actual.statusObjectId().equals(expected.statusObjectId())
                    || !actual.formatId().equals(expected.formatId())
                    || !actual.issuerCaId().equals(expected.issuerCaId())
                    || actual.type() != expected.type()
                    || !actual.thisUpdate().equals(expected.thisUpdate())
                    || !actual.nextUpdate().equals(expected.nextUpdate())
                    || !actual.content().equals(expected.content())
                    || content.encoding() != Encoding.DER
                    || content.lifecycle() != DurableContentReference.Lifecycle.PERSISTED
                    || !actual.statusObjectId().value().equals("crl:" + content.sha256())
                    || content.length() != expectedContent.length()
                    || !content.sha256().equals(expectedContent.sha256())) {
            throw invalid("FULL_CRL_PUBLISHED_STATUS_DIFFERS");
        }
        }
    }

    /**
     * Owns hybrid assembly/publication while the enclosing publisher retains ordinary CRL
     * publication.
     */
    private final class HybridPublication {
        private EncodedObject publish(
                DomainContinuationStore.Record domain,
                zeroecho.pki.spi.store.CrlHybridExecution execution,
                zeroecho.pki.spi.store.SignWorkflowStore.Workflow parent,
                zeroecho.pki.spi.store.SignWorkflowStore.Workflow child) {

            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
            FullCrlSigningCommand.validate(command);
            CrlHybridSigningCommand.Descriptor descriptor =
                    CrlHybridSigningCommand.descriptor(command);
            IssuerCryptographicBinding binding =
                    store.getIssuerCryptographicBinding(new PkiId(command.field(6))).orElseThrow();
            DurableContentReference nativeTbs = execution.nativeTbs().orElseThrow();
            requireNativeCapture(binding, descriptor, execution, child, nativeTbs);
            byte[] signature = child.result().orElseThrow().bytes();
            byte[] alternative = parent.result().orElseThrow().bytes();
            DurableContentReference assembled = null;
            boolean published = false;
            try {
                requireSignatureBounds(child, parent, signature, alternative, descriptor);
                FullCrlSigningCommand.requireAdmission(
                        command.field(8), nativeTbs.length(), pureEdDsaMaximumTbsBytes);
                byte[] algorithm = HexFormat.of().parseHex(command.field(9));
                X509Certificate certificate = issuer(command);
                assembled = assemble(nativeTbs, algorithm, signature);
                try (RepeatableContent crl = store.stagedContent().openContent(assembled)) {
                    new HybridVerification(
                                    command,
                                    descriptor,
                                    binding,
                                    nativeTbs,
                                    signature,
                                    alternative,
                                    algorithm,
                                    certificate)
                            .verify(crl);
                } catch (GeneralSecurityException
                        | IOException
                        | IllegalArgumentException failure) {
                    throw new DomainContinuationPublisher.PostconditionFailure(
                            "HYBRID_CRL_SIGNATURE_INVALID", failure);
                }
                PkiId id = new PkiId("crl:" + assembled.sha256());
                StatusObject expected =
                        status(
                                id,
                                assembled,
                                domain,
                                store.requireCrlSignerLineage(binding.issuerId()));
                Optional<StatusObject> existing = store.getStatusObject(id);
                if (existing.isPresent()) {
                    StatusObject retained = existing.orElseThrow();
                    requirePublished(retained, domain, assembled);
                    if (!retained.attributes().ids().equals(expected.attributes().ids())
                            || expected.attributes().ids().stream()
                                    .anyMatch(
                                            attribute ->
                                                    !retained.attributes()
                                                            .getAll(attribute)
                                                            .equals(
                                                                    expected.attributes()
                                                                            .getAll(attribute)))) {
                        throw invalid("HYBRID_CRL_PUBLISHED_AUTHORITY_DIFFERS");
                    }
                    // Reconcile the original signing effect and scheduled receipt; never replace
                    // retained content.
                    store.putStatusObjectFromSigning(
                            retained, domain.operationId(), domain.commandCommitment());
                } else {
                    store.putStatusObjectFromSigning(
                            expected, domain.operationId(), domain.commandCommitment());
                    published = true;
                    DomainContinuationPublisher.afterDurablePublication(
                            DomainContinuationPublisher.PublicationFaultPoint.AFTER_STATUS);
                }
                return new EncodedObject(
                        Encoding.BINARY, id.value().getBytes(StandardCharsets.US_ASCII));
            } catch (IOException failure) {
                throw new PkiException("Hybrid CRL content processing failed", failure);
            } catch (IllegalArgumentException invalid) {
                throw new DomainContinuationPublisher.PostconditionFailure(
                        "HYBRID_CRL_ADMISSION_INVALID", invalid);
            } finally {
                Arrays.fill(signature, (byte) 0);
                Arrays.fill(alternative, (byte) 0);
                if (assembled != null && !published) {
                    new DomainContentAccess(store).releaseUnlessPublished(assembled, false);
                }
            }
        }
    }

    /** Verifies one assembled hybrid CRL against its frozen signing coordinates. */
    private final class HybridVerification {
        private final DomainCommandEncoding.Decoded command;
        private final CrlHybridSigningCommand.Descriptor descriptor;
        private final IssuerCryptographicBinding binding;
        private final DurableContentReference nativeTbs;
        private final byte[] signature;
        private final byte[] alternative;
        private final byte[] algorithm;
        private final X509Certificate certificate;

        private HybridVerification(
                DomainCommandEncoding.Decoded command,
                CrlHybridSigningCommand.Descriptor descriptor,
                IssuerCryptographicBinding binding,
                DurableContentReference nativeTbs,
                byte[] signature,
                byte[] alternative,
                byte[] algorithm,
                X509Certificate certificate) {
            this.command = command;
            this.descriptor = descriptor;
            this.binding = binding;
            this.nativeTbs = nativeTbs;
            this.signature = signature;
            this.alternative = alternative;
            this.algorithm = algorithm;
            this.certificate = certificate;
        }

        private void verify(RepeatableContent crl) throws IOException, GeneralSecurityException {
            StreamingDerReader.AlternativeCrlLayout hybrid =
                    new StreamingDerReader().inspectAlternativeCrl(crl, CancellationSignal.NONE);
            StreamingDerReader.SignedObjectLayout layout = hybrid.semantic().layout();
            requireLayout(hybrid, layout);
            requireSlice(crl, layout.tbsAlgorithmOffset(), layout.tbsAlgorithmLength(), algorithm);
            requireSlice(
                    crl, layout.outerAlgorithmOffset(), layout.outerAlgorithmLength(), algorithm);
            requireSlice(
                    crl,
                    layout.issuerOffset(),
                    layout.issuerLength(),
                    certificate.getSubjectX500Principal().getEncoded());
            requireIssuerRole(hybrid);
            try (RepeatableContent tbs =
                            new ContentSlice(crl, layout.tbsOffset(), layout.tbsLength());
                    RepeatableContent altTbs =
                            zeroecho.pki.impl.framework.x509.StreamingCrlAlternativeSignature.alternativeTbs(
                                    crl, CancellationSignal.NONE)) {
                if (!StreamingCrlSignatureVerifier.verify(
                                tbs,
                                command.field(8),
                                Pkix.subjectPublicKeyInfo(certificate),
                                signature,
                                bindings,
                                CancellationSignal.NONE)
                        .equals(nativeTbs.sha256())) {
                    throw invalid("HYBRID_CRL_NATIVE_SIGNATURE_INVALID");
                }
                FullCrlSigningCommand.requireAdmission(
                        binding.alternative().orElseThrow().signatureAlgorithm().canonicalForm(),
                        altTbs.length().orElseThrow(),
                        pureEdDsaMaximumTbsBytes);
                if (!StreamingCrlSignatureVerifier.verify(
                                altTbs,
                                binding.alternative()
                                        .orElseThrow()
                                        .signatureAlgorithm()
                                        .canonicalForm(),
                                zeroecho.pki.impl.core.CrlSigningRoleTuple.alternativeSpki(certificate),
                                alternative,
                                bindings,
                                CancellationSignal.NONE)
                        .equals(command.field(28))) {
                    throw invalid("HYBRID_CRL_ALTERNATIVE_SIGNATURE_INVALID");
                }
            }
        }

        private void requireLayout(
                StreamingDerReader.AlternativeCrlLayout hybrid,
                StreamingDerReader.SignedObjectLayout layout) {
            if (layout.tbsLength() != nativeTbs.length()
                    || !hybrid.semantic().crlNumber().toString().equals(command.field(10))
                    || !layout.thisUpdate().equals(Optional.of(Instant.parse(command.field(3))))
                    || !layout.nextUpdate().equals(Optional.of(Instant.parse(command.field(4))))
                    || !hybrid.semantic()
                            .deltaIndicator()
                            .equals(
                                    FullCrlSigningCommand.DELTA_OPERATION.equals(
                                                    command.operation())
                                            ? Optional.of(new java.math.BigInteger(command.field(32)))
                                            : Optional.empty())
                    || !Arrays.equals(hybrid.alternativeSignature(), alternative)
                    || !Arrays.equals(
                            hybrid.alternativeAlgorithmDer(),
                            binding.alternative()
                                    .orElseThrow()
                                    .signatureAlgorithmIdentifier()
                                    .bytes())) {
                throw invalid("HYBRID_CRL_LAYOUT_DIFFERS");
            }
        }

        private void requireIssuerRole(StreamingDerReader.AlternativeCrlLayout hybrid)
                throws IOException, GeneralSecurityException {
            X509AlgorithmIdentifier identifier =
                    BcX509AlgorithmAdapter.fromLib(Pkix.parseAlgorithmIdentifier(algorithm));
            if (!bindings.reverse(identifier, X509AlgorithmRole.SIGNATURE_ALGORITHM)
                            .equals(binding.primary().signatureAlgorithm())
                    || !bindings.resolve(
                                    command.field(17),
                                    binding.primary().signatureAlgorithm(),
                                    X509AlgorithmRole.SIGNATURE_ALGORITHM)
                            .equals(identifier)
                    || !zeroecho.pki.impl.core.CrlScope.of(
                                    certificate.getSubjectX500Principal().getEncoded(),
                                    Pkix.subjectPublicKeyInfo(certificate))
                            .digest()
                            .equals(command.field(11))
                    || !descriptor
                            .roleTupleCommitment()
                            .equals(
                                    zeroecho.pki.impl.core.CrlSigningRoleTuple.commitment(
                                            binding,
                                            certificate,
                                            algorithm,
                                            hybrid.alternativeAlgorithmDer()))) {
                throw invalid("HYBRID_CRL_ISSUER_ROLE_DIFFERS");
            }
        }
    }

    private static void requireNativeCapture(
            IssuerCryptographicBinding binding,
            CrlHybridSigningCommand.Descriptor descriptor,
            zeroecho.pki.spi.store.CrlHybridExecution execution,
            zeroecho.pki.spi.store.SignWorkflowStore.Workflow child,
            DurableContentReference nativeTbs) {
        if (!binding.commitment().equals(descriptor.issuerBindingCommitment())
                || !execution.nativeChildId().equals(child.operationId())
                || !execution
                        .nativeAcceptanceCommitment()
                        .orElseThrow()
                        .matches(child.envelope().acceptanceCommitment())
                || !nativeTbs.equals(child.envelope().candidate())) {
            throw invalid("HYBRID_CRL_NATIVE_CAPTURE_DIFFERS");
        }
    }

    private static void requireSignatureBounds(
            zeroecho.pki.spi.store.SignWorkflowStore.Workflow child,
            zeroecho.pki.spi.store.SignWorkflowStore.Workflow parent,
            byte[] signature,
            byte[] alternative,
            CrlHybridSigningCommand.Descriptor descriptor) {
        if (child.result().orElseThrow().encoding() != Encoding.BINARY
                || signature.length == 0
                || signature.length > descriptor.primaryMaximumSignatureBytes()
                || parent.result().orElseThrow().encoding() != Encoding.BINARY
                || alternative.length == 0
                || alternative.length > descriptor.alternativeMaximumSignatureBytes()) {
            throw invalid("HYBRID_CRL_SIGNATURE_BOUND_INVALID");
        }
    }
}
