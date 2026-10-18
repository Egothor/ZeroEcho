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
import java.util.Optional;
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
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.StreamingDerWriter;
import zeroecho.pki.impl.framework.x509.StreamingCrlSignatureVerifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.Pkix;

/** Streams one full CRL in O(B) I/O and bounded heap, except pure EdDSA provider buffering. */
final class FullCrlContinuationPublisher {
    private static final int MAXIMUM_SIGNATURE_BYTES = 1_048_576;
    private static final AttributeId COMMAND = new AttributeId("zeroecho.pki.full-crl.command-sha256");
    private final PkiStore store;
    private final X509BindingCatalog bindings;
    private final long pureEdDsaMaximumTbsBytes;

    /* default */ FullCrlContinuationPublisher(PkiStore store, X509BindingCatalog bindings, long maximum) {
        this.store = store;
        this.bindings = bindings;
        this.pureEdDsaMaximumTbsBytes = maximum;
    }

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
            throw new DomainContinuationPublisher.PostconditionFailure("FULL_CRL_ADMISSION_INVALID", failure);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (assembled != null && !published) {
                new DomainContentAccess(store).releaseUnlessPublished(assembled, false);
            }
        }
    }

    private X509Certificate issuer(DomainCommandEncoding.Decoded command) {
        IssuerGeneration generation = store.getIssuerGeneration(new PkiId(command.field(6)))
                .orElseThrow(() -> invalid("FULL_CRL_ISSUER_UNAVAILABLE"));
        if (!generation.authorityId().value().equals(command.field(0))
                || !generation.credentialId().value().equals(command.field(7))
                || !generation.signingKeyRef().value().equals(command.field(5))
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
            throw new DomainContinuationPublisher.PostconditionFailure("FULL_CRL_SIGNATURE_INVALID", failure);
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

    /* default */ static StatusObject status(PkiId id, DurableContentReference content, DomainContinuationStore.Record domain) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
        return new StatusObject(id, new FormatId(command.field(2)), new PkiId(command.field(0)), StatusObjectType.valueOf(command.field(1)),
                Instant.parse(command.field(3)), Optional.of(Instant.parse(command.field(4))), content,
                SimpleAttributeSet.builder().put(COMMAND, new AttributeValue.StringValue(domain.commandCommitment()))
                        .putAll(FullCrlSnapshotProvenance.from(command).attributes()).build());
    }

    /* default */ static void requirePublished(StatusObject actual, DomainContinuationStore.Record domain,
            DurableContentReference expectedContent) {
        DurableContentReference content = actual.content();
        StatusObject expected = status(actual.statusObjectId(), content, domain);
        // Attribute identifiers have no ordering contract; each identifier's typed value list does.
        if (!FullCrlSnapshotProvenance.decode(actual.attributes()).equals(
                    FullCrlSnapshotProvenance.decode(expected.attributes()))
                || !actual.attributes().ids().equals(expected.attributes().ids())
                || expected.attributes().ids().stream().anyMatch(id ->
                        !actual.attributes().getAll(id).equals(expected.attributes().getAll(id)))
                || !actual.statusObjectId().equals(expected.statusObjectId())
                || !actual.formatId().equals(expected.formatId())
                || !actual.issuerCaId().equals(expected.issuerCaId())
                || actual.type() != expected.type()
                || !actual.thisUpdate().equals(expected.thisUpdate())
                || !actual.nextUpdate().equals(expected.nextUpdate())
                || !actual.content().equals(expected.content()) || content.encoding() != Encoding.DER
                || content.lifecycle() != DurableContentReference.Lifecycle.PERSISTED
                || !actual.statusObjectId().value().equals("crl:" + content.sha256())
                || content.length() != expectedContent.length() || !content.sha256().equals(expectedContent.sha256())) {
            throw invalid("FULL_CRL_PUBLISHED_STATUS_DIFFERS");
        }
    }

    private static DomainContinuationPublisher.PostconditionFailure invalid(String code) {
        return new DomainContinuationPublisher.PostconditionFailure(code);
    }
}
