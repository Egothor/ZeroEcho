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

package zeroecho.pki.impl.core;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.framework.x509.StreamingX509CrlTbsWriter;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pkix.Pkix;

/**
 * Internal full-CRL TBS staging, without signing or publication. A complete
 * validating pass precedes the irreversible number reservation. A second pass
 * streams into one operation sink, with no aggregate heap representation.
 * Failures after reservation deliberately leave a sequence gap; failures after
 * completion retire the unowned content and preserve suppressed cleanup errors.
 *
 * <p>Two passes cost O(R + S*G + B), including upstream frozen CA membership
 * checks and bounded per-record point I/O/certificate parsing. The temporary
 * source retains the existing O(G) frozen membership; new per-entry auxiliary
 * memory is O(1), staged disk is O(B), and the returned carrier is O(1).
 * Issuer key-identifier decoding additionally costs bounded O(I) time and memory.
 * Snapshot checkpoint construction may internally external-sort.</p>
 */
final class FullCrlTbsPreparation {
    private static final int OCTET_STRING_TAG = 0x04;
    private final PkiStore store;

    /* default */ FullCrlTbsPreparation(PkiStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /* default */ // Exceptional cleanup retains ownership and releases resources after failed validation or provider invocation.
                  // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
                  @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl" })
                  PreparedFullCrlTbs prepare(FullCrlPreparation.Prepared prepared, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(prepared, "prepared");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        X509AlgorithmIdentifier signature = prepared.signatureIdentifier();
        X509Certificate certificate = Pkix.parseCertificate(prepared.issuerDer());
        byte[] extension = certificate.getExtensionValue("2.5.29.14"); // NOPMD - AvoidUsingHardCodedIP: X.509 SubjectKeyIdentifier OID, not an IP address.
        byte[] keyIdentifier = extension == null ? Pkix.subjectKeyIdentifier(certificate.getPublicKey())
                : decodeKeyIdentifier(extension);
        StreamingX509CrlTbsWriter writer = new StreamingX509CrlTbsWriter(signature,
                certificate.getSubjectX500Principal().getEncoded(), keyIdentifier, prepared.thisUpdate(), prepared.nextUpdate(),
                prepared.base().map(DeltaCrlBase::crlNumber));
        StagedContentStore staging = store.stagedContent();
        String localStoreId = Objects.requireNonNull(staging.contentStoreId(), "contentStoreId");
        DurableContentReference content = null;
        try {
            PreparedFullCrlTbs result;
            try (FullCrlEntrySource source = new FullCrlEntrySource(store, prepared, cancellation)) {
                StreamingX509CrlTbsWriter.Measurement measurement = writer.measure(source, cancellation);
                cancellation.throwIfCancelled();
                BigInteger number = store.reserveCrlNumber(prepared.generation().issuerId());
                if (prepared.base().isPresent() && number.compareTo(prepared.base().orElseThrow().crlNumber()) <= 0) {
                    throw new IOException("Delta CRL number does not advance its full CRL base");
                }
                cancellation.throwIfCancelled();
                long expectedLength = writer.encodedLength(measurement, number);
                try (ContentSink sink = staging.beginContent(Encoding.DER, DurableContentReference.Lifecycle.OPERATION);
                        OutputStream output = sink.outputStream()) {
                    cancellation.throwIfCancelled();
                    long written = writer.write(source, measurement, number, output, cancellation);
                    if (written != expectedLength || sink.length() != expectedLength) {
                        throw new IOException("Full CRL staged byte length disagrees with measurement");
                    }
                    cancellation.throwIfCancelled();
                    DurableContentReference completed = sink.complete();
                    if (completed == null || !localStoreId.equals(completed.storeId())) {
                        throw new IOException("Full CRL completion returned no local content reference");
                    }
                    // Only a confirmed local reference may be retired by this store.
                    content = completed;
                    content = validateCompletion(staging, completed, expectedLength);
                }
                cancellation.throwIfCancelled();
                result = new PreparedFullCrlTbs(prepared.authorityId(), prepared.generation().issuerId(), prepared.credentialId(),
                        prepared.profile(), prepared.issuerContent(), prepared.scope().digest(),
                        prepared.generation().profilePolicyCommitment(), prepared.generation().x509BindingCommitment(),
                        prepared.generation().signingKeyRef(), prepared.signatureBinding().algorithmIdentity().canonicalForm(),
                        prepared.signatureBinding(), signature, number, prepared.evaluationTime(), prepared.thisUpdate(), prepared.nextUpdate(),
                        source.snapshotId(), source.sourceStoreId(), source.revision(), source.boundary(), source.commitment(), source.rawCount(),
                        measurement.entryCount(), content, prepared.base());
            }
            cancellation.throwIfCancelled();
            return result;
        } catch (IOException | RuntimeException | Error failure) {
            if (content != null) {
                try { staging.retireUnownedContent(content); }
                catch (IOException | RuntimeException cleanup) { failure.addSuppressed(cleanup); }
            }
            throw failure;
        }
    }

    private static DurableContentReference validateCompletion(StagedContentStore staging, DurableContentReference content,
            long expectedLength) throws IOException {
        if (content.encoding() != Encoding.DER || content.lifecycle() != DurableContentReference.Lifecycle.OPERATION
                || content.length() != expectedLength || content.contentId() == null || content.contentId().isBlank()
                || content.sha256() == null || !content.sha256().matches("[0-9a-f]{64}")) {
            throw new IOException("Full CRL completed content metadata is invalid");
        }
        DurableContentReference restored = staging.restoreReference(content.storeId(), content.contentId(), content.encoding(),
                content.length(), content.sha256(), content.lifecycle());
        if (restored == null || !content.storeId().equals(restored.storeId()) || !content.contentId().equals(restored.contentId())
                || content.encoding() != restored.encoding() || content.lifecycle() != restored.lifecycle()
                || content.length() != restored.length() || !content.sha256().equals(restored.sha256())) {
            throw new IOException("Full CRL restored content metadata disagrees with completion");
        }
        return restored;
    }

    /** Strictly unwraps both DER OCTET STRINGs of a present SubjectKeyIdentifier. */
    /* default */ static byte[] decodeKeyIdentifier(byte[] extension) throws IOException {
        byte[] inner = octets(extension);
        byte[] identifier = octets(inner);
        if (identifier.length == 0) { throw new IOException("Issuer SubjectKeyIdentifier is empty"); }
        return identifier;
    }

    private static byte[] octets(byte[] der) throws IOException {
        new StreamingDerReader().validate(der, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
        if (der[0] != OCTET_STRING_TAG) { throw new IOException("Issuer SubjectKeyIdentifier requires DER OCTET STRING"); }
        // The strict reader already verified the sole object's canonical length and complete bounds.
        int offset = 2;
        if ((der[1] & 0x80) != 0) { offset += der[1] & 0x7f; }
        return Arrays.copyOfRange(der, offset, der.length);
    }
}
