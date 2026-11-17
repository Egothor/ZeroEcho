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

package zeroecho.pki.impl.fs;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ContentSlice;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.store.DomainContinuationStore;

import java.io.IOException;
import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.CrlHybridExecution;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

/**
 * Bounded canonical execution rows and exact reverse mirrors; graph authority is checked by the store.
 */
final class CrlHybridMetadata {
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.crl-hybrid-execution}; persisted identities depend on this value.
     */
    /* default */ static final String EXECUTION_NAMESPACE = "io.zeroecho.pki.crl-hybrid-execution";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.crl-hybrid-parent}; persisted identities depend on this value.
     */
    /* default */ static final String REVERSE_NAMESPACE = "io.zeroecho.pki.crl-hybrid-parent";
    /**
     * Inclusive maximum encoded metadata record length in bytes.
     */
    /* default */ static final int MAXIMUM_BYTES = 16 * 1024;
    private CrlHybridMetadata() { }
    /**
     * Returns the exact metadata key for the parent execution row.
     *
     * @param parent operation identifier bound into the key
     * @return namespaced operation key
     * @throws NullPointerException if the identifier is null
     */
    /* default */ static MetadataKey executionKey(PkiId parent) { return new MetadataKey(EXECUTION_NAMESPACE, parent.value()); }
    /**
     * Returns the exact metadata key for the native-child reverse lookup row.
     *
     * @param child operation identifier bound into the key
     * @return namespaced operation key
     * @throws NullPointerException if the identifier is null
     */
    /* default */ static MetadataKey reverseKey(PkiId child) { return new MetadataKey(REVERSE_NAMESPACE, child.value()); }
    /**
     * Derives native-child scheduling coordinates only after validating captured issuer generation and
     * binding authority.
     *
     * @param parent accepted parent operation envelope
     * @param execution frozen hybrid execution coordinates
     * @param rows pinned reader of captured issuer authority
     * @return native signing key and accepted fairness authority
     * @throws NullPointerException if a required argument is null
     * @throws IllegalArgumentException if the captured command or issuer coordinates are malformed
     * @throws java.util.NoSuchElementException if the parent has no outer command
     * @throws IOException if issuer evidence is missing, inconsistent or unreadable
     */
    /* default */ static SignWorkflowStore.SchedulingCoordinates futureChildCoordinates(SignWorkflowStore.AcceptanceEnvelope parent,
            CrlHybridExecution execution, SigningHybridCrlDependencies.RowReader rows) throws IOException {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(parent.outer().orElseThrow().command());
        CrlHybridSigningCommand.Descriptor descriptor = CrlHybridSigningCommand.descriptor(command);
        PkiId issuer = new PkiId(command.field(6));
        byte[] generationBytes = rows.read(AuthorityMetadataCodec.generationKey(issuer));
        byte[] bindingBytes = rows.read(AuthorityMetadataCodec.bindingKey(issuer));
        if (generationBytes == null || bindingBytes == null) { throw new IOException("Hybrid CRL future child lacks captured issuer evidence"); }
        IssuerGeneration generation = FsCodec.decode(FsCodec.ISSUER_GENERATION, generationBytes);
        IssuerCryptographicBinding binding = IssuerBindingStorageCodec.decode(bindingBytes, generation);
        if (!issuer.equals(generation.issuerId()) || !binding.commitment().equals(execution.issuerBindingCommitment())
                || !binding.commitment().equals(descriptor.issuerBindingCommitment()) || binding.alternative().isEmpty()
                || !binding.authorityId().equals(parent.fairnessAuthorityId())
                || !execution.parentId().equals(parent.operationId()) || !execution.nativeChildId().equals(descriptor.nativeChildId())) {
            throw new IOException("Hybrid CRL future child issuer authority differs");
        }
        return new SignWorkflowStore.SchedulingCoordinates(binding.primary().keyRef(), parent.fairnessAuthorityId());
    }

    /**
     * Builds a serialization-only maximal native-child prototype for capacity accounting.
     * The prototype is not an issued content reference or a signing or adoption input.
     *
     * @param parent accepted parent operation envelope
     * @param execution frozen hybrid execution coordinates
     * @param rows pinned reader of captured issuer authority
     * @return future-child envelope containing synthetic maximum-size content coordinates
     * @throws NullPointerException if a required argument is null
     * @throws IllegalArgumentException if accepted command or envelope coordinates are malformed
     * @throws java.util.NoSuchElementException if the parent has no outer command
     * @throws IOException if issuer scheduling authority is missing, inconsistent or unreadable
     */
    /* default */ static SignWorkflowStore.AcceptanceEnvelope futureChildEnvelope(SignWorkflowStore.AcceptanceEnvelope parent,
            CrlHybridExecution execution, SigningHybridCrlDependencies.RowReader rows) throws IOException {
        SignWorkflowStore.SchedulingCoordinates coordinate = futureChildCoordinates(parent, execution, rows);
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(parent.outer().orElseThrow().command());
        CrlHybridMetadata.BudgetContentReference reference = new BudgetContentReference(parent.candidate().storeId(), "ffffffff-ffff-ffff-ffff-ffffffffffff",
                Encoding.DER, Long.MAX_VALUE, "f".repeat(64), DurableContentReference.Lifecycle.OPERATION);
        return SignWorkflowStore.AcceptanceEnvelope.from(new SignWorkflowStore.AcceptanceCommand(execution.nativeChildId(),
                parent.providerNamespace(), parent.providerConfigurationCommitment(), parent.accessContext(), coordinate.keyRef(),
                coordinate.fairnessAuthorityId(), command.field(8), parent.signatureEncoding(), parent.createdAt(), parent.deadline(),
                reference, Optional.empty(), SignWorkflowStore.Mode.NORMAL, Optional.empty()));
    }

    private record BudgetContentReference(String storeId, String contentId, Encoding encoding, long length,
            String sha256, DurableContentReference.Lifecycle lifecycle)
            implements DurableContentReference { }

    /**
     * Derives the initial alternative-signature waiting phase for an accepted hybrid CRL command.
     *
     * @param command candidate signing acceptance
     * @return initial execution, or empty for a nonstatus or nonhybrid command
     * @throws NullPointerException if command is null
     * @throws IllegalArgumentException if the command is malformed or its native child identity differs
     * from the deterministic parent binding
     */
    /* default */ static Optional<CrlHybridExecution> initial(SignWorkflowStore.AcceptanceCommand command) {
        if (command.outer().filter(value -> value.kind() == DomainContinuationStore.Kind.STATUS).isEmpty()) { return Optional.empty(); }
        SignWorkflowStore.OuterCommand outer = command.outer().orElseThrow();
        DomainCommandEncoding.Decoded decoded = DomainCommandEncoding.decode(outer.command());
        if (!CrlHybridSigningCommand.isHybrid(decoded)) { return Optional.empty(); }
        CrlHybridSigningCommand.Descriptor descriptor = CrlHybridSigningCommand.descriptor(decoded);
        if (!descriptor.nativeChildId().equals(CrlHybridSigningCommand.nativeChildId(command.operationId()))) {
            throw new IllegalArgumentException("Hybrid CRL native child identity differs from deterministic parent binding");
        }
        return Optional.of(new CrlHybridExecution(1, command.operationId(), outer.commandCommitment(),
                descriptor.issuerBindingCommitment(), descriptor.roleTupleCommitment(), descriptor.nativeChildId(),
                SignWorkflowStore.CrlHybridPhase.AWAITING_ALT, 0, Optional.empty(), Optional.empty(), Optional.empty()));
    }

    /**
     * Computes the bounded future hybrid transaction byte allowance from accepted inputs and captured issuer authority.
     *
     * @param parent accepted parent operation envelope
     * @param execution frozen hybrid execution coordinates
     * @param rows pinned reader of captured issuer authority
     * @return maximum future transaction size in bytes
     * @throws IOException if required authority cannot be read or validated
     */
    /* default */ static long futureTransactionBytes(SignWorkflowStore.AcceptanceEnvelope parent, CrlHybridExecution execution,
            SigningHybridCrlDependencies.RowReader rows) throws IOException {
        return CrlHybridTransactionBudget.maximum(parent, execution, rows);
    }

    /**
     * Validates published CRL ownership, accepted child signature, issuer lineage and exact DER content coordinates.
     * Validation uses persisted CRL bytes even after operation content retirement.
     *
     * @param status published CRL status object
     * @param execution accepted hybrid execution
     * @param rows reader of accepted operation and authority metadata
     * @param content owning durable CRL content resolver
     * @throws NullPointerException if a required argument is null
     * @throws java.util.NoSuchElementException if required accepted execution coordinates are absent
     * @throws IllegalArgumentException if encoded commands or algorithm coordinates are malformed
     * @throws IOException if ownership, signatures, algorithms, lineage or content differ from accepted
     * inputs or cannot be read
     */
    /* default */ static void requireOwnedPublication(StatusObject status, CrlHybridExecution execution,
            SigningHybridCrlDependencies.RowReader rows, StagedContentStore content) throws IOException {
        byte[] owner = rows.read(FilesystemPkiStore.statusOwnerKey(status.statusObjectId()));
        byte[] domainBytes = rows.read(FilesystemPkiStore.domainContinuationKey(execution.parentId()));
        byte[] childEnvelopeBytes = rows.read(FilesystemPkiStore.signingEnvelopeKey(execution.nativeChildId()));
        byte[] childStateBytes = rows.read(FilesystemPkiStore.signingStateKey(execution.nativeChildId()));
        if (owner == null || domainBytes == null || childEnvelopeBytes == null || childStateBytes == null
                || !Arrays.equals(owner, FilesystemPkiStore.encodeStatusOwner(status.statusObjectId(), status.content()))) {
            throw new IOException("Hybrid CRL publication ownership is incomplete");
        }
        DomainContinuationStore.Record domain = FsCodec.decode(FsCodec.DOMAIN_CONTINUATION, domainBytes, content);
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
        SignWorkflowStore.AcceptanceEnvelope childEnvelope = FsCodec.decode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, childEnvelopeBytes, content);
        SignWorkflowStore.MutableState childState = FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE, childStateBytes, content);
        SignWorkflowStore.Workflow child = new SignWorkflowStore.Workflow(childEnvelope, childState);
        byte[] lineageBytes = rows.read(CrlSignerLineageCodec.key(new PkiId(command.field(6))));
        if (lineageBytes == null) { throw new IOException("Hybrid CRL publication lineage is missing"); }
        CrlSignerLineage lineage = CrlSignerLineageCodec.decode(CrlSignerLineageCodec.key(new PkiId(command.field(6))), lineageBytes);
        StatusObject expected = FullCrlSigningCommand.publicationStatus(status.statusObjectId(), status.content(), domain, lineage.lineageId());
        requireAcceptedExecution(status, execution, domain, lineage, expected, childEnvelope, child);
        byte[] signature = child.result().orElseThrow().bytes();
        PublicationContent.requireContent(status, execution, command, content, signature);
    }



    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    /**
     * Encodes a hybrid execution and enforces the finite metadata row bound.
     *
     * @param value validated execution state
     * @return newly allocated complete execution bytes
     * @throws IOException if encoding fails or exceeds the row bound
     */
    /* default */ static byte[] encode(CrlHybridExecution value) throws IOException {
        byte[] bytes = FsCodec.encode(FsCodec.CRL_HYBRID_EXECUTION, value);
        if (bytes.length > MAXIMUM_BYTES) { throw new IOException("Hybrid CRL execution exceeds row bound"); }
        return bytes;
    }
    /**
     * Reads a bounded parent execution row and validates its operation identity.
     *
     * @param snapshot caller-owned pinned metadata view
     * @param parent operation identifier used for lookup
     * @param content durable resolver for encoded content references
     * @return validated execution, or empty if the row is absent
     * @throws NullPointerException if a required argument is null
     * @throws IOException if decoding, key binding or linked-child phase validation fails
     */
    /* default */ static Optional<CrlHybridExecution> read(MetadataSnapshot snapshot, PkiId parent, StagedContentStore content) throws IOException {
        return read(snapshot, executionKey(parent), content, false);
    }
    /**
     * Reads a bounded linked native-child reverse execution row and validates its operation identity.
     *
     * @param snapshot caller-owned pinned metadata view
     * @param child operation identifier used for lookup
     * @param content durable resolver for encoded content references
     * @return validated execution, or empty if the row is absent
     * @throws NullPointerException if a required argument is null
     * @throws IOException if decoding, key binding or linked-child phase validation fails
     */
    /* default */ static Optional<CrlHybridExecution> reverse(MetadataSnapshot snapshot, PkiId child, StagedContentStore content) throws IOException {
        return read(snapshot, reverseKey(child), content, true);
    }
    private static Optional<CrlHybridExecution> read(MetadataSnapshot snapshot, MetadataKey key, StagedContentStore content,
            boolean reverse) throws IOException {
        try (MetadataSnapshot.Record row = snapshot.get(key).orElse(null)) {
            if (row == null) { return Optional.empty(); }
            CrlHybridExecution value = FsCodec.decode(FsCodec.CRL_HYBRID_EXECUTION, CredentialMetadataAuthority.read(row, MAXIMUM_BYTES), content);
            if (!(reverse ? reverseKey(value.nativeChildId()) : executionKey(value.parentId())).equals(key)
                    || reverse && value.phase() != SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
                throw new IOException("Hybrid CRL execution row identity differs");
            }
            return Optional.of(value);
        }
    }

    private static void requireAcceptedExecution(StatusObject status, CrlHybridExecution execution,
            DomainContinuationStore.Record domain, CrlSignerLineage lineage, StatusObject expected,
            SignWorkflowStore.AcceptanceEnvelope childEnvelope, SignWorkflowStore.Workflow child) throws IOException {
        if (!domain.commandCommitment().equals(execution.parentCommandCommitment())
                || !execution.issuerBindingCommitment().equals(lineage.issuerBindingCommitment())
                || !execution.roleTupleCommitment().equals(lineage.signerTupleCommitment())
                || !Arrays.equals(FsCodec.encode(FsCodec.STATUS_OBJECT, expected), FsCodec.encode(FsCodec.STATUS_OBJECT, status))
                || !childEnvelope.acceptanceCommitment().matches(execution.nativeAcceptanceCommitment().orElseThrow())
                || !childEnvelope.candidate().equals(execution.nativeTbs().orElseThrow())
                || child.state() != SignWorkflowStore.State.SUCCEEDED && child.state() != SignWorkflowStore.State.RETIRED
                || child.result().isEmpty() || child.result().orElseThrow().encoding() != Encoding.BINARY
                || !status.statusObjectId().value().equals("crl:" + status.content().sha256())) {
            throw new IOException("Hybrid CRL publication differs from accepted execution");
        }
    }






    /** Validates exact retained CRL content and algorithm slices. */
    private static final class PublicationContent {
        private static void requireContent(StatusObject status, CrlHybridExecution execution,
                DomainCommandEncoding.Decoded command, StagedContentStore content, byte[] signature) throws IOException {
            try (RepeatableContent crl = content.openContent(status.content())) {
                StreamingDerReader.AlternativeCrlLayout parsed = new StreamingDerReader().inspectAlternativeCrl(crl, CancellationSignal.NONE);
                StreamingDerReader.SignedObjectLayout layout = parsed.semantic().layout();
                if (layout.tbsLength() != execution.nativeTbs().orElseThrow().length()
                        || !digestSlice(crl, layout.tbsOffset(), layout.tbsLength()).equals(execution.nativeTbs().orElseThrow().sha256())
                        || !digestSlice(crl, 0, status.content().length()).equals(status.content().sha256())
                        || !digest(parsed.alternativeSignature()).equals(execution.alternativeSignatureSha256().orElseThrow())
                        || layout.signatureLength() != signature.length) { throw new IOException("Hybrid CRL publication content differs"); }
                try (ContentSlice slice = new ContentSlice(crl, layout.signatureOffset(), layout.signatureLength()); InputStream input = slice.openStream()) {
                    if (!Arrays.equals(input.readNBytes(signature.length + 1), signature)) { throw new IOException("Hybrid CRL native result differs"); }
                }
                byte[] nativeAlgorithm = HexFormat.of().parseHex(command.field(9));
                if (layout.outerAlgorithmLength() != nativeAlgorithm.length || layout.tbsAlgorithmLength() != nativeAlgorithm.length) { throw new IOException("Hybrid CRL native algorithm differs"); }
                requireAlgorithm(crl, layout.outerAlgorithmOffset(), nativeAlgorithm);
                requireAlgorithm(crl, layout.tbsAlgorithmOffset(), nativeAlgorithm);
            } finally { Arrays.fill(signature, (byte)0); }
        }

        private static void requireAlgorithm(RepeatableContent crl, long offset, byte[] nativeAlgorithm) throws IOException {
            try (ContentSlice slice = new ContentSlice(crl, offset, nativeAlgorithm.length); InputStream input = slice.openStream()) {
                if (!Arrays.equals(input.readNBytes(nativeAlgorithm.length + 1), nativeAlgorithm)) {
                    throw new IOException("Hybrid CRL native algorithm differs");
                }
            }
        }

        private static String digestSlice(RepeatableContent content, long offset, long length) throws IOException {
            try (ContentSlice slice = new ContentSlice(content, offset, length); InputStream input = slice.openStream()) {
                MessageDigest digest = sha256(); byte[] buffer = new byte[65_536]; long remaining = length;
                while (remaining > 0) {
                    int count = input.read(buffer, 0, (int)Math.min(buffer.length, remaining));
                    if (count <= 0) { throw new IOException("Hybrid CRL publication truncated"); } digest.update(buffer, 0, count); remaining -= count;
                }
                if (input.read() != -1) { throw new IOException("Hybrid CRL publication length differs"); }
                return HexFormat.of().formatHex(digest.digest());
            }
        }

        private static String digest(byte[] bytes) { return HexFormat.of().formatHex(sha256().digest(bytes)); }
    }

}
