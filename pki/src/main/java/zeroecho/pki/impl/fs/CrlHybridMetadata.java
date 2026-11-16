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
    static final String EXECUTION_NAMESPACE = "io.zeroecho.pki.crl-hybrid-execution";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.crl-hybrid-parent}; persisted identities depend on this value.
     */
    static final String REVERSE_NAMESPACE = "io.zeroecho.pki.crl-hybrid-parent";
    /**
     * Inclusive maximum encoded metadata record length in bytes.
     */
    static final int MAXIMUM_BYTES = 16 * 1024;
    private CrlHybridMetadata() { }
    /**
     * Returns the exact metadata key for the parent execution row.
     *
     * @param parent operation identifier bound into the key
     * @return namespaced operation key
     * @throws NullPointerException if the identifier is null
     */
    static MetadataKey executionKey(PkiId parent) { return new MetadataKey(EXECUTION_NAMESPACE, parent.value()); }
    /**
     * Returns the exact metadata key for the native-child reverse lookup row.
     *
     * @param child operation identifier bound into the key
     * @return namespaced operation key
     * @throws NullPointerException if the identifier is null
     */
    static MetadataKey reverseKey(PkiId child) { return new MetadataKey(REVERSE_NAMESPACE, child.value()); }
    /**
     * Derives native-child scheduling coordinates only after validating captured issuer generation and binding authority.
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
    static SignWorkflowStore.SchedulingCoordinates futureChildCoordinates(SignWorkflowStore.AcceptanceEnvelope parent,
            CrlHybridExecution execution, SigningHybridCrlDependencies.RowReader rows) throws IOException {
        var command = zeroecho.pki.impl.core.continuation.DomainCommandEncoding.decode(parent.outer().orElseThrow().command());
        var descriptor = zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.descriptor(command);
        PkiId issuer = new PkiId(command.field(6));
        byte[] generationBytes = rows.read(AuthorityMetadataCodec.generationKey(issuer));
        byte[] bindingBytes = rows.read(AuthorityMetadataCodec.bindingKey(issuer));
        if (generationBytes == null || bindingBytes == null) throw new IOException("Hybrid CRL future child lacks captured issuer evidence");
        var generation = FsCodec.decode(FsCodec.ISSUER_GENERATION, generationBytes);
        var binding = IssuerBindingStorageCodec.decode(bindingBytes, generation);
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
    static SignWorkflowStore.AcceptanceEnvelope futureChildEnvelope(SignWorkflowStore.AcceptanceEnvelope parent,
            CrlHybridExecution execution, SigningHybridCrlDependencies.RowReader rows) throws IOException {
        var coordinate = futureChildCoordinates(parent, execution, rows);
        var command = zeroecho.pki.impl.core.continuation.DomainCommandEncoding.decode(parent.outer().orElseThrow().command());
        var reference = new BudgetContentReference(parent.candidate().storeId(), "ffffffff-ffff-ffff-ffff-ffffffffffff",
                zeroecho.pki.api.Encoding.DER, Long.MAX_VALUE, "f".repeat(64), zeroecho.pki.api.content.DurableContentReference.Lifecycle.OPERATION);
        return SignWorkflowStore.AcceptanceEnvelope.from(new SignWorkflowStore.AcceptanceCommand(execution.nativeChildId(),
                parent.providerNamespace(), parent.providerConfigurationCommitment(), parent.accessContext(), coordinate.keyRef(),
                coordinate.fairnessAuthorityId(), command.field(8), parent.signatureEncoding(), parent.createdAt(), parent.deadline(),
                reference, Optional.empty(), SignWorkflowStore.Mode.NORMAL, Optional.empty()));
    }

    private record BudgetContentReference(String storeId, String contentId, zeroecho.pki.api.Encoding encoding, long length,
            String sha256, zeroecho.pki.api.content.DurableContentReference.Lifecycle lifecycle)
            implements zeroecho.pki.api.content.DurableContentReference { }

    /**
     * Derives the initial alternative-signature waiting phase for an accepted hybrid CRL command.
     *
     * @param command candidate signing acceptance
     * @return initial execution, or empty for a nonstatus or nonhybrid command
     * @throws NullPointerException if command is null
     * @throws IllegalArgumentException if the command is malformed or its native child identity differs from the deterministic parent binding
     */
    static Optional<CrlHybridExecution> initial(SignWorkflowStore.AcceptanceCommand command) {
        if (command.outer().filter(value -> value.kind() == zeroecho.pki.spi.store.DomainContinuationStore.Kind.STATUS).isEmpty()) return Optional.empty();
        var outer = command.outer().orElseThrow();
        var decoded = zeroecho.pki.impl.core.continuation.DomainCommandEncoding.decode(outer.command());
        if (!zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.isHybrid(decoded)) return Optional.empty();
        var descriptor = zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.descriptor(decoded);
        if (!descriptor.nativeChildId().equals(zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.nativeChildId(command.operationId()))) {
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
    static long futureTransactionBytes(SignWorkflowStore.AcceptanceEnvelope parent, CrlHybridExecution execution,
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
     * @throws IOException if ownership, signatures, algorithms, lineage or content differ from accepted inputs or cannot be read
     */
    static void requireOwnedPublication(zeroecho.pki.api.status.StatusObject status, CrlHybridExecution execution,
            SigningHybridCrlDependencies.RowReader rows, StagedContentStore content) throws IOException {
        byte[] owner = rows.read(FilesystemPkiStore.statusOwnerKey(status.statusObjectId()));
        byte[] domainBytes = rows.read(FilesystemPkiStore.domainContinuationKey(execution.parentId()));
        byte[] childEnvelopeBytes = rows.read(FilesystemPkiStore.signingEnvelopeKey(execution.nativeChildId()));
        byte[] childStateBytes = rows.read(FilesystemPkiStore.signingStateKey(execution.nativeChildId()));
        if (owner == null || domainBytes == null || childEnvelopeBytes == null || childStateBytes == null
                || !java.util.Arrays.equals(owner, FilesystemPkiStore.encodeStatusOwner(status.statusObjectId(), status.content()))) {
            throw new IOException("Hybrid CRL publication ownership is incomplete");
        }
        var domain = FsCodec.decode(FsCodec.DOMAIN_CONTINUATION, domainBytes, content);
        var command = zeroecho.pki.impl.core.continuation.DomainCommandEncoding.decode(domain.command());
        var childEnvelope = FsCodec.decode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, childEnvelopeBytes, content);
        var childState = FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE, childStateBytes, content);
        var child = new SignWorkflowStore.Workflow(childEnvelope, childState);
        byte[] lineageBytes = rows.read(CrlSignerLineageCodec.key(new PkiId(command.field(6))));
        if (lineageBytes == null) throw new IOException("Hybrid CRL publication lineage is missing");
        var lineage = CrlSignerLineageCodec.decode(CrlSignerLineageCodec.key(new PkiId(command.field(6))), lineageBytes);
        var expected = zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.publicationStatus(status.statusObjectId(), status.content(), domain, lineage.lineageId());
        if (!domain.commandCommitment().equals(execution.parentCommandCommitment())
                || !execution.issuerBindingCommitment().equals(lineage.issuerBindingCommitment())
                || !execution.roleTupleCommitment().equals(lineage.signerTupleCommitment())
                || !java.util.Arrays.equals(FsCodec.encode(FsCodec.STATUS_OBJECT, expected), FsCodec.encode(FsCodec.STATUS_OBJECT, status))
                || !childEnvelope.acceptanceCommitment().matches(execution.nativeAcceptanceCommitment().orElseThrow())
                || !childEnvelope.candidate().equals(execution.nativeTbs().orElseThrow())
                || child.state() != SignWorkflowStore.State.SUCCEEDED && child.state() != SignWorkflowStore.State.RETIRED
                || child.result().isEmpty() || child.result().orElseThrow().encoding() != zeroecho.pki.api.Encoding.BINARY
                || !status.statusObjectId().value().equals("crl:" + status.content().sha256())) {
            throw new IOException("Hybrid CRL publication differs from accepted execution");
        }
        byte[] signature = child.result().orElseThrow().bytes();
        try (var crl = content.openContent(status.content())) {
            var parsed = new zeroecho.pki.impl.framework.x509.StreamingDerReader().inspectAlternativeCrl(crl, zeroecho.core.io.CancellationSignal.NONE);
            var layout = parsed.semantic().layout();
            if (layout.tbsLength() != execution.nativeTbs().orElseThrow().length()
                    || !digestSlice(crl, layout.tbsOffset(), layout.tbsLength()).equals(execution.nativeTbs().orElseThrow().sha256())
                    || !digestSlice(crl, 0, status.content().length()).equals(status.content().sha256())
                    || !digest(parsed.alternativeSignature()).equals(execution.alternativeSignatureSha256().orElseThrow())
                    || layout.signatureLength() != signature.length) throw new IOException("Hybrid CRL publication content differs");
            try (var slice = new zeroecho.core.io.ContentSlice(crl, layout.signatureOffset(), layout.signatureLength()); var input = slice.openStream()) {
                if (!java.util.Arrays.equals(input.readNBytes(signature.length + 1), signature)) throw new IOException("Hybrid CRL native result differs");
            }
            byte[] nativeAlgorithm = java.util.HexFormat.of().parseHex(command.field(9));
            if (layout.outerAlgorithmLength() != nativeAlgorithm.length || layout.tbsAlgorithmLength() != nativeAlgorithm.length) throw new IOException("Hybrid CRL native algorithm differs");
            for (long offset : new long[] { layout.outerAlgorithmOffset(), layout.tbsAlgorithmOffset() }) {
                try (var slice = new zeroecho.core.io.ContentSlice(crl, offset, nativeAlgorithm.length); var input = slice.openStream()) {
                    if (!java.util.Arrays.equals(input.readNBytes(nativeAlgorithm.length + 1), nativeAlgorithm)) throw new IOException("Hybrid CRL native algorithm differs");
                }
            }
        } finally { java.util.Arrays.fill(signature, (byte)0); }
    }

    private static String digestSlice(zeroecho.core.io.RepeatableContent content, long offset, long length) throws IOException {
        try (var slice = new zeroecho.core.io.ContentSlice(content, offset, length); var input = slice.openStream()) {
            var digest = sha256(); byte[] buffer = new byte[65_536]; long remaining = length;
            while (remaining > 0) {
                int count = input.read(buffer, 0, (int)Math.min(buffer.length, remaining));
                if (count <= 0) throw new IOException("Hybrid CRL publication truncated"); digest.update(buffer, 0, count); remaining -= count;
            }
            if (input.read() != -1) throw new IOException("Hybrid CRL publication length differs");
            return java.util.HexFormat.of().formatHex(digest.digest());
        }
    }
    private static String digest(byte[] bytes) { return java.util.HexFormat.of().formatHex(sha256().digest(bytes)); }
    private static java.security.MessageDigest sha256() {
        try { return java.security.MessageDigest.getInstance("SHA-256"); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    /**
     * Encodes a hybrid execution and enforces the finite metadata row bound.
     *
     * @param value validated execution state
     * @return newly allocated complete execution bytes
     * @throws IOException if encoding fails or exceeds the row bound
     */
    static byte[] encode(CrlHybridExecution value) throws IOException {
        byte[] bytes = FsCodec.encode(FsCodec.CRL_HYBRID_EXECUTION, value);
        if (bytes.length > MAXIMUM_BYTES) throw new IOException("Hybrid CRL execution exceeds row bound");
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
    static Optional<CrlHybridExecution> read(MetadataSnapshot snapshot, PkiId parent, StagedContentStore content) throws IOException {
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
    static Optional<CrlHybridExecution> reverse(MetadataSnapshot snapshot, PkiId child, StagedContentStore content) throws IOException {
        return read(snapshot, reverseKey(child), content, true);
    }
    private static Optional<CrlHybridExecution> read(MetadataSnapshot snapshot, MetadataKey key, StagedContentStore content,
            boolean reverse) throws IOException {
        try (var row = snapshot.get(key).orElse(null)) {
            if (row == null) return Optional.empty();
            var value = FsCodec.decode(FsCodec.CRL_HYBRID_EXECUTION, CredentialMetadataAuthority.read(row, MAXIMUM_BYTES), content);
            if (!(reverse ? reverseKey(value.nativeChildId()) : executionKey(value.parentId())).equals(key)
                    || reverse && value.phase() != SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
                throw new IOException("Hybrid CRL execution row identity differs");
            }
            return Optional.of(value);
        }
    }
}
