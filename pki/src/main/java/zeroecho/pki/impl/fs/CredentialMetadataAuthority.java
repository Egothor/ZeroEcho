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

package zeroecho.pki.impl.fs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/**
 * Borrowed metadata/content authority for credential records and their atomic
 * owner sets. Point reads use O(owners) bounded metadata work, with at most the
 * existing 2048 owners per content object. Startup scans retain one record and
 * one bounded owner set; they never repair or delete corrupt authority.
 */
final class CredentialMetadataAuthority {
    // Exact existing staged owner-set wire format and capability bounds.
    private static final int OWNER_VERSION = 2;
    private static final int MAX_OWNER_BYTES = 1_048_576;
    private static final int MAX_OWNERS = 2048;
    private static final int MAX_VALUE_BYTES = AuthorityMetadataCodec.MAX_VALUE_BYTES;
    private final TransactionalMetadataStore metadata;
    private final StagedContentStore content;

    /* default */ CredentialMetadataAuthority(TransactionalMetadataStore metadata, StagedContentStore content) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.content = Objects.requireNonNull(content, "content");
    }

    /* default */ Optional<Credential> find(PkiId id) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) { return find(snapshot, id); }
    }

    /* default */ Optional<Credential> find(MetadataSnapshot snapshot, PkiId id) throws IOException {
        Optional<Credential> found = raw(snapshot, id);
        if (found.isPresent()) {
            Credential credential = found.orElseThrow();
            if (!owners(snapshot, credential.content()).contains(DurableContentOwner.credentialRecord(id))) {
                throw invalid();
            }
            validateContent(credential.content());
        }
        return found;
    }

    /* default */ Set<DurableContentOwner> owners(DurableContentReference reference) throws IOException {
        if (reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED) { return Set.of(); }
        try (MetadataSnapshot snapshot = metadata.snapshot()) { return owners(snapshot, reference); }
    }

    // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
    @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
    private Set<DurableContentOwner> owners(MetadataSnapshot snapshot, DurableContentReference reference) throws IOException {
        requireReference(reference);
        try (MetadataSnapshot.Record record = snapshot.get(AuthorityMetadataCodec.ownerSetKey(reference.contentId())).orElse(null)) {
            if (record == null) { return Set.of(); }
            Set<DurableContentOwner> owners = decodeOwners(record.key(), read(record, MAX_OWNER_BYTES));
            for (DurableContentOwner owner : owners) {
                Credential credential = raw(snapshot, new PkiId(owner.identifier())).orElseThrow(CredentialMetadataAuthority::invalid);
                if (!credential.content().equals(reference)) { throw invalid(); }
            }
            return owners;
        }
    }

    /** Stages only; caller owns its existing content reservation and transaction. */
    /* default */ void stageCreate(MetadataSnapshot snapshot, MetadataTransaction transaction, Credential credential) throws IOException {
        requireReference(credential.content());
        validateContent(credential.content());
        Set<DurableContentOwner> owners = new LinkedHashSet<>(owners(snapshot, credential.content()));
        if (!owners.add(DurableContentOwner.credentialRecord(credential.credentialId()))) { throw invalid(); }
        MetadataKey recordKey = AuthorityMetadataCodec.credentialKey(credential.credentialId());
        byte[] payload = FsCodec.encode(FsCodec.CREDENTIAL, credential);
        AuthorityMetadataCodec.requireValueSize(payload);
        try (RepeatableContent bytes = new ImmutableByteContent(payload)) {
            transaction.create(recordKey, bytes, CancellationSignal.NONE);
        }
        MetadataKey ownerKey = AuthorityMetadataCodec.ownerSetKey(credential.content().contentId());
        try (MetadataSnapshot.Record previous = snapshot.get(ownerKey).orElse(null);
                RepeatableContent bytes = new ImmutableByteContent(encodeOwners(credential.content().contentId(), owners))) {
            if (previous == null) { transaction.create(ownerKey, bytes, CancellationSignal.NONE); }
            else { transaction.replace(ownerKey, previous.recordRevision(), bytes, CancellationSignal.NONE); }
        }
    }

    /** Validates both directions before any staged-content reclamation may begin. */
    /* default */ void validateAll(Visitor visitor) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) { validateAll(snapshot, visitor); }
    }

    /* default */ // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
                  @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
                  void validateAll(MetadataSnapshot snapshot, Visitor visitor) throws IOException {
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.CREDENTIAL_RECORD), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    Credential credential = AuthorityMetadataCodec.credential(record.key(), read(record, MAX_VALUE_BYTES), content);
                    if (!owners(snapshot, credential.content()).contains(DurableContentOwner.credentialRecord(credential.credentialId()))) {
                        throw invalid();
                    }
                    validateContent(credential.content());
                    visitor.accept(credential);
                }
            }
        }
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.CREDENTIAL_OWNER_SET), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    Set<DurableContentOwner> owners = decodeOwners(record.key(), read(record, MAX_OWNER_BYTES));
                    Credential first = raw(snapshot, new PkiId(owners.iterator().next().identifier())).orElseThrow(CredentialMetadataAuthority::invalid);
                    if (!AuthorityMetadataCodec.ownerSetKey(first.content().contentId()).equals(record.key())
                            || !owners(snapshot, first.content()).equals(owners)) { throw invalid(); }
                }
            }
        }
    }

    private Optional<Credential> raw(MetadataSnapshot snapshot, PkiId id) throws IOException {
        try (MetadataSnapshot.Record record = snapshot.get(AuthorityMetadataCodec.credentialKey(id)).orElse(null)) {
            if (record == null) { return Optional.empty(); }
            Credential credential = AuthorityMetadataCodec.credential(record.key(), read(record, MAX_VALUE_BYTES), content);
            if (!credential.credentialId().equals(id)) { throw invalid(); }
            requireReference(credential.content());
            return Optional.of(credential);
        }
    }

    private void requireReference(DurableContentReference reference) throws IOException {
        if (reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED
                || !reference.storeId().equals(content.contentStoreId())) { throw invalid(); }
        content.restoreReference(reference.storeId(), reference.contentId(), reference.encoding(), reference.length(),
                reference.sha256(), reference.lifecycle());
    }

    private void validateContent(DurableContentReference reference) throws IOException {
        try (RepeatableContent payload = content.openContent(reference); InputStream input = payload.openStream()) {
            byte[] buffer = new byte[16 * 1024];
            while (true) {
                int read = input.read(buffer);
                if (read < 0) { return; }
                if (read == 0) { throw invalid(); }
            }
        }
    }

    /* default */ static byte[] encodeOwners(String contentId, Set<DurableContentOwner> owners) throws IOException {
        AuthorityMetadataCodec.ownerSetKey(contentId);
        if (owners.isEmpty() || owners.size() > MAX_OWNERS) { throw invalid(); }
        List<String> values = owners.stream().map(owner -> {
            if (owner.category() != DurableContentOwner.Category.CREDENTIAL_RECORD) { throw new IllegalArgumentException("Credential owner category differs"); }
            return owner.canonicalForm();
        }).sorted().toList();
        long size = 1L + 2 + contentId.length() + 4;
        for (String value : values) { size += 2L + value.length(); }
        if (size > MAX_OWNER_BYTES) { throw invalid(); }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) size);
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeByte(OWNER_VERSION);
            output.writeUTF(contentId);
            output.writeInt(values.size());
            for (String value : values) { output.writeUTF(value); }
        }
        return bytes.toByteArray();
    }

    /* default */ static Set<DurableContentOwner> decodeOwners(MetadataKey key, byte[] bytes) throws IOException {
        if (bytes.length > MAX_OWNER_BYTES) { throw invalid(); }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (input.readUnsignedByte() != OWNER_VERSION) { throw invalid(); }
            String contentId = input.readUTF();
            if (!AuthorityMetadataCodec.ownerSetKey(contentId).equals(key)) { throw invalid(); }
            int count = input.readInt();
            if (count <= 0 || count > MAX_OWNERS) { throw invalid(); }
            Set<DurableContentOwner> owners = readOwners(input, count);
            if (input.read() != -1) { throw invalid(); }
            return Set.copyOf(owners);
        } catch (IllegalArgumentException malformed) { throw new IOException("Credential ownership metadata is invalid", malformed); }
    }

    private static Set<DurableContentOwner> readOwners(DataInputStream input, int count) throws IOException {
        Set<DurableContentOwner> owners = new LinkedHashSet<>();
        String previous = "";
        String prefix = DurableContentOwner.Category.CREDENTIAL_RECORD.name() + ":";
        for (int index = 0; index < count; index++) {
            String value = input.readUTF();
            if (!value.startsWith(prefix) || value.compareTo(previous) <= 0) { throw invalid(); }
            owners.add(DurableContentOwner.credentialRecord(new PkiId(value.substring(prefix.length()))));
            previous = value;
        }
        return owners;
    }

    /* default */ static byte[] read(MetadataSnapshot.Record record, int maximum) throws IOException {
        long length = record.length().orElseThrow(CredentialMetadataAuthority::invalid);
        if (length < 0 || length > maximum) { throw invalid(); }
        try (InputStream input = record.openStream()) {
            byte[] bytes = input.readNBytes((int) length);
            if (bytes.length != length || input.read() != -1) { throw invalid(); }
            return bytes;
        }
    }

    private static IOException invalid() { return new IOException("Credential metadata ownership is inconsistent"); }
    /** Checked visitor over authoritative credential records. */
    /* default */
    @FunctionalInterface
    interface Visitor {
        /** Consumes one credential, propagating storage failures. */
        void accept(Credential credential) throws IOException;
    }
}
