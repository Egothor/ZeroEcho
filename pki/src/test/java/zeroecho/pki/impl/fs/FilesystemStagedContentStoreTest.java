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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;

final class FilesystemStagedContentStoreTest {
    private static final String STORE_ID = "0123456789abcdef0123456789abcdef";
    private static final String FOREIGN_STORE_ID = "fedcba9876543210fedcba9876543210";

    @Test
    void productionContentStreamReadsExactlyOnceAndValidatesAtEof(@TempDir Path directory) throws Exception {
        AtomicInteger opens = new AtomicInteger();
        AtomicLong bytesRead = new AtomicLong();
        FilesystemStagedContentStore.ContentReadObserver observer = new FilesystemStagedContentStore.ContentReadObserver() {
            @Override
            public void opened() {
                opens.incrementAndGet();
            }

            @Override
            public void read(int count) {
                bytesRead.addAndGet(count);
            }
        };
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID, observer);
        byte[] payload = "one-production-payload-pass".getBytes(StandardCharsets.US_ASCII);
        DurableContentReference reference = stage(store, DurableContentReference.Lifecycle.PERSISTED,
                new String(payload, StandardCharsets.US_ASCII));

        try (RepeatableContent content = store.openContent(reference);
                java.io.InputStream input = content.openStream()) {
            assertEquals(payload.length, input.transferTo(OutputStream.nullOutputStream()));
        }
        assertEquals(1, opens.get());
        assertEquals(payload.length, bytesRead.get());

        byte[] substituted = payload.clone();
        substituted[substituted.length - 1] ^= 1;
        Files.write(directory.resolve(reference.contentId() + ".content"), substituted);
        try (RepeatableContent content = store.openContent(reference);
                java.io.InputStream input = content.openStream()) {
            assertThrows(IOException.class, () -> input.transferTo(OutputStream.nullOutputStream()));
        }
        assertEquals(2, opens.get());
        assertEquals(payload.length * 2L, bytesRead.get());
    }

    @Test
    void temporaryIndexClassifiesCommitForceFailureAndCleansPreMoveFailure(@TempDir Path directory) throws Exception {
        System.out.println("temporaryIndexClassifiesCommitForceFailureAndCleansPreMoveFailure");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        byte[] value = "index-value".getBytes(StandardCharsets.US_ASCII);
        try (TemporaryUniqueIndex index = store.beginUniqueIndex()) {
            DurableMetadataFiles.installFault(point -> {
                if (point == DurableMetadataFiles.FaultPoint.FILE_FORCE) {
                    throw new IOException("injected file force");
                }
            });
            assertThrows(IOException.class, () -> index.add(value));
            DurableMetadataFiles.clearFault();
            assertFalse(index.contains(value));

            DurableMetadataFiles.installFault(point -> {
                if (point == DurableMetadataFiles.FaultPoint.DIRECTORY_FORCE_AFTER_MOVE) {
                    throw new IOException("injected directory force");
                }
            });
            DurableMetadataFiles.UncertainAfterMutationException uncertain = assertThrows(
                    DurableMetadataFiles.UncertainAfterMutationException.class, () -> index.add(value));
            DurableMetadataFiles.clearFault();
            assertEquals(DurableMetadataFiles.Mutation.MOVE, uncertain.mutation());
            assertTrue(index.contains(value));
        } finally {
            DurableMetadataFiles.clearFault();
        }
        System.out.println("temporaryIndexClassifiesCommitForceFailureAndCleansPreMoveFailure...ok");
    }

    @Test
    void ownerRecordRejectsContentIdentitySubstitution(@TempDir Path directory) throws Exception {
        System.out.println("ownerRecordRejectsContentIdentitySubstitution");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        DurableContentReference reference = stage(store, DurableContentReference.Lifecycle.PERSISTED, "owned");
        DurableContentOwner owner = new DurableContentOwner(DurableContentOwner.Category.CREDENTIAL_RECORD,
                "credential-owner");
        assertTrue(store.retainContent(reference, owner));
        Path owners = directory.resolve(reference.contentId() + ".owners");
        try (DataOutputStream output = new DataOutputStream(Files.newOutputStream(owners))) {
            output.writeByte(2);
            output.writeUTF("00000000-0000-4000-8000-000000000000");
            output.writeInt(1);
            output.writeUTF(owner.canonicalForm());
        }
        assertThrows(IOException.class, () -> store.contentOwners(reference));
        System.out.println("ownerRecordRejectsContentIdentitySubstitution...ok");
    }

    @Test
    void recoveryRetainsOnlyDurablyReferencedCompletedContent(@TempDir Path directory) throws Exception {
        System.out.println("recoveryRetainsOnlyDurablyReferencedCompletedContent");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        DurableContentReference retained = stage(store, DurableContentReference.Lifecycle.OPERATION, "retained");
        DurableContentReference abandoned = stage(store, DurableContentReference.Lifecycle.PERSISTED, "abandoned");
        DurableContentReference temporary = stage(store, DurableContentReference.Lifecycle.TEMPORARY, "temporary");

        try (TemporaryUniqueIndex references = store.beginUniqueIndex();
                TemporaryUniqueIndex owners = store.beginUniqueIndex()) {
            references.add(retained.contentId().getBytes(StandardCharsets.US_ASCII));
            store.recoverContent(references, owners);
        }

        try (RepeatableContent content = store.openContent(retained)) {
            assertEquals(retained.length(), content.length().orElseThrow());
        }
        assertThrows(IOException.class, () -> store.openContent(abandoned));
        assertThrows(IOException.class, () -> store.openContent(temporary));
        System.out.println("...retainedLength=" + retained.length());
        System.out.println("recoveryRetainsOnlyDurablyReferencedCompletedContent...ok");
    }

    @Test
    void transactionalSigningOwnerPreventsGeneralRetirement(@TempDir Path directory) throws Exception {
        System.out.println("transactionalSigningOwnerPreventsGeneralRetirement");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        DurableContentReference reference = stage(store, DurableContentReference.Lifecycle.OPERATION, "sign-input");
        DurableContentOwner authority = signingOwner("authority");
        store.bindTransactionalOwnership(candidate -> candidate.equals(reference) ? Set.of(authority) : Set.of());
        assertThrows(IOException.class, () -> store.retireUnownedContent(reference));
        try (zeroecho.core.io.RepeatableContent content = store.openContent(reference)) {
            assertEquals(reference.length(), content.length().orElseThrow());
        }
        assertThrows(IllegalArgumentException.class,
                () -> store.retainContent(reference, signingOwner("authority")));
        assertThrows(IllegalArgumentException.class,
                () -> store.retainContent(reference, new DurableContentOwner(
                        DurableContentOwner.Category.STATUS_OBJECT_RECORD, "status-authority")));
        System.out.println("transactionalSigningOwnerPreventsGeneralRetirement...ok");
    }

    @Test
    void sharedSigningPublicationReservationsAreReferenceCounted(@TempDir Path directory) throws Exception {
        System.out.println("sharedSigningPublicationReservationsAreReferenceCounted");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        DurableContentReference reference = stage(store, DurableContentReference.Lifecycle.OPERATION, "shared");
        try (FilesystemStagedContentStore.TransactionalReservation first =
                store.reserveTransactionalPublication(reference);
                FilesystemStagedContentStore.TransactionalReservation second =
                        store.reserveTransactionalPublication(reference)) {
            first.close();
            assertThrows(IOException.class, () -> store.retireUnownedContent(reference));
        }
        store.retireUnownedContent(reference);
        assertThrows(IOException.class, () -> store.openContent(reference));
        System.out.println("sharedSigningPublicationReservationsAreReferenceCounted...ok");
    }

    @Test
    @RequiresSymlinkCreation
    void rejectsTraversalForeignMetadataAndSymlinkContent(@TempDir Path directory) throws Exception {
        System.out.println("rejectsTraversalForeignMetadataAndSymlinkContent");
        String storeId = STORE_ID;
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, storeId);
        assertThrows(IllegalArgumentException.class,
                () -> store.openContent(new UntrustedReference(storeId, "../outside", Encoding.BINARY, 0L,
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        DurableContentReference.Lifecycle.TEMPORARY)));
        DurableContentReference reference = stage(store, DurableContentReference.Lifecycle.PERSISTED, "content");
        DurableContentReference foreign = new UntrustedReference(FOREIGN_STORE_ID,
                reference.contentId(), reference.encoding(), reference.length(), reference.sha256(),
                reference.lifecycle());
        assertThrows(IllegalArgumentException.class, () -> store.openContent(foreign));

        Path content = directory.resolve(reference.contentId() + ".content");
        Path external = directory.resolve("external.bin");
        Files.writeString(external, "content", StandardCharsets.US_ASCII);
        Files.delete(content);
        Files.createSymbolicLink(content, external.getFileName());
        assertThrows(IOException.class, () -> store.openContent(reference));
        System.out.println("...rejected=traversal,foreign,symlink");
        System.out.println("rejectsTraversalForeignMetadataAndSymlinkContent...ok");
    }

    @Test
    void ownerIndexKeysAreFixedDeterministicAndDomainComplete() {
        System.out.println("ownerIndexKeysAreFixedDeterministicAndDomainComplete");
        DurableContentOwner shortOwner = signingOwner("short");
        DurableContentOwner longOwner = signingOwner("a".repeat(128));
        DurableContentOwner otherOperation = signingOwner("b".repeat(128));
        DurableContentOwner otherCategory = new DurableContentOwner(
                DurableContentOwner.Category.CREDENTIAL_RECORD, longOwner.identifier());

        String shortKey = FilesystemStagedContentStore.ownerIndexKey(shortOwner);
        String longKey = FilesystemStagedContentStore.ownerIndexKey(longOwner);
        assertEquals(shortKey, FilesystemStagedContentStore.ownerIndexKey(shortOwner));
        assertEquals(64, shortKey.length());
        assertEquals(64, longKey.length());
        assertTrue(shortKey.matches("[0-9a-f]{64}"));
        assertFalse(longKey.equals(FilesystemStagedContentStore.ownerIndexKey(otherOperation)));
        assertFalse(longKey.equals(FilesystemStagedContentStore.ownerIndexKey(otherCategory)));
        System.out.println("...keyLength=" + longKey.length());
        System.out.println("ownerIndexKeysAreFixedDeterministicAndDomainComplete...ok");
    }

    @Test
    void longOwnerIndexSurvivesLookupAndRejectsSubstitution(@TempDir Path directory) throws Exception {
        System.out.println("longOwnerIndexSurvivesLookupAndRejectsSubstitution");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        DurableContentOwner owner = signingOwner("a".repeat(128));
        byte[] ownerBytes = owner.canonicalForm().getBytes(StandardCharsets.UTF_8);
        try (TemporaryUniqueIndex index = store.beginOwnerIndex()) {
            assertTrue(index.add(ownerBytes));
            assertTrue(index.contains(ownerBytes));
            Path indexDirectory = uniqueIndexDirectory(directory);
            List<Path> entries;
            try (java.util.stream.Stream<Path> paths = Files.list(indexDirectory)) {
                entries = paths.filter(path -> !path.getFileName().toString().contains(".incomplete-")).toList();
            }
            assertEquals(1, entries.size());
            assertEquals(64, entries.get(0).getFileName().toString().length());
            DurableContentOwner substituted = signingOwner("b".repeat(128));
            writeRawIndexRecord(entries.get(0), substituted.canonicalForm().getBytes(StandardCharsets.UTF_8));
            assertThrows(IOException.class, () -> index.contains(ownerBytes));
        }
        System.out.println("...ownerBytes=" + ownerBytes.length);
        System.out.println("longOwnerIndexSurvivesLookupAndRejectsSubstitution...ok");
    }

    @Test
    void ownerIndexConcurrentRetainHasOnePhysicalRecord(@TempDir Path directory) throws Exception {
        System.out.println("ownerIndexConcurrentRetainHasOnePhysicalRecord");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        byte[] owner = signingOwner("c".repeat(128)).canonicalForm().getBytes(StandardCharsets.UTF_8);
        try (TemporaryUniqueIndex index = store.beginOwnerIndex()) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<Boolean> first = executor.submit(() -> index.add(owner));
                Future<Boolean> second = executor.submit(() -> index.add(owner));
                assertTrue(first.get() ^ second.get());
                assertTrue(index.contains(owner));
            } finally {
                executor.shutdownNow();
            }
            try (java.util.stream.Stream<Path> paths = Files.list(uniqueIndexDirectory(directory))) {
                assertEquals(1L, paths.count());
            }
        }
        System.out.println("...physicalRecords=1");
        System.out.println("ownerIndexConcurrentRetainHasOnePhysicalRecord...ok");
    }

    @Test
    void preChangeRawOwnerFilenameIsNotAccepted(@TempDir Path directory) throws Exception {
        System.out.println("preChangeRawOwnerFilenameIsNotAccepted");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        byte[] owner = signingOwner("old").canonicalForm().getBytes(StandardCharsets.UTF_8);
        try (TemporaryUniqueIndex index = store.beginOwnerIndex()) {
            Path oldEntry = uniqueIndexDirectory(directory).resolve(HexFormat.of().formatHex(owner));
            Files.createFile(oldEntry);
            assertFalse(index.contains(owner));
        }
        System.out.println("...oldLayoutRejected=true");
        System.out.println("preChangeRawOwnerFilenameIsNotAccepted...ok");
    }

    @Test
    @RequiresSymlinkCreation
    void ownerIndexValidatesCompleteCommittedNamespace(@TempDir Path directory) throws Exception {
        System.out.println("ownerIndexValidatesCompleteCommittedNamespace");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        byte[] owner = signingOwner("namespace").canonicalForm().getBytes(StandardCharsets.UTF_8);
        try (TemporaryUniqueIndex index = store.beginOwnerIndex()) {
            assertTrue(index.add(owner));
            Path indexDirectory = uniqueIndexDirectory(directory);
            Path expected = onlyEntry(indexDirectory);
            index.validateNamespace();

            Path moved = indexDirectory.resolve("f".repeat(64));
            Files.move(expected, moved);
            assertThrows(IOException.class, index::validateNamespace);
            Files.move(moved, expected);

            Path copied = indexDirectory.resolve("e".repeat(64));
            Files.copy(expected, copied);
            assertThrows(IOException.class, index::validateNamespace);
            Files.delete(copied);

            for (String invalid : List.of("hidden", ".hidden", "A".repeat(64), "0".repeat(63))) {
                Path hostile = indexDirectory.resolve(invalid);
                Files.createFile(hostile);
                assertThrows(IOException.class, index::validateNamespace);
                Files.delete(hostile);
            }

            Path subdirectory = Files.createDirectory(indexDirectory.resolve("subdirectory"));
            assertThrows(IOException.class, index::validateNamespace);
            Files.delete(subdirectory);
            Path link = indexDirectory.resolve("0".repeat(64));
            Files.createSymbolicLink(link, expected.getFileName());
            assertThrows(IOException.class, index::validateNamespace);
            Files.delete(link);
            index.validateNamespace();
            assertTrue(index.contains(owner));
        }
        System.out.println("...hostileEntries=8");
        System.out.println("ownerIndexValidatesCompleteCommittedNamespace...ok");
    }

    @Test
    void ownerIndexRejectsMalformedAndSubstitutedRecords(@TempDir Path directory) throws Exception {
        System.out.println("ownerIndexRejectsMalformedAndSubstitutedRecords");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        byte[] owner = signingOwner("record").canonicalForm().getBytes(StandardCharsets.UTF_8);
        byte[] other = signingOwner("other").canonicalForm().getBytes(StandardCharsets.UTF_8);
        try (TemporaryUniqueIndex index = store.beginOwnerIndex()) {
            assertTrue(index.add(owner));
            Path entry = onlyEntry(uniqueIndexDirectory(directory));
            byte[] record = Files.readAllBytes(entry);

            writeRawIndexRecord(entry, other);
            assertThrows(IOException.class, index::validateNamespace);
            Files.write(entry, record);

            Files.write(entry, new byte[] {1, 0, 0});
            assertThrows(IOException.class, index::validateNamespace);
            Files.write(entry, record);

            byte[] trailing = java.util.Arrays.copyOf(record, record.length + 1);
            Files.write(entry, trailing);
            assertThrows(IOException.class, index::validateNamespace);
            Files.write(entry, record);

            byte[] unknownVersion = record.clone();
            unknownVersion[0] = 2;
            Files.write(entry, unknownVersion);
            assertThrows(IOException.class, index::validateNamespace);
            Files.write(entry, record);
            index.validateNamespace();
        }
        System.out.println("...recordFailures=4");
        System.out.println("ownerIndexRejectsMalformedAndSubstitutedRecords...ok");
    }

    @Test
    void ownerIndexConcurrentDifferentOwnersAndRemoveAreSerializable(@TempDir Path directory) throws Exception {
        System.out.println("ownerIndexConcurrentDifferentOwnersAndRemoveAreSerializable");
        FilesystemStagedContentStore store = new FilesystemStagedContentStore(directory, STORE_ID);
        byte[] firstOwner = signingOwner("first").canonicalForm().getBytes(StandardCharsets.UTF_8);
        byte[] secondOwner = signingOwner("second").canonicalForm().getBytes(StandardCharsets.UTF_8);
        try (TemporaryUniqueIndex index = store.beginOwnerIndex()) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                CyclicBarrier insertBarrier = new CyclicBarrier(2);
                Future<Boolean> first = executor.submit(() -> {
                    insertBarrier.await();
                    return index.add(firstOwner);
                });
                Future<Boolean> second = executor.submit(() -> {
                    insertBarrier.await();
                    return index.add(secondOwner);
                });
                assertTrue(first.get());
                assertTrue(second.get());
                index.validateNamespace();
                assertTrue(index.contains(firstOwner));
                assertTrue(index.contains(secondOwner));

                CyclicBarrier mutationBarrier = new CyclicBarrier(2);
                Future<Boolean> add = executor.submit(() -> {
                    mutationBarrier.await();
                    return index.add(firstOwner);
                });
                Future<Boolean> remove = executor.submit(() -> {
                    mutationBarrier.await();
                    return index.remove(firstOwner);
                });
                boolean added = add.get();
                boolean removed = remove.get();
                assertTrue(removed);
                index.validateNamespace();
                assertEquals(added, index.contains(firstOwner));
                assertTrue(index.contains(secondOwner));
            } finally {
                executor.shutdownNow();
            }
        }
        System.out.println("...serializable=true");
        System.out.println("ownerIndexConcurrentDifferentOwnersAndRemoveAreSerializable...ok");
    }

    private static DurableContentReference stage(FilesystemStagedContentStore store,
            DurableContentReference.Lifecycle lifecycle, String value) throws IOException {
        try (ContentSink sink = store.beginContent(Encoding.BINARY, lifecycle);
                OutputStream output = sink.outputStream()) {
            output.write(value.getBytes(StandardCharsets.US_ASCII));
            return sink.complete();
        }
    }

    private static DurableContentOwner signingOwner(String namespace) {
        return DurableContentOwner.signingOperation(new PkiId(
                "zsign:v1:" + namespace + ":1:0123456789abcdef0123456789abcdef"));
    }

    private static Path uniqueIndexDirectory(Path root) throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.list(root)) {
            return paths.filter(path -> path.getFileName().toString().endsWith(".unique-index")).findFirst()
                    .orElseThrow();
        }
    }

    private static Path onlyEntry(Path directory) throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            return paths.findFirst().orElseThrow();
        }
    }

    private static void writeRawIndexRecord(Path path, byte[] value) throws IOException {
        try (DataOutputStream output = new DataOutputStream(Files.newOutputStream(path))) {
            output.writeByte(1);
            output.writeInt(value.length);
            output.write(value);
        }
    }

    private record UntrustedReference(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference {
    }
}
