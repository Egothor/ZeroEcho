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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreId;

class CrlScopeReservationStoreTest {
    @Test
    void ownerCreationIncludesCounterAndReplayCannotResetIt(@TempDir Path root) throws Exception {
        CrlScope scope = CrlScope.of(new X500Principal("CN=Counter").getEncoded(),
                HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        CrlScopeOwner owner = new CrlScopeOwner(scope, new PkiId("ca:counter"));
        MetadataStoreId storeId = new MetadataStoreId("0123456789abcdef0123456789abcdef");
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.create(root, storeId)) {
            CrlScopeReservationStore reservations = new CrlScopeReservationStore(metadata, BigInteger.valueOf(17),
                    ignored -> { });
            reservations.claim(owner);
            assertEquals(BigInteger.valueOf(17), reservations.reserve(owner));
            reservations.claim(owner);
            CrlScopeReservationStore differentInitial = new CrlScopeReservationStore(metadata, BigInteger.ZERO,
                    ignored -> { });
            differentInitial.claim(owner);
            assertEquals(BigInteger.valueOf(18), differentInitial.reserve(owner));
        }
    }

    @Test
    void claimRejectsMissingOrOrphanCounterInsteadOfRepairingPair(@TempDir Path root) throws Exception {
        CrlScope scope = CrlScope.of(new X500Principal("CN=Incomplete").getEncoded(),
                HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        CrlScopeOwner owner = new CrlScopeOwner(scope, new PkiId("ca:incomplete"));
        CrlScopeCounter counter = new CrlScopeCounter(scope.digest(), BigInteger.ONE);
        MetadataStoreId storeId = new MetadataStoreId("0123456789abcdef0123456789abcdef");
        List<MetadataKey> keys = List.of(CrlScopeMetadataCodec.key(owner), CrlScopeMetadataCodec.key(counter));
        List<byte[]> values = List.of(CrlScopeMetadataCodec.encode(owner), CrlScopeMetadataCodec.encode(counter));
        for (int index = 0; index < 2; index++) {
            try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.create(
                    Files.createDirectory(root.resolve(Integer.toString(index))), storeId)) {
                metadata.directCommit(List.of(new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE, keys.get(index), -1, values.get(index))));
                CrlScopeReservationStore reservations = new CrlScopeReservationStore(metadata, BigInteger.ONE,
                        ignored -> { });
                assertThrows(IOException.class, () -> reservations.claim(owner));
                assertThrows(IOException.class, () -> reservations.reserve(owner));
            }
        }
    }

    @Test
    void acceptanceStagesBothOwnerCounterPairsAndSerialAtomically(@TempDir Path root) throws Exception {
        byte[] spki = HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32));
        CrlScopeOwner parent = new CrlScopeOwner(CrlScope.of(new X500Principal("CN=Parent").getEncoded(), spki),
                new PkiId("ca:parent"));
        CrlScopeOwner child = new CrlScopeOwner(CrlScope.of(new X500Principal("CN=Child").getEncoded(), spki),
                new PkiId("ca:child"));
        ScopeSerialReservation serial = new ScopeSerialReservation(parent.scope(), BigInteger.ONE,
                new ScopeSerialReservation.SigningOwner(new PkiId("operation"), "01".repeat(32)));
        MetadataStoreId storeId = new MetadataStoreId("0123456789abcdef0123456789abcdef");
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.create(root, storeId)) {
            CrlScopeReservationStore reservations = new CrlScopeReservationStore(metadata, BigInteger.valueOf(7),
                    ignored -> { });
            SignAcceptanceCrlScope claims = new SignAcceptanceCrlScope(List.of(parent, child), serial);
            try (zeroecho.pki.spi.store.MetadataTransaction transaction = metadata.beginTransaction()) {
                reservations.stageAcceptance(transaction, claims);
                assertTrue(reservations.findOwner(parent.scope()).isEmpty());
                assertTrue(reservations.findOwner(child.scope()).isEmpty());
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            assertEquals(BigInteger.valueOf(7), reservations.reserve(parent));
            assertEquals(BigInteger.valueOf(7), reservations.reserve(child));
            try (zeroecho.pki.spi.store.MetadataTransaction transaction = metadata.beginTransaction()) {
                reservations.stageAcceptance(transaction, claims);
            }
            assertEquals(BigInteger.valueOf(8), reservations.reserve(parent));
            assertEquals(BigInteger.valueOf(8), reservations.reserve(child));
        }
    }

    @Test
    void authorityScanRejectsMalformedKeysAndMissingOwners(@TempDir Path root) throws Exception {
        CrlScope scope = CrlScope.of(new X500Principal("CN=Recovery").getEncoded(),
                HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        CrlScopeOwner owner = new CrlScopeOwner(scope, new PkiId("ca:recovery"));
        ScopeSerialReservation reservation = new ScopeSerialReservation(scope, BigInteger.ONE,
                new ScopeSerialReservation.SigningOwner(new PkiId("operation"), "01".repeat(32)));
        MetadataStoreId storeId = new MetadataStoreId("0123456789abcdef0123456789abcdef");
        List<MetadataKey> keys = List.of(CrlScopeMetadataCodec.key(reservation),
                new MetadataKey("io.zeroecho.pki.crl-scope-owner", "wrong"),
                CrlScopeMetadataCodec.key(owner),
                new MetadataKey("io.zeroecho.pki.scope-serial", "wrong"));
        List<byte[]> values = List.of(CrlScopeMetadataCodec.encode(reservation),
                CrlScopeMetadataCodec.encode(owner), new byte[] { 1 }, CrlScopeMetadataCodec.encode(reservation));
        for (int index = 0; index < keys.size(); index++) {
            try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.create(
                    Files.createDirectory(root.resolve(Integer.toString(index))), storeId)) {
                metadata.directCommit(List.of(new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE, keys.get(index), -1, values.get(index))));
                CrlScopeReservationStore store = new CrlScopeReservationStore(metadata, BigInteger.ONE, ignored -> { });
                assertThrows(IOException.class, () -> store.validateAuthority((claim, serial) -> { }));
            }
        }
    }

    @Test
    void authorityScanPreservesOrphanSigningReservation(@TempDir Path root) throws Exception {
        CrlScope scope = CrlScope.of(new X500Principal("CN=Recovery").getEncoded(),
                HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        CrlScopeOwner owner = new CrlScopeOwner(scope, new PkiId("ca:recovery"));
        ScopeSerialReservation reservation = new ScopeSerialReservation(scope, BigInteger.ONE,
                new ScopeSerialReservation.SigningOwner(new PkiId("operation"), "01".repeat(32)));
        MetadataStoreId storeId = new MetadataStoreId("0123456789abcdef0123456789abcdef");
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.create(root, storeId)) {
            CrlScopeReservationStore store = new CrlScopeReservationStore(metadata, BigInteger.ONE, ignored -> { });
            store.claim(owner, reservation);
            AtomicInteger visited = new AtomicInteger();
            store.validateAuthority((claim, serial) -> {
                assertEquals(owner, claim);
                assertEquals(reservation, serial);
                visited.incrementAndGet();
            });
            assertEquals(1, visited.get());
            assertEquals(reservation, store.findReservation(scope, BigInteger.ONE).orElseThrow());
        }
    }

    @Test
    void pinnedExportSeesBothScopeAndSerialOrNeitherAtConcurrentCommit(@TempDir Path root) throws Exception {
        CrlScope scope = CrlScope.of(new X500Principal("CN=Concurrent").getEncoded(),
                HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        CrlScopeOwner owner = new CrlScopeOwner(scope, new PkiId("ca:concurrent"));
        CrlScopeCounter counter = new CrlScopeCounter(scope.digest(), BigInteger.ONE);
        ScopeSerialReservation reservation = new ScopeSerialReservation(scope, BigInteger.ONE,
                new ScopeSerialReservation.ImportedCertificateOwner("01".repeat(32)));
        MetadataStoreId storeId = new MetadataStoreId("0123456789abcdef0123456789abcdef");
        BlockingCommit operations = new BlockingCommit();
        Path before = Files.createDirectory(root.resolve("before"));
        Path after = Files.createDirectory(root.resolve("after"));
        try (SegmentedTransactionalMetadataStore source = SegmentedTransactionalMetadataStore.create(
                    Files.createDirectory(root.resolve("source")), storeId, operations);
                ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<MetadataCommitResult> committed = executor.submit(() -> source.directCommit(List.of(
                    new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.CREATE,
                            CrlScopeMetadataCodec.key(owner), -1, CrlScopeMetadataCodec.encode(owner)),
                    new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.CREATE,
                            CrlScopeMetadataCodec.key(counter), -1, CrlScopeMetadataCodec.encode(counter)),
                    new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.CREATE,
                            CrlScopeMetadataCodec.key(reservation), -1, CrlScopeMetadataCodec.encode(reservation)))));
            try {
                assertTrue(operations.entered.await(10, TimeUnit.SECONDS));
                source.exportSnapshotTo(before, Set.of());
            } finally { operations.release.countDown(); }
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, committed.get(10, TimeUnit.SECONDS).outcome());
            source.exportSnapshotTo(after, Set.of());
        } finally { operations.release.countDown(); }
        try (SegmentedTransactionalMetadataStore copied = SegmentedTransactionalMetadataStore.open(before, storeId)) {
            CrlScopeReservationStore values = new CrlScopeReservationStore(copied, BigInteger.ONE, ignored -> { });
            assertTrue(values.findOwner(scope).isEmpty());
            assertTrue(values.findReservation(scope, BigInteger.ONE).isEmpty());
            values.validateAuthority((claim, serial) -> { });
        }
        try (SegmentedTransactionalMetadataStore copied = SegmentedTransactionalMetadataStore.open(after, storeId)) {
            CrlScopeReservationStore values = new CrlScopeReservationStore(copied, BigInteger.ONE, ignored -> { });
            assertEquals(owner, values.findOwner(scope).orElseThrow());
            assertEquals(reservation, values.findReservation(scope, BigInteger.ONE).orElseThrow());
            values.validateAuthority((claim, serial) -> { });
        }
    }

    @Test
    void permanentClaimsSurviveReopenAndRejectChangedAuthoritySerialOwner(@TempDir Path root) throws Exception {
        CrlScope scope = CrlScope.of(new X500Principal("CN=Root").getEncoded(),
                HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        CrlScopeOwner owner = new CrlScopeOwner(scope, new PkiId("ca:root"));
        ScopeSerialReservation reservation = new ScopeSerialReservation(scope, BigInteger.ONE,
                new ScopeSerialReservation.ImportedCertificateOwner("01".repeat(32)));
        MetadataStoreId storeId = new MetadataStoreId("0123456789abcdef0123456789abcdef");
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.create(root, storeId)) {
            CrlScopeReservationStore store = new CrlScopeReservationStore(metadata, BigInteger.ONE, result -> {
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
            });
            store.claim(owner, reservation);
            store.claim(owner, reservation);
            assertThrows(IllegalStateException.class,
                    () -> store.claim(new CrlScopeOwner(scope, new PkiId("ca:other"))));
            assertThrows(IllegalStateException.class, () -> store.claim(owner,
                    new ScopeSerialReservation(scope, BigInteger.ONE,
                            new ScopeSerialReservation.ImportedCertificateOwner("02".repeat(32)))));
            assertThrows(IllegalStateException.class, () -> store.claim(owner,
                    new ScopeSerialReservation(scope, BigInteger.ONE,
                            new ScopeSerialReservation.SigningOwner(new PkiId("op:other"), "01".repeat(32)))));
        }
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.open(root, storeId)) {
            CrlScopeReservationStore store = new CrlScopeReservationStore(metadata, BigInteger.ONE, result -> {
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
            });
            store.claim(owner, reservation);
            assertEquals(owner, store.findOwner(scope).orElseThrow());
            assertEquals(reservation, store.findReservation(scope, BigInteger.ONE).orElseThrow());
        }
    }

    private static final class BlockingCommit implements SigningActiveWal.Operations {
        private final AtomicInteger forces = new AtomicInteger();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);

        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) { return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public void forceDirectory(Path directory) throws IOException { SigningFormatSupport.forceDirectory(directory); }

        private SigningActiveWal.WalChannel wrap(FileChannel channel) {
            return new SigningActiveWal.WalChannel() {
                @Override public int read(ByteBuffer target) throws IOException { return channel.read(target); }
                @Override public int write(ByteBuffer source) throws IOException { return channel.write(source); }
                @Override public long position() throws IOException { return channel.position(); }
                @Override public SigningActiveWal.WalChannel position(long value) throws IOException { channel.position(value); return this; }
                @Override public long size() throws IOException { return channel.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException { channel.truncate(size); return this; }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws IOException { channel.close(); }
                @Override public void force(boolean metadata) throws IOException {
                    if (forces.incrementAndGet() == 2) {
                        entered.countDown();
                        try {
                            if (!release.await(10, TimeUnit.SECONDS)) { throw new IOException("Controlled commit release timed out"); }
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            throw new IOException("Controlled commit interrupted", interrupted);
                        }
                    }
                    channel.force(metadata);
                }
            };
        }
    }
}
