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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.spi.store.MetadataStoreId;

final class FilesystemRevocationCheckpointBuilderTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("102030405060708090a0b0c0d0e0f001");
    private static final FilesystemRevocationCurrentIndex.Configuration INDEX_CONFIGURATION =
            new FilesystemRevocationCurrentIndex.Configuration(2L, 1, 2);

    @TempDir
    private Path temporaryDirectory;

    @Test
    void boundedMultiPassBuildPublishesCanonicalCurrentState() throws Exception {
        System.out.print("boundedMultiPassBuildPublishesCanonicalCurrentState ");
        try (Fixture fixture = fixture("multi-pass")) {
            List<PkiId> identities = List.of(
                    new PkiId("credential:zeta"), new PkiId("credential:beta"),
                    new PkiId("credential:eta"), new PkiId("credential:alpha"),
                    new PkiId("credential:delta"), new PkiId("credential:gamma"),
                    new PkiId("credential:epsilon"));
            fixture.appendAll(identities);
            AtomicInteger mergeWrites = new AtomicInteger();
            FilesystemRevocationCheckpointBuilder.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.MERGE_WRITE) {
                    mergeWrites.incrementAndGet();
                }
            };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration generation =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(), faults);
                try (FilesystemRevocationCheckpoint checkpoint = FilesystemRevocationCheckpoint.open(
                        generation.path(), fixture.logPath(), fixture.log().scan())) {
                    assertEquals(identities.size(), checkpoint.entryCount());
                    assertEquals(List.of(
                            "credential:alpha", "credential:beta", "credential:delta",
                            "credential:epsilon", "credential:eta", "credential:gamma",
                            "credential:zeta"), collect(checkpoint));
                }
            }
            assertTrue(mergeWrites.get() > identities.size());
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void frozenSnapshotRemainsAtCapturedRevisionDuringLiveUpdate() throws Exception {
        System.out.print("frozenSnapshotRemainsAtCapturedRevisionDuringLiveUpdate ");
        try (Fixture fixture = fixture("frozen")) {
            PkiId first = new PkiId("credential:first");
            PkiId second = new PkiId("credential:second");
            fixture.log().append(first, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                Path frozenPath = fixture.workRoot().resolve("manual-frozen");
                Files.createDirectories(fixture.workRoot());
                try (FilesystemRevocationCurrentIndex.FrozenSnapshot frozen =
                        index.freeze(frozenPath, 31)) {
                    RevocationTransitionFrameCodec.CompleteRecord appended =
                            fixture.log().append(second, held(1L, 2L));
                    index.update(appended);
                    assertEquals(1L, frozen.coverage().coveredRevision());
                    assertEquals(List.of(first), collect(frozen));
                }
                assertFalse(Files.exists(frozenPath));
                assertEquals(2L, index.coveredGlobalRevision());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void logAppendAfterFreezeProducesValidHistoricalCheckpoint() throws Exception {
        System.out.print("logAppendAfterFreezeProducesValidHistoricalCheckpoint ");
        try (Fixture fixture = fixture("historical")) {
            PkiId first = new PkiId("credential:first");
            fixture.log().append(first, held(1L, 1L));
            AtomicBoolean appended = new AtomicBoolean();
            FilesystemRevocationCheckpointBuilder.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.BEFORE_PUBLICATION
                        && appended.compareAndSet(false, true)) {
                    fixture.log().append(
                            new PkiId("credential:later"), held(1L, 2L));
                }
            };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration generation =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(), faults);
                FilesystemRevocationLog.RecoveryResult recovery = fixture.log().scan();
                try (FilesystemRevocationCheckpoint checkpoint = FilesystemRevocationCheckpoint.open(
                        generation.path(), fixture.logPath(), recovery)) {
                    assertEquals(1L, checkpoint.coveredRevision());
                    assertEquals(List.of(first.value()), collect(checkpoint));
                }
                assertEquals(2L, recovery.globalRevision());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void emptyIndexBuildsGenesisCheckpoint() throws Exception {
        System.out.print("emptyIndexBuildsGenesisCheckpoint ");
        try (Fixture fixture = fixture("empty")) {
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration generation =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration());
                try (FilesystemRevocationCheckpoint checkpoint = FilesystemRevocationCheckpoint.open(
                        generation.path(), fixture.logPath(), fixture.log().scan())) {
                    assertEquals(0L, checkpoint.coveredRevision());
                    assertEquals(0L, checkpoint.entryCount());
                }
            }
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void runFailurePublishesNothingAndCleansWorkspace() throws Exception {
        System.out.print("runFailurePublishesNothingAndCleansWorkspace ");
        try (Fixture fixture = fixture("failure")) {
            fixture.log().append(new PkiId("credential:first"), held(1L, 1L));
            FilesystemRevocationCheckpointBuilder.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.RUN_WRITE) {
                    throw new IOException("injected run failure");
                }
            };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                assertThrows(IOException.class, () ->
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(),
                                fixture.builderConfiguration(), faults));
                assertEquals(1L, index.coveredGlobalRevision());
            }
            assertFalse(hasCheckpoint(fixture.checkpoints()));
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void boundsAreValidatedWithoutCreatingWorkspace() throws Exception {
        System.out.print("boundsAreValidatedWithoutCreatingWorkspace ");
        Path work = temporaryDirectory.resolve("invalid-work");
        assertThrows(IllegalArgumentException.class, () ->
                new FilesystemRevocationCheckpointBuilder.Configuration(0L, 2, 64, work));
        assertThrows(IllegalArgumentException.class, () ->
                new FilesystemRevocationCheckpointBuilder.Configuration(64L, 1, 64, work));
        assertThrows(IllegalArgumentException.class, () ->
                new FilesystemRevocationCheckpointBuilder.Configuration(64L, 2, 0, work));
        assertFalse(Files.exists(work));
        System.out.println("...ok");
    }

    @Test
    void frozenCopyAndForceFailuresReleaseBuilderResources() throws Exception {
        System.out.print("frozenCopyAndForceFailuresReleaseBuilderResources ");
        try (Fixture fixture = fixture("frozen-failures")) {
            PkiId identity = new PkiId("credential:frozen-failure");
            fixture.log().append(identity, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                for (FilesystemRevocationCheckpointBuilder.FaultPoint failurePoint : List.of(
                        FilesystemRevocationCheckpointBuilder.FaultPoint.FROZEN_COPY,
                        FilesystemRevocationCheckpointBuilder.FaultPoint.FROZEN_FORCE)) {
                    FilesystemRevocationCheckpointBuilder.FaultInjector faults = point -> {
                        if (point == failurePoint) {
                            throw new IOException("injected frozen failure");
                        }
                    };
                    assertThrows(IOException.class, () ->
                            FilesystemRevocationCheckpointBuilder.build(
                                    index, fixture.checkpoints(),
                                    fixture.builderConfiguration(), faults));
                    assertEquals(identity,
                            index.lookup(identity).orElseThrow().data().credentialId());
                    assertTrue(directoryEmpty(fixture.workRoot()));
                }
                FilesystemRevocationCheckpoint.PublishedGeneration generation =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration());
                assertTrue(Files.isRegularFile(generation.path()));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void runAndMergeForceFailuresPreservePreviousGeneration() throws Exception {
        System.out.print("runAndMergeForceFailuresPreservePreviousGeneration ");
        try (Fixture fixture = fixture("force-failures")) {
            PkiId first = new PkiId("credential:first");
            PkiId second = new PkiId("credential:second");
            fixture.log().append(first, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration previous =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration());
                RevocationTransitionFrameCodec.CompleteRecord appended =
                        fixture.log().append(second, held(1L, 2L));
                index.update(appended);
                for (FilesystemRevocationCheckpointBuilder.FaultPoint failurePoint : List.of(
                        FilesystemRevocationCheckpointBuilder.FaultPoint.RUN_FORCE,
                        FilesystemRevocationCheckpointBuilder.FaultPoint.MERGE_FORCE)) {
                    FilesystemRevocationCheckpointBuilder.FaultInjector faults = point -> {
                        if (point == failurePoint) {
                            throw new IOException("injected temporary force failure");
                        }
                    };
                    assertThrows(IOException.class, () ->
                            FilesystemRevocationCheckpointBuilder.build(
                                    index, fixture.checkpoints(),
                                    fixture.builderConfiguration(), faults));
                    assertTrue(Files.isRegularFile(previous.path()));
                    assertTrue(directoryEmpty(fixture.workRoot()));
                }
                try (FilesystemRevocationCheckpoint checkpoint =
                        FilesystemRevocationCheckpoint.open(
                                previous.path(), fixture.logPath(), fixture.log().scan())) {
                    assertEquals(List.of(first.value()), collect(checkpoint));
                }
            }
        }
        System.out.println("...ok");
    }

    @Test
    void boundedResourcesAndRepeatedBuildAreDeterministic() throws Exception {
        System.out.print("boundedResourcesAndRepeatedBuildAreDeterministic ");
        try (Fixture fixture = fixture("bounded-observation")) {
            fixture.appendAll(List.of(
                    new PkiId("credential:h"), new PkiId("credential:d"),
                    new PkiId("credential:f"), new PkiId("credential:b"),
                    new PkiId("credential:g"), new PkiId("credential:c"),
                    new PkiId("credential:e"), new PkiId("credential:a")));
            AtomicLong maximumRunEntries = new AtomicLong();
            AtomicLong maximumRunBytes = new AtomicLong();
            AtomicLong maximumTemporaryBytes = new AtomicLong();
            AtomicLong initialRunEntries = new AtomicLong();
            AtomicLong expectedHeadEncodings = new AtomicLong();
            AtomicLong actualHeadEncodings = new AtomicLong();
            AtomicInteger maximumOpenInputs = new AtomicInteger();
            AtomicInteger initialRunCount = new AtomicInteger();
            AtomicInteger mergePassCount = new AtomicInteger();
            FilesystemRevocationCheckpointBuilder.FaultInjector observer =
                    new FilesystemRevocationCheckpointBuilder.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCheckpointBuilder.FaultPoint point) {
                            // Observation only.
                        }

                        @Override
                        public void observeRunBuffer(long entryCount, long encodedBytes) {
                            maximumRunEntries.accumulateAndGet(entryCount, Math::max);
                            maximumRunBytes.accumulateAndGet(encodedBytes, Math::max);
                        }

                        @Override
                        public void observeOpenMergeInputs(int openInputs) {
                            maximumOpenInputs.accumulateAndGet(openInputs, Math::max);
                        }

                        @Override
                        public void observeTemporaryRun(
                                int pass, long entryCount, long encodedBytes) {
                            maximumTemporaryBytes.accumulateAndGet(encodedBytes, Math::max);
                            if (pass == 0) {
                                initialRunCount.incrementAndGet();
                                initialRunEntries.addAndGet(entryCount);
                            }
                        }

                        @Override
                        public void observeMergePass(
                                int pass,
                                long inputRuns,
                                long outputRuns,
                                long inputEntries,
                                long outputEntries) {
                            mergePassCount.incrementAndGet();
                            assertEquals(inputEntries, outputEntries);
                            assertEquals((inputRuns + 1L) / 2L, outputRuns);
                            expectedHeadEncodings.addAndGet(inputEntries);
                        }

                        @Override
                        public void observeMergeHeadEncoding() {
                            actualHeadEncodings.incrementAndGet();
                        }
                    };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration first =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(),
                                fixture.builderConfiguration(), observer);
                FilesystemRevocationCheckpoint.PublishedGeneration second =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(),
                                fixture.builderConfiguration(), observer);
                assertEquals(first.generationId(), second.generationId());
                assertEquals(first.path(), second.path());
                assertFalse(second.newlyPublished());
            }
            assertEquals(1L, maximumRunEntries.get());
            assertTrue(maximumRunBytes.get() > 0L);
            assertTrue(maximumTemporaryBytes.get() > maximumRunBytes.get());
            assertEquals(2, maximumOpenInputs.get());
            assertEquals(16, initialRunCount.get());
            assertEquals(16L, initialRunEntries.get());
            assertTrue(mergePassCount.get() >= 6);
            assertEquals(expectedHeadEncodings.get(), actualHeadEncodings.get());
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void currentStateFieldsAndAuthoritativeLocatorsAreExact() throws Exception {
        System.out.print("currentStateFieldsAndAuthoritativeLocatorsAreExact ");
        try (Fixture fixture = fixture("entry-fields")) {
            PkiId clearIdentity = new PkiId("credential:clear");
            PkiId revokedIdentity = new PkiId("credential:revoked");
            fixture.log().append(clearIdentity, held(1L, 1L));
            RevocationTransitionFrameCodec.CompleteRecord clearRecord =
                    fixture.log().append(clearIdentity, clear(2L, 2L));
            RevocationTransitionFrameCodec.CompleteRecord revokedRecord =
                    fixture.log().append(revokedIdentity, permanentWithAttributes(1L, 3L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration generation =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration());
                try (FilesystemRevocationCheckpoint checkpoint =
                        FilesystemRevocationCheckpoint.open(
                                generation.path(), fixture.logPath(), fixture.log().scan())) {
                    List<RevocationCheckpointCodec.CurrentStateEntry> entries =
                            collectEntries(checkpoint);
                    assertEquals(2, entries.size());
                    assertEquals(RevocationState.CLEAR, entries.get(0).transition().state());
                    assertEquals(clearRecord.recordOffset(), entries.get(0).frameStart());
                    assertEquals(clearRecord.recordEnd(), entries.get(0).frameEnd());
                    assertEquals(revokedRecord.commitment(), entries.get(1).transitionCommitment());
                    assertEquals(revokedRecord.recordOffset(), entries.get(1).frameStart());
                    assertEquals(revokedRecord.recordEnd(), entries.get(1).frameEnd());
                    assertEquals(RevocationExecutionEvidence.administrative("operator-a", "realm-a", "request-a",
                            RevocationExecutionEvidence.Authentication.DIRECT_MTLS,
                            RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT, "a".repeat(64),
                            Optional.empty()).attributes().ids(), entries.get(1).transition().attributes().ids());
                }
            }
        }
        System.out.println("...ok");
    }

    @Test
    void corruptOrTruncatedTemporaryRunFailsClosed() throws Exception {
        System.out.print("corruptOrTruncatedTemporaryRunFailsClosed ");
        for (boolean truncate : List.of(false, true)) {
            try (Fixture fixture = fixture("temporary-corruption-" + truncate)) {
                fixture.appendAll(List.of(
                        new PkiId("credential:a"), new PkiId("credential:b")));
                AtomicBoolean changed = new AtomicBoolean();
                FilesystemRevocationCheckpointBuilder.FaultInjector faults =
                        new FilesystemRevocationCheckpointBuilder.FaultInjector() {
                            @Override
                            public void fail(
                                    FilesystemRevocationCheckpointBuilder.FaultPoint point) {
                                // Corruption occurs after the strict run is complete.
                            }

                            @Override
                            public void afterRunWritten(Path run) throws IOException {
                                if (changed.compareAndSet(false, true)) {
                                    corruptRun(run, truncate);
                                }
                            }
                        };
                FilesystemRevocationCheckpointBuilder.Configuration oneRun =
                        new FilesystemRevocationCheckpointBuilder.Configuration(
                                Long.MAX_VALUE, 2, 37, fixture.workRoot());
                try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                    assertThrows(IOException.class, () ->
                            FilesystemRevocationCheckpointBuilder.build(
                                    index, fixture.checkpoints(), oneRun, faults));
                }
                assertFalse(hasCheckpoint(fixture.checkpoints()));
                assertTrue(directoryEmpty(fixture.workRoot()));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void publicationFailureAndCleanupFailureHaveSafeIndependentOutcomes() throws Exception {
        System.out.print("publicationFailureAndCleanupFailureHaveSafeIndependentOutcomes ");
        try (Fixture fixture = fixture("publication-cleanup")) {
            PkiId first = new PkiId("credential:first");
            PkiId second = new PkiId("credential:second");
            fixture.log().append(first, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration previous =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration());
                index.update(fixture.log().append(second, held(1L, 2L)));
                FilesystemRevocationCheckpointBuilder.FaultInjector publicationFailure = point -> {
                    if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.BEFORE_PUBLICATION) {
                        throw new IOException("injected publication failure");
                    }
                };
                assertThrows(IOException.class, () ->
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(),
                                publicationFailure));
                assertTrue(Files.isRegularFile(previous.path()));

                FilesystemRevocationCheckpointBuilder.FaultInjector cleanupFailure = point -> {
                    if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.CLEANUP) {
                        throw new IOException("injected cleanup failure");
                    }
                };
                FilesystemRevocationCheckpoint.PublishedGeneration current =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(),
                                cleanupFailure);
                assertTrue(Files.isRegularFile(current.path()));
                assertEquals(2L, current.coveredRevision());
            }
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void frozenSnapshotCloseInvalidatesCursorAndDeletesCopy() throws Exception {
        System.out.print("frozenSnapshotCloseInvalidatesCursorAndDeletesCopy ");
        try (Fixture fixture = fixture("frozen-close")) {
            fixture.log().append(new PkiId("credential:first"), held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                Files.createDirectories(fixture.workRoot());
                Path copy = fixture.workRoot().resolve("frozen-copy");
                FilesystemRevocationCurrentIndex.FrozenSnapshot frozen =
                        index.freeze(copy, 17);
                FilesystemRevocationCurrentIndex.FrozenCursor cursor = frozen.openCursor();
                frozen.close();
                frozen.close();
                assertThrows(IllegalStateException.class, cursor::advance);
                assertThrows(IllegalStateException.class, frozen::openCursor);
                cursor.close();
                cursor.close();
                assertFalse(Files.exists(copy));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void frozenCloseFailureCannotReplacePublishedGeneration() throws Exception {
        System.out.print("frozenCloseFailureCannotReplacePublishedGeneration ");
        try (Fixture fixture = fixture("frozen-close-outcome")) {
            fixture.log().append(new PkiId("credential:first"), held(1L, 1L));
            FilesystemRevocationCheckpointBuilder.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.FROZEN_CLOSE) {
                    throw new IOException("injected frozen close failure");
                }
            };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration generation =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(),
                                faults);
                assertTrue(Files.isRegularFile(generation.path()));
            }
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void frozenCloseFailureIsSuppressedBeforePublication() throws Exception {
        System.out.print("frozenCloseFailureIsSuppressedBeforePublication ");
        try (Fixture fixture = fixture("frozen-close-primary")) {
            fixture.log().append(new PkiId("credential:first"), held(1L, 1L));
            FilesystemRevocationCheckpointBuilder.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.RUN_WRITE) {
                    throw new IOException("primary run failure");
                }
                if (point == FilesystemRevocationCheckpointBuilder.FaultPoint.FROZEN_CLOSE) {
                    throw new IOException("secondary frozen close failure");
                }
            };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                IOException failure = assertThrows(IOException.class, () ->
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(),
                                faults));
                assertEquals("primary run failure", failure.getMessage());
                assertEquals(1, failure.getSuppressed().length);
                assertEquals("secondary frozen close failure",
                        failure.getSuppressed()[0].getMessage());
            }
            assertFalse(hasCheckpoint(fixture.checkpoints()));
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void malformedFrozenSlotPopulationFailsBeforePublication() throws Exception {
        System.out.print("malformedFrozenSlotPopulationFailsBeforePublication ");
        try (Fixture fixture = fixture("malformed-frozen")) {
            fixture.log().append(new PkiId("credential:first"), held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                clearIndexCells(fixture.indexPath());
                assertThrows(IOException.class, () ->
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration()));
            }
            assertFalse(hasCheckpoint(fixture.checkpoints()));
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void maximumComponentEntryIsOneBoundedSingletonRun() throws Exception {
        System.out.print("maximumComponentEntryIsOneBoundedSingletonRun ");
        try (Fixture fixture = fixture("maximum-singleton")) {
            PkiId identity = new PkiId(
                    "x".repeat(RevocationTransitionFrameCodec.MAX_COMPONENT_BYTES));
            fixture.log().append(identity, held(1L, 1L));
            AtomicLong maximumEntries = new AtomicLong();
            FilesystemRevocationCheckpointBuilder.FaultInjector observer =
                    new FilesystemRevocationCheckpointBuilder.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCheckpointBuilder.FaultPoint point) {
                            // Observation only.
                        }

                        @Override
                        public void observeRunBuffer(long entryCount, long encodedBytes) {
                            maximumEntries.accumulateAndGet(entryCount, Math::max);
                        }
                    };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpoint.PublishedGeneration generation =
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(),
                                observer);
                try (FilesystemRevocationCheckpoint checkpoint =
                        FilesystemRevocationCheckpoint.open(
                                generation.path(), fixture.logPath(), fixture.log().scan())) {
                    assertEquals(1L, checkpoint.entryCount());
                }
            }
            assertEquals(1L, maximumEntries.get());
        }
        System.out.println("...ok");
    }

    @Test
    void duplicateIdentityInjectedIntoTemporaryRunFailsClosed() throws Exception {
        System.out.print("duplicateIdentityInjectedIntoTemporaryRunFailsClosed ");
        try (Fixture fixture = fixture("duplicate-run")) {
            fixture.log().append(new PkiId("credential:first"), held(1L, 1L));
            AtomicBoolean rewritten = new AtomicBoolean();
            FilesystemRevocationCheckpointBuilder.FaultInjector faults =
                    new FilesystemRevocationCheckpointBuilder.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCheckpointBuilder.FaultPoint point) {
                            // Duplicate injection occurs after strict run creation.
                        }

                        @Override
                        public void afterRunWritten(Path run) throws IOException {
                            if (rewritten.compareAndSet(false, true)) {
                                rewriteRunWithDuplicate(run);
                            }
                        }
                    };
            FilesystemRevocationCheckpointBuilder.Configuration oneRun =
                    new FilesystemRevocationCheckpointBuilder.Configuration(
                            Long.MAX_VALUE, 2, 37, fixture.workRoot());
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                assertThrows(IOException.class, () ->
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), oneRun, faults));
            }
            assertFalse(hasCheckpoint(fixture.checkpoints()));
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    @Test
    void authenticSupersededTransitionCannotReplaceFrozenCurrentState() throws Exception {
        System.out.print("authenticSupersededTransitionCannotReplaceFrozenCurrentState ");
        try (Fixture fixture = fixture("superseded-authentic")) {
            PkiId identity = new PkiId("credential:first");
            RevocationTransitionFrameCodec.CompleteRecord heldRecord =
                    fixture.log().append(identity, held(1L, 1L));
            fixture.log().append(identity, clear(2L, 2L));
            RevocationCheckpointCodec.CurrentStateEntry superseded = entry(heldRecord);
            AtomicBoolean rewritten = new AtomicBoolean();
            FilesystemRevocationCheckpointBuilder.FaultInjector faults =
                    new FilesystemRevocationCheckpointBuilder.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCheckpointBuilder.FaultPoint point) {
                            // Authentic replacement occurs after strict run creation.
                        }

                        @Override
                        public void afterRunWritten(Path run) throws IOException {
                            if (rewritten.compareAndSet(false, true)) {
                                rewriteRunWithEntry(run, superseded);
                            }
                        }
                    };
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                assertThrows(IOException.class, () ->
                        FilesystemRevocationCheckpointBuilder.build(
                                index, fixture.checkpoints(), fixture.builderConfiguration(),
                                faults));
            }
            assertFalse(hasCheckpoint(fixture.checkpoints()));
            assertTrue(directoryEmpty(fixture.workRoot()));
        }
        System.out.println("...ok");
    }

    private Fixture fixture(String name) throws IOException {
        Path root = temporaryDirectory.resolve(name);
        FsPaths paths = new FsPaths(root);
        Path logPath = paths.revocationTransitionLog();
        Files.createDirectories(logPath.getParent());
        FilesystemRevocationLog log = FilesystemRevocationLog.create(
                logPath, STORE_ID, credential -> { });
        return new Fixture(
                logPath, paths.revocationCurrentIndex(),
                paths.revocationCheckpointDirectory(),
                paths.revocationCheckpointWorkDirectory(), log);
    }

    private static RevocationTransition held(long revision, long second) {
        return new RevocationTransition(
                revision, RevocationState.HELD, Instant.ofEpochSecond(second),
                Optional.empty(), new SimpleAttributeSet());
    }

    private static RevocationTransition clear(long revision, long second) {
        return new RevocationTransition(
                revision, RevocationState.CLEAR, Instant.ofEpochSecond(second),
                Optional.empty(), new SimpleAttributeSet());
    }

    private static RevocationTransition permanentWithAttributes(long revision, long second) {
        zeroecho.pki.api.attr.AttributeSet attributes = RevocationExecutionEvidence.administrative("operator-a",
                "realm-a", "request-a", RevocationExecutionEvidence.Authentication.DIRECT_MTLS,
                RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT, "a".repeat(64), Optional.empty())
                .attributes();
        return new RevocationTransition(
                revision, RevocationState.PERMANENTLY_REVOKED,
                Instant.ofEpochSecond(second), Optional.of(RevocationReason.KEY_COMPROMISE),
                attributes);
    }

    private static RevocationCheckpointCodec.CurrentStateEntry entry(
            RevocationTransitionFrameCodec.CompleteRecord record) {
        return new RevocationCheckpointCodec.CurrentStateEntry(
                record.data().credentialId(), record.data().globalRevision(),
                record.data().transition().revision(), record.commitment(),
                record.data().transition(), record.recordOffset(), record.recordEnd());
    }

    private static List<String> collect(FilesystemRevocationCheckpoint checkpoint)
            throws Exception {
        List<String> values = new ArrayList<>();
        try (FilesystemRevocationCheckpoint.Cursor cursor = checkpoint.allCurrentStates()) {
            while (cursor.advance(CancellationSignal.NONE)) {
                values.add(cursor.current().credentialId().value());
            }
        }
        return values;
    }

    private static List<RevocationCheckpointCodec.CurrentStateEntry> collectEntries(
            FilesystemRevocationCheckpoint checkpoint) throws Exception {
        List<RevocationCheckpointCodec.CurrentStateEntry> values = new ArrayList<>();
        try (FilesystemRevocationCheckpoint.Cursor cursor = checkpoint.allCurrentStates()) {
            while (cursor.advance(CancellationSignal.NONE)) {
                values.add(cursor.current());
            }
        }
        return values;
    }

    private static void corruptRun(Path run, boolean truncate) throws IOException {
        try (FileChannel channel = FileChannel.open(
                run, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            long last = channel.size() - 1L;
            if (truncate) {
                channel.truncate(last);
            } else {
                ByteBuffer byteValue = ByteBuffer.allocate(1);
                channel.read(byteValue, last);
                byteValue.flip();
                byteValue.put(0, (byte) (byteValue.get(0) ^ 0x5a));
                channel.write(byteValue, last);
            }
        }
    }

    private static void clearIndexCells(Path indexPath) throws IOException {
        try (FileChannel channel = FileChannel.open(
                indexPath, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            long offset = 2L * FilesystemRevocationCurrentIndex.SUPERBLOCK_BYTES;
            ByteBuffer zeros = ByteBuffer.allocate(512);
            while (offset < channel.size()) {
                zeros.clear();
                zeros.limit((int) Math.min((long) zeros.capacity(), channel.size() - offset));
                while (zeros.hasRemaining()) {
                    offset += channel.write(zeros, offset);
                }
            }
            channel.force(true);
        }
    }

    private static void rewriteRunWithDuplicate(Path run) throws IOException {
        try (FileChannel channel = FileChannel.open(
                run, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
            RevocationCheckpointCodec.ValidatedFile validated = codec.validate(channel);
            RevocationCheckpointCodec.DecodedRecord decoded = codec.sequentialDecoder().read(
                    channel, RevocationCheckpointCodec.HEADER_BYTES, validated.trailerOffset());
            RevocationCheckpointCodec.HeaderData original = validated.header();
            RevocationCheckpointCodec.HeaderData duplicateHeader =
                    new RevocationCheckpointCodec.HeaderData(
                            original.storeId(), original.coveredRevision(),
                            original.finalRecordStart(), original.coveredBoundary(),
                            original.globalCommitment(), 2L);
            RevocationCheckpointCodec.Encoder encoder = codec.encoder(channel, duplicateHeader);
            encoder.write(decoded.entry());
            encoder.write(decoded.entry());
            encoder.finish();
            channel.force(true);
        }
    }

    private static void rewriteRunWithEntry(
            Path run, RevocationCheckpointCodec.CurrentStateEntry entry) throws IOException {
        try (FileChannel channel = FileChannel.open(
                run, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
            RevocationCheckpointCodec.HeaderData original =
                    codec.validate(channel).header();
            RevocationCheckpointCodec.HeaderData replacementHeader =
                    new RevocationCheckpointCodec.HeaderData(
                            original.storeId(), original.coveredRevision(),
                            original.finalRecordStart(), original.coveredBoundary(),
                            original.globalCommitment(), 1L);
            RevocationCheckpointCodec.Encoder encoder =
                    codec.encoder(channel, replacementHeader);
            encoder.write(entry);
            encoder.finish();
            channel.force(true);
        }
    }

    private static List<PkiId> collect(
            FilesystemRevocationCurrentIndex.FrozenSnapshot frozen) throws Exception {
        List<PkiId> values = new ArrayList<>();
        try (FilesystemRevocationCurrentIndex.FrozenCursor cursor = frozen.openCursor()) {
            while (cursor.advance()) {
                values.add(cursor.current().credentialId());
            }
        }
        return values;
    }

    private static boolean directoryEmpty(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return true;
        }
        try (DirectoryStream<Path> paths = Files.newDirectoryStream(directory)) {
            return !paths.iterator().hasNext();
        }
    }

    private static boolean hasCheckpoint(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return false;
        }
        try (DirectoryStream<Path> paths = Files.newDirectoryStream(directory, "*.chk")) {
            return paths.iterator().hasNext();
        }
    }

    private record Fixture(
            Path logPath,
            Path indexPath,
            Path checkpoints,
            Path workRoot,
            FilesystemRevocationLog log) implements AutoCloseable {

        private FilesystemRevocationCurrentIndex rebuild() throws IOException {
            return FilesystemRevocationCurrentIndex.rebuild(
                    indexPath, logPath, STORE_ID, INDEX_CONFIGURATION);
        }

        private FilesystemRevocationCheckpointBuilder.Configuration builderConfiguration() {
            return new FilesystemRevocationCheckpointBuilder.Configuration(
                    1L, 2, 37, workRoot);
        }

        private void appendAll(List<PkiId> identities) throws IOException {
            long globalRevision = 1L;
            for (PkiId identity : identities) {
                log.append(identity, held(1L, globalRevision));
                globalRevision++;
            }
        }

        @Override
        public void close() throws IOException {
            log.close();
        }
    }
}
