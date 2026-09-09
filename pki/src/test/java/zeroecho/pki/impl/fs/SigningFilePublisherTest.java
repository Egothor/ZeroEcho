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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class SigningFilePublisherTest {

    @TempDir
    private Path temporaryDirectory;

    @Test
    void immutableAndManifestPublicationHaveExpectedReplacementSemantics() throws Exception {
        Path immutable = temporaryDirectory.resolve("segment.zew");
        SigningFilePublisher.publishImmutable(immutable, channel -> writePartial(channel, new byte[] { 1, 2, 3 }));
        assertArrayEquals(new byte[] { 1, 2, 3 }, Files.readAllBytes(immutable));
        assertThrows(SigningFilePublisher.PublicationException.class,
                () -> SigningFilePublisher.publishImmutable(immutable, channel -> { }));

        Path manifest = temporaryDirectory.resolve("manifest.zem");
        SigningFilePublisher.publishManifest(manifest, channel -> writePartial(channel, new byte[] { 1 }));
        SigningFilePublisher.publishManifest(manifest, channel -> writePartial(channel, new byte[] { 2 }));
        assertArrayEquals(new byte[] { 2 }, Files.readAllBytes(manifest));
    }

    @Test
    void everyPreMoveFaultDeletesTempAndPreservesTarget() throws Exception {
        for (SigningFilePublisher.PublicationStage stage : new SigningFilePublisher.PublicationStage[] {
                SigningFilePublisher.PublicationStage.WRITE,
                SigningFilePublisher.PublicationStage.FILE_FORCE }) {
            Path target = temporaryDirectory.resolve("target-" + stage);
            Files.write(target, new byte[] { 9 });
            FaultOperations operations = new FaultOperations(stage, false);
            SigningFilePublisher.PublicationException failure = assertThrows(
                    SigningFilePublisher.PublicationException.class,
                    () -> SigningFilePublisher.publish(target, true,
                            channel -> writePartial(channel, new byte[] { 1, 2 }), operations));
            assertEquals(stage, failure.stage());
            assertFalse(failure.durabilityUncertain());
            assertArrayEquals(new byte[] { 9 }, Files.readAllBytes(target));
            assertFalse(Files.exists(operations.temporary));
        }
    }

    @Test
    void atomicMoveUnsupportedHasNoFallbackAndDirectoryForceIsUncertain() throws Exception {
        Path unsupported = temporaryDirectory.resolve("unsupported");
        FaultOperations move = new FaultOperations(SigningFilePublisher.PublicationStage.ATOMIC_MOVE, true);
        SigningFilePublisher.PublicationException moveFailure = assertThrows(
                SigningFilePublisher.PublicationException.class,
                () -> SigningFilePublisher.publish(unsupported, false, channel -> { }, move));
        assertFalse(moveFailure.durabilityUncertain());
        assertFalse(Files.exists(unsupported));

        Path target = temporaryDirectory.resolve("uncertain");
        FaultOperations force = new FaultOperations(SigningFilePublisher.PublicationStage.DIRECTORY_FORCE, false);
        SigningFilePublisher.PublicationException forceFailure = assertThrows(
                SigningFilePublisher.PublicationException.class,
                () -> SigningFilePublisher.publish(target, false,
                        channel -> writePartial(channel, new byte[] { 7 }), force));
        assertTrue(forceFailure.durabilityUncertain());
        assertTrue(Files.exists(target));
        assertFalse(Files.exists(force.temporary));
    }

    @Test
    void ambiguousMoveFailureNeverClaimsRollbackOrDeletesPossibleSource() throws Exception {
        for (boolean replace : new boolean[] { false, true }) {
            Path target = temporaryDirectory.resolve("committed-then-failed-" + replace);
            if (replace) {
                Files.write(target, new byte[] { 9 });
            }
            FaultOperations operations = new FaultOperations(null, false);
            operations.commitThenThrow = true;
            SigningFilePublisher.PublicationException failure = assertThrows(
                    SigningFilePublisher.PublicationException.class,
                    () -> SigningFilePublisher.publish(target, replace,
                            channel -> writePartial(channel, new byte[] { 4 }), operations));
            assertEquals(SigningFilePublisher.PublicationStage.ATOMIC_MOVE, failure.stage());
            assertTrue(failure.durabilityUncertain());
            assertArrayEquals(new byte[] { 4 }, Files.readAllBytes(target));
            assertFalse(Files.exists(operations.temporary));
        }

        Path target = temporaryDirectory.resolve("ambiguous-before-visible-move");
        FaultOperations operations = new FaultOperations(SigningFilePublisher.PublicationStage.ATOMIC_MOVE, false);
        SigningFilePublisher.PublicationException failure = assertThrows(
                SigningFilePublisher.PublicationException.class,
                () -> SigningFilePublisher.publish(target, false, channel -> { }, operations));
        assertTrue(failure.durabilityUncertain());
        assertTrue(Files.exists(operations.temporary));
    }

    @Test
    @RequiresSymlinkCreation
    void replacedTemporaryPathIsRejectedWithoutFollowingSymlink() throws Exception {
        Path arbitrary = temporaryDirectory.resolve("arbitrary");
        Files.write(arbitrary, new byte[] { 8 });
        Path target = temporaryDirectory.resolve("target");
        FaultOperations operations = new FaultOperations(null, false);
        operations.replaceTemporaryWithSymlink = arbitrary;
        SigningFilePublisher.PublicationException failure = assertThrows(
                SigningFilePublisher.PublicationException.class,
                () -> SigningFilePublisher.publish(target, false,
                        channel -> writePartial(channel, new byte[] { 1 }), operations));
        assertFalse(failure.durabilityUncertain());
        assertArrayEquals(new byte[] { 8 }, Files.readAllBytes(arbitrary));
        assertFalse(Files.exists(target));
        assertTrue(Files.exists(operations.temporary, java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    @RequiresFileIdentity
    void cleanupNeverDeletesReplacementRegularFile() throws Exception {
        Path target = temporaryDirectory.resolve("regular-replacement-target");
        FaultOperations operations = new FaultOperations(SigningFilePublisher.PublicationStage.FILE_FORCE, false);
        operations.replaceTemporaryWithRegularFile = true;
        SigningFilePublisher.PublicationException failure = assertThrows(
                SigningFilePublisher.PublicationException.class,
                () -> SigningFilePublisher.publish(target, false,
                        channel -> writePartial(channel, new byte[] { 1 }), operations));
        assertFalse(failure.durabilityUncertain());
        assertArrayEquals(new byte[] { 6 }, Files.readAllBytes(operations.temporary));
        assertFalse(Files.exists(target));
    }

    private static void writePartial(FileChannel channel, byte[] bytes) throws IOException {
        for (byte value : bytes) {
            SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(new byte[] { value }));
        }
    }

    private final class FaultOperations implements SigningFilePublisher.PublicationOperations {
        private final SigningFilePublisher.PublicationStage fault;
        private final boolean unsupported;
        private Path temporary;
        private boolean commitThenThrow;
        private Path replaceTemporaryWithSymlink;
        private boolean replaceTemporaryWithRegularFile;
        private Object originalKey;

        private FaultOperations(SigningFilePublisher.PublicationStage fault, boolean unsupported) {
            this.fault = fault;
            this.unsupported = unsupported;
        }

        @Override
        public SigningFilePublisher.TemporaryFile createTemporary(Path parent, String prefix) throws IOException {
            temporary = Files.createTempFile(parent, prefix, ".tmp");
            originalKey = Files.readAttributes(temporary, java.nio.file.attribute.BasicFileAttributes.class,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS).fileKey();
            return new SigningFilePublisher.TemporaryFile(temporary,
                    FileChannel.open(temporary, StandardOpenOption.WRITE), originalKey);
        }

        @Override
        public void write(FileChannel channel, SigningFilePublisher.ContentWriter writer) throws IOException {
            fail(SigningFilePublisher.PublicationStage.WRITE);
            writer.write(channel);
        }

        @Override
        public void forceFile(FileChannel channel) throws IOException {
            if (replaceTemporaryWithRegularFile) {
                channel.close();
                Files.delete(temporary);
                Files.write(temporary, new byte[] { 6 }, StandardOpenOption.CREATE_NEW);
            }
            fail(SigningFilePublisher.PublicationStage.FILE_FORCE);
        }

        @Override
        public void validateTemporary(SigningFilePublisher.TemporaryFile value) throws IOException {
            if (replaceTemporaryWithSymlink != null) {
                Files.delete(value.path());
                Files.createSymbolicLink(value.path(), replaceTemporaryWithSymlink);
                throw new java.nio.file.FileAlreadyExistsException("changed");
            }
        }

        @Override
        public void atomicMove(Path source, Path target, boolean replace) throws IOException {
            fail(SigningFilePublisher.PublicationStage.ATOMIC_MOVE);
            if (replace) {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
            }
            if (commitThenThrow) {
                throw new IOException("ambiguous after move");
            }
        }

        @Override
        public void forceDirectory(Path directory) throws IOException {
            fail(SigningFilePublisher.PublicationStage.DIRECTORY_FORCE);
        }

        @Override
        public void deleteTemporary(SigningFilePublisher.TemporaryFile value) throws IOException {
            if (!Files.exists(value.path(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                return;
            }
            java.nio.file.attribute.BasicFileAttributes current = Files.readAttributes(value.path(),
                    java.nio.file.attribute.BasicFileAttributes.class,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS);
            // fileKey() is null where the filesystem has no stable file identity
            // (e.g. Windows); fall back to the regular-file check there.
            if (current.isRegularFile()
                    && (value.fileKey() == null || value.fileKey().equals(current.fileKey()))) {
                Files.delete(value.path());
            }
        }

        private void fail(SigningFilePublisher.PublicationStage current) throws IOException {
            if (fault == current) {
                if (unsupported && current == SigningFilePublisher.PublicationStage.ATOMIC_MOVE) {
                    throw new AtomicMoveNotSupportedException("source", "target", "unsupported");
                }
                throw new IOException("injected");
            }
        }
    }
}
