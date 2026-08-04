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
package zeroecho.pki.impl.publish;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.spi.publish.PublicationAttempt;
import zeroecho.pki.spi.publish.PublicationOutcome;
import zeroecho.pki.spi.publish.Publisher;

/** Bounded-memory, idempotent publisher for one administrator-owned directory. */
final class FilesystemPublisher implements Publisher {
    private static final int BUFFER_BYTES = 16 * 1024;

    private final PublicationTarget target;
    private final Path root;

    /* default */ FilesystemPublisher(PublicationTarget target, Path root) {
        this.target = Objects.requireNonNull(target, "target");
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
    }

    @Override
    public PublicationTarget target() {
        return target;
    }

    @Override
    public PublicationOutcome publish(PublicationAttempt attempt, RepeatableContent payload) {
        Objects.requireNonNull(attempt, "attempt");
        Objects.requireNonNull(payload, "payload");
        Path destination = destination(attempt);
        Path temporary = destination.resolveSibling(destination.getFileName() + ".tmp-" + attempt.attemptToken());
        try {
            Files.createDirectories(root);
            if (Files.exists(destination)) {
                return matches(destination, attempt) ? PublicationOutcome.SUCCESS : PublicationOutcome.TERMINAL_FAILURE;
            }
            writeValidated(temporary, payload, attempt);
            try {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException failure) {
                return PublicationOutcome.RETRYABLE_FAILURE;
            }
            forceDirectory();
            return PublicationOutcome.SUCCESS;
        } catch (IOException failure) {
            return Files.exists(destination) && matchesUnchecked(destination, attempt) ? PublicationOutcome.SUCCESS
                    : PublicationOutcome.RETRYABLE_FAILURE;
        } finally {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException ignored) {
                // Definite publication outcome is not changed by temporary cleanup.
            }
        }
    }

    @Override
    public Optional<PublicationOutcome> reconcile(PublicationAttempt attempt) {
        Objects.requireNonNull(attempt, "attempt");
        Path destination = destination(attempt);
        if (!Files.exists(destination)) {
            return Optional.of(PublicationOutcome.RETRYABLE_FAILURE);
        }
        return Optional.of(matchesUnchecked(destination, attempt) ? PublicationOutcome.SUCCESS
                : PublicationOutcome.TERMINAL_FAILURE);
    }

    private Path destination(PublicationAttempt attempt) {
        byte[] identity = attempt.publicationId().value().getBytes(StandardCharsets.UTF_8);
        return root.resolve(HexFormat.of().formatHex(sha256().digest(identity)) + ".bin");
    }

    private static void writeValidated(Path path, RepeatableContent payload, PublicationAttempt attempt)
            throws IOException {
        MessageDigest digest = sha256();
        long count = 0L;
        ByteBuffer buffer = ByteBuffer.allocate(BUFFER_BYTES);
        try (InputStream input = payload.openStream(); FileChannel output = FileChannel.open(path,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] bytes = buffer.array();
            int read;
            while ((read = input.read(bytes)) >= 0) {
                if (read == 0) {
                    continue;
                }
                count = Math.addExact(count, read);
                digest.update(bytes, 0, read);
                buffer.clear().limit(read);
                while (buffer.hasRemaining()) {
                    output.write(buffer);
                }
            }
            output.force(true);
        }
        String actual = HexFormat.of().formatHex(digest.digest());
        if (count != attempt.length() || !actual.equals(attempt.sha256())) {
            throw new IOException("Publication content commitment mismatch");
        }
    }

    private static boolean matches(Path path, PublicationAttempt attempt) throws IOException {
        if (Files.size(path) != attempt.length()) {
            return false;
        }
        MessageDigest digest = sha256();
        byte[] buffer = new byte[BUFFER_BYTES];
        try (InputStream input = Files.newInputStream(path)) {
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) {
                    digest.update(buffer, 0, read);
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest()).equals(attempt.sha256());
    }

    private static boolean matchesUnchecked(Path path, PublicationAttempt attempt) {
        try {
            return matches(path, attempt);
        } catch (IOException failure) {
            return false;
        }
    }

    private void forceDirectory() throws IOException {
        try (FileChannel directory = FileChannel.open(root, StandardOpenOption.READ)) {
            directory.force(true);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }
}
