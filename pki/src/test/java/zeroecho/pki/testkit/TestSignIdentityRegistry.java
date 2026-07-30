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
package zeroecho.pki.testkit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SignatureWorkflow.SignRequest;

/**
 * Durable exact-idempotency helper shared by filesystem-backed test providers.
 */
final class TestSignIdentityRegistry {
    private final Path root;
    private final Map<PkiId, Object> locks = new ConcurrentHashMap<>();

    TestSignIdentityRegistry(Path providerRoot) {
        this.root = providerRoot.resolve(".sign-identities");
    }

    boolean begin(SignRequest request) {
        Object lock = locks.computeIfAbsent(request.submissionId(), ignored -> new Object());
        synchronized (lock) {
            Path path = path(request.submissionId());
            if (Files.exists(path)) {
                Identity existing = read(path);
                if (!constantTimeEquals(existing.fingerprint, request.semanticFingerprint())) {
                    throw new IllegalStateException("conflicting signing request");
                }
                if (request.fencingToken() < existing.fence) {
                    throw new IllegalStateException("stale signing fence");
                }
                if (request.fencingToken() > existing.fence) {
                    write(path, new Identity(existing.fingerprint, request.fencingToken()));
                }
                return false;
            }
            write(path, new Identity(request.semanticFingerprint(), request.fencingToken()));
            return true;
        }
    }

    boolean acceptFence(PkiId operationId, long fence) {
        Object lock = locks.computeIfAbsent(operationId, ignored -> new Object());
        synchronized (lock) {
            Path path = path(operationId);
            if (!Files.exists(path)) {
                return false;
            }
            Identity existing = read(path);
            if (fence < existing.fence) {
                return false;
            }
            write(path, new Identity(existing.fingerprint, fence));
            return true;
        }
    }

    private Path path(PkiId id) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(id.value().getBytes(StandardCharsets.UTF_8));
            return root.resolve(HexFormat.of().formatHex(hash) + ".txt");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static Identity read(Path path) {
        try {
            String[] parts = Files.readString(path, StandardCharsets.US_ASCII).split("\\n", -1);
            if (parts.length != 2) {
                throw new IllegalStateException("corrupt test signing identity");
            }
            return new Identity(parts[0], Long.parseLong(parts[1]));
        } catch (IOException | NumberFormatException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void write(Path path, Identity identity) {
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, identity.fingerprint + "\n" + identity.fence, StandardCharsets.US_ASCII);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static boolean constantTimeEquals(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII),
                right.getBytes(StandardCharsets.US_ASCII));
    }

    private record Identity(String fingerprint, long fence) {
    }
}
