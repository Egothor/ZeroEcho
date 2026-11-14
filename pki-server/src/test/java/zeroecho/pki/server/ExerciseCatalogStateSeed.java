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
package zeroecho.pki.server;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.impl.core.DefaultPublicationService;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.publish.FilesystemPublisherProvider;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.publish.PublicationAttempt;
import zeroecho.pki.spi.publish.PublicationOutcome;
import zeroecho.pki.spi.publish.Publisher;

/**
 * Test-only offline preparation of publication retry/reconciliation preconditions.
 * The disposable launcher must stop and inspect its owned backend before creating
 * the one-use authorization file. This helper never authenticates an HTTP actor,
 * bypasses a store transition, fabricates an approval or opens private key material.
 * A prepared unknown outcome models lost acknowledgement, not an observed crash.
 */
public final class ExerciseCatalogStateSeed {
    private ExerciseCatalogStateSeed() { }

    /**
     * Seeds one owned PENDING publication through real domain processing.
     * @param arguments fixture root, fixture nonce, exercise run ID, publication ID,
     *        immutable source SHA-256 and RETRYABLE_FAILURE or OUTCOME_UNKNOWN
     * @throws Exception if ownership, one-use stop authorization, domain processing
     *         or immutable content validation cannot be established
     */
    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 6) throw new IllegalArgumentException("Six fixture arguments required");
        Path root = Path.of(arguments[0]).toAbsolutePath().normalize();
        String nonce = arguments[1], runId = arguments[2], publicationId = arguments[3], sha256 = arguments[4];
        PublicationStatus requested = PublicationStatus.valueOf(arguments[5]);
        if (!nonce.matches("[0-9a-f]{32}") || !runId.matches("[0-9a-f]{32}")
                || !publicationId.matches("exercise-" + runId + "-[a-z0-9-]{1,64}")
                || !sha256.matches("[0-9a-f]{64}")
                || !Set.of(PublicationStatus.RETRYABLE_FAILURE, PublicationStatus.OUTCOME_UNKNOWN).contains(requested)) {
            throw new IllegalArgumentException("Invalid fixture identity or requested state");
        }
        requirePrivate(root, true);
        root = root.toRealPath();
        Map<String, PkiOperationValue> owner = object(root.resolve(".exercise-owner.json"));
        if (!text(owner, "nonce").equals(nonce)) throw new IllegalStateException("Fixture owner differs");
        Map<String, PkiOperationValue> configuration = object(root.resolve("config/server.json"));
        var realm = ((PkiOperationValue.ObjectValue) configuration.get("realm")).fields();
        if (!text(realm, "realmId").equals("zeroecho-exercise-" + nonce)) {
            throw new IllegalStateException("Fixture realm differs");
        }
        Path authorization = root.resolve(".exercise-seed-authorization.json");
        var grant = object(authorization);
        if (!text(grant, "nonce").equals(nonce) || !text(grant, "runId").equals(runId)
                || !text(grant, "publicationId").equals(publicationId) || !text(grant, "sourceSha256").equals(sha256)
                || !text(grant, "state").equals(requested.name())
                || !(grant.get("backendStopped") instanceof PkiOperationValue.BooleanValue stopped) || !stopped.value()
                || !text(grant, "serverId").matches("[0-9a-f]{64}") || !text(grant, "ticket").matches("[0-9a-f]{32}")) {
            throw new IllegalStateException("Stopped fixture authorization differs");
        }
        Files.move(authorization, root.resolve(".exercise-seed-consumed-" + text(grant, "ticket") + ".json"), StandardCopyOption.ATOMIC_MOVE);
        Path storeRoot = root.resolve("store-container/store").toRealPath();
        Path publisherRoot = root.resolve("artifacts/publication").toRealPath();
        if (!storeRoot.startsWith(root) || !publisherRoot.startsWith(root)) throw new IllegalStateException("Fixture path escaped ownership");
        Clock clock = Clock.systemUTC();
        try (var store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock)) {
            var pending = store.getPublicationRecord(new PkiId(publicationId)).orElseThrow();
            if (pending.status() != PublicationStatus.PENDING || !pending.content().sha256().equals(sha256)
                    || !pending.target().targetId().equals("exercise-files")) {
                throw new IllegalStateException("Publication immutable precondition differs");
            }
            Publisher actual = new FilesystemPublisherProvider().allocate(new ProviderConfig("filesystem",
                    Map.of("root", publisherRoot.toString(), "targetId", "exercise-files")));
            Publisher fault = new Publisher() {
                @Override public PublicationTarget target() { return actual.target(); }
                @Override public PublicationOutcome publish(PublicationAttempt attempt, RepeatableContent payload) {
                    if (requested == PublicationStatus.RETRYABLE_FAILURE) return PublicationOutcome.RETRYABLE_FAILURE;
                    if (actual.publish(attempt, payload) != PublicationOutcome.SUCCESS) {
                        throw new IllegalStateException("Fixture filesystem publication did not succeed");
                    }
                    throw new IllegalStateException("Fixture simulates acknowledgement loss after a real filesystem effect");
                }
                @Override public Optional<PublicationOutcome> reconcile(PublicationAttempt attempt) { return actual.reconcile(attempt); }
            };
            try (var service = new DefaultPublicationService(store, clock, List.of(fault))) {
                var result = service.process(pending.publicationId());
                if (result.status() != requested) throw new IllegalStateException("Requested crash-state precondition was not established");
                var retained = store.getPublicationRecord(pending.publicationId()).orElseThrow();
                if (!retained.hasSameOperation(pending) || retained.status() != requested) {
                    throw new IllegalStateException("Publication provenance changed");
                }
            }
            System.out.println("PUBLICATION_STATE_READY");
        }
    }

    private static Map<String, PkiOperationValue> object(Path path) throws Exception {
        requirePrivate(path, false);
        if (Files.size(path) > 1024 * 1024) throw new IllegalArgumentException("Fixture metadata exceeds its bound");
        return ((PkiOperationValue.ObjectValue) StrictJson.parse(Files.readAllBytes(path), 1024 * 1024)).fields();
    }
    private static String text(Map<String, PkiOperationValue> object, String key) {
        return ((PkiOperationValue.Text) object.get(key)).value();
    }
    private static void requirePrivate(Path path, boolean directory) throws Exception {
        if (Files.isSymbolicLink(path) || !(directory ? Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                : Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))) throw new IllegalArgumentException("Private fixture path required");
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
        if (permissions.stream().anyMatch(value -> value.name().startsWith("GROUP_") || value.name().startsWith("OTHERS_"))) {
            throw new IllegalArgumentException("Fixture path is not private");
        }
    }
}
