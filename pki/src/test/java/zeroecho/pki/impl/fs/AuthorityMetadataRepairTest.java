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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.testkit.IntermediateCreationFixture;

final class AuthorityMetadataRepairTest {
    @Test void committedLargeAuthorityAndCredentialPayloadsReadAndReopen(@TempDir Path root) throws Exception {
        Credential credential;
        IssuerGeneration generation;
        try (FilesystemPkiStore store = open(root)) {
            Credential original = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "large-record", "profile");
            SimpleAttributeSet attributes = new SimpleAttributeSet(List.of(
                    new SimpleAttributeSet.Entry(new AttributeId("first"), List.of(new AttributeValue.StringValue("a".repeat(600_000)))),
                    new SimpleAttributeSet.Entry(new AttributeId("second"), List.of(new AttributeValue.StringValue("b".repeat(600_000))))));
            credential = new Credential(original.credentialId(), original.formatId(), original.issuerRef(), original.subjectRef(), original.validity(),
                    original.serialOrUniqueId(), original.publicKeyId(), original.profileBinding(), original.status(), original.content(), attributes);
            requireAboveOldReadCeiling(FsCodec.encode(FsCodec.CREDENTIAL, credential));
            store.putCredential(credential);
            generation = generation(new PkiId("authority:" + "a".repeat(100_000)), credential.credentialId(), new KeyRef("k".repeat(1_048_576)));
            requireAboveOldReadCeiling(FsCodec.encode(FsCodec.ISSUER_GENERATION, generation));
            store.putIssuerGeneration(generation);
            assertEquals(generation, store.getIssuerGeneration(generation.issuerId()).orElseThrow());
            assertArrayEquals(FsCodec.encode(FsCodec.CREDENTIAL, credential),
                    FsCodec.encode(FsCodec.CREDENTIAL, store.getCredential(credential.credentialId()).orElseThrow()));
        }
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(generation, store.getIssuerGeneration(generation.issuerId()).orElseThrow());
            assertArrayEquals(FsCodec.encode(FsCodec.CREDENTIAL, credential),
                    FsCodec.encode(FsCodec.CREDENTIAL, store.getCredential(credential.credentialId()).orElseThrow()));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"selected", "unselected", "owner", "content", "path-ancestor"})
    void liveCaReadsRejectDamagedCredentialAuthorityAfterOpen(String damage, @TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            CaRecord ca;
            Credential victim;
            if (damage.equals("path-ancestor")) {
                IntermediateCreationFixture fixture = new IntermediateCreationFixture();
                fixture.initialize(store, 2);
                fixture.intermediateParent(store, 1, false);
                ca = store.getCa(new PkiId("middle-authority")).orElseThrow();
                PkiId ancestor = store.getIssuerChainPath(ca.issuanceChainPathId()).orElseThrow().orderedCredentialIds().getLast();
                victim = store.getCredential(ancestor).orElseThrow();
            } else {
                ca = FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "read-authority", CaState.ACTIVE);
                store.putCa(ca);
                victim = store.getCredential(store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow().credentialId()).orElseThrow();
                if (damage.equals("unselected")) {
                    victim = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "unselected", "profile");
                    store.putCredential(victim);
                    IssuerGeneration additional = generation(ca.caId(), victim.credentialId(), new KeyRef("additional-key"));
                    store.putIssuerGeneration(additional);
                    List<PkiId> members = new ArrayList<>(ca.issuerIds());
                    members.add(additional.issuerId());
                    ca = new CaRecord(ca.caId(), ca.kind(), ca.state(), ca.issuerKeyRef(), ca.subjectRef(), members,
                            ca.currentIssuanceIssuerId(), ca.issuanceChainPathId());
                    store.putCa(ca);
                }
            }
            assertEquals(ca, store.getCa(ca.caId()).orElseThrow());
            if (damage.equals("content")) {
                Path path = root.resolve("staged-content").resolve(victim.content().contentId() + ".content");
                byte[] bytes = Files.readAllBytes(path);
                bytes[0] ^= 1;
                Files.write(path, bytes);
            } else {
                MetadataKey key = damage.equals("owner") ? AuthorityMetadataCodec.ownerSetKey(victim.content().contentId())
                        : AuthorityMetadataCodec.credentialKey(victim.credentialId());
                try (MetadataSnapshot snapshot = store.metadataStore().snapshot(); MetadataSnapshot.Record row = snapshot.get(key).orElseThrow();
                        MetadataTransaction transaction = store.metadataStore().beginTransaction()) {
                    transaction.delete(key, row.recordRevision());
                    assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
                }
            }
            PkiId id = ca.caId();
            assertThrows(IllegalStateException.class, () -> store.getCa(id));
            assertThrows(IllegalStateException.class, store::listCas);
            assertThrows(IllegalStateException.class, () -> store.listCasPage(Optional.empty(), 10));
        }
    }

    @Test void startupStreamsLargeKeyReferencesWithinFixedHeap(@TempDir Path temporary) throws Exception {
        Path root = temporary.resolve("store");
        try (FilesystemPkiStore store = open(root)) {
            Credential credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "heap", "profile");
            store.putCredential(credential);
            KeyRef shared = new KeyRef("k".repeat(1_048_576));
            for (int index = 0; index < 128; index++) {
                store.putIssuerGeneration(generation(new PkiId("heap-authority:" + index), credential.credentialId(), shared));
            }
        }
        String executable = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win") ? "java.exe" : "java";
        Path java = Path.of(System.getProperty("java.home"), "bin", executable);
        Path output = temporary.resolve("reopen.log");
        Process process = new ProcessBuilder(java.toString(), "-Xmx96m", "-cp", childClasspath(), ReopenProcess.class.getName(), root.toString())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "Fixed-heap reopen timed out");
            assertEquals(0, process.exitValue(), () -> {
                try { return Files.readString(output, StandardCharsets.UTF_8); }
                catch (java.io.IOException failure) { return "Child output unavailable"; }
            });
        } finally {
            if (process.isAlive()) { process.destroyForcibly(); process.waitFor(10, TimeUnit.SECONDS); }
        }
    }

    private static void requireAboveOldReadCeiling(byte[] bytes) {
        assertTrue(bytes.length > 1_114_112);
        assertTrue(bytes.length < AuthorityMetadataCodec.MAX_VALUE_BYTES);
    }

    private static IssuerGeneration generation(PkiId authority, PkiId credential, KeyRef key) {
        return new IssuerGeneration(IssuerGeneration.idFor(authority, credential), authority, credential, key,
                IssuerGenerationState.ACTIVE, "0".repeat(64), "1".repeat(64));
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()); }

    private static String childClasspath() throws Exception {
        Set<String> entries = new LinkedHashSet<>();
        String configured = System.getProperty("java.class.path", "");
        if (!configured.isBlank()) { entries.addAll(List.of(configured.split(java.io.File.pathSeparator))); }
        for (ClassLoader loader = AuthorityMetadataRepairTest.class.getClassLoader(); loader != null; loader = loader.getParent()) {
            if (loader instanceof URLClassLoader urls) {
                for (URL url : urls.getURLs()) { if (url.getProtocol().equals("file")) { entries.add(Path.of(url.toURI()).toString()); } }
            }
        }
        for (Class<?> type : List.of(AuthorityMetadataRepairTest.class, FilesystemPkiStore.class)) {
            entries.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        }
        return String.join(java.io.File.pathSeparator, entries);
    }

    /** Isolated startup-only probe; a materialized 128-MiB generation list cannot fit. */
    public static final class ReopenProcess {
        public static void main(String[] arguments) throws Exception {
            java.util.logging.LogManager.getLogManager().reset();
            try (FilesystemPkiStore store = open(Path.of(arguments[0]))) {
                if (!store.listCas().isEmpty()) { throw new AssertionError("Unexpected authority head"); }
            }
        }
    }
}
