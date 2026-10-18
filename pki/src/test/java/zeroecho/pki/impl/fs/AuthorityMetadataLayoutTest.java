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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.credential.Credential;

final class AuthorityMetadataLayoutTest {
    @ParameterizedTest @ValueSource(strings = {
        "cas/by-id/legacy/current.bin", "cas/by-id/legacy/history/123-1.bin",
        "issuer-generations/by-id/legacy.bin", "issuer-chain-paths/by-id/legacy.bin",
        "credentials/by-id/legacy.bin", "credential-handoffs/legacy.intent",
        "credential-handoffs/legacy.credential.pending", "credentials/by-id/legacy.credential.pending"
    })
    void populatedLegacyAuthorityFailsBeforeMutation(String relative, @TempDir Path root) throws Exception {
        {
            FilesystemPkiStore ignored = open(root);
            if (ignored != null) {
                ignored.close();
            }
        }
        Path legacy = root.resolve(relative);
        Files.createDirectories(legacy.getParent());
        Files.write(legacy, new byte[] {1, 2, 3});
        Map<String, String> before = image(root);
        assertThrows(IllegalStateException.class, () -> open(root));
        assertEquals(before, image(root));
    }

    @Test void previousVersionIsRejectedWithoutRepairAndEmptyDirectoriesAreAccepted(@TempDir Path root) throws Exception {
        {
            FilesystemPkiStore ignored = open(root);
            if (ignored != null) {
                ignored.close();
            }
        }
        assertEquals("v18", Files.readString(root.resolve("VERSION"), StandardCharsets.US_ASCII));
        for (String path : List.of("cas/by-id/empty/history", "issuer-generations/by-id", "issuer-chain-paths/by-id",
                "credentials/by-id", "credential-handoffs")) { Files.createDirectories(root.resolve(path)); }
        {
            FilesystemPkiStore ignored = open(root);
            if (ignored != null) {
                ignored.close();
            }
        }
        for (String previous : List.of("v13", "v17")) {
            Files.writeString(root.resolve("VERSION"), previous, StandardCharsets.US_ASCII);
            Map<String, String> before = image(root);
            assertThrows(IllegalStateException.class, () -> open(root));
            assertEquals(before, image(root));
        }
    }

    @Test void legacyCredentialSidecarOwnerIsRejectedBeforeReclamation(@TempDir Path root) throws Exception {
        Credential credential;
        try (FilesystemPkiStore store = open(root)) {
            credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "legacy-owner", "profile");
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeByte(2);
            output.writeUTF(credential.content().contentId());
            output.writeInt(1);
            output.writeUTF(DurableContentOwner.credentialRecord(credential.credentialId()).canonicalForm());
        }
        Files.write(root.resolve("staged-content").resolve(credential.content().contentId() + ".owners"), bytes.toByteArray());
        Map<String, String> before = image(root);
        assertThrows(IllegalStateException.class, () -> open(root));
        assertEquals(before, image(root));
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()); }

    private static Map<String, String> image(Path root) throws Exception {
        Map<String, String> result = new LinkedHashMap<>();
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted().toList()) {
                result.put(root.relativize(path).toString(), Files.isDirectory(path) ? "directory"
                        : Base64.getEncoder().encodeToString(Files.readAllBytes(path)));
            }
        }
        return result;
    }
}
