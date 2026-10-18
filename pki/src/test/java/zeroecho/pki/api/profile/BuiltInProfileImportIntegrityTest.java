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
package zeroecho.pki.api.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.DefaultProfileService;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Built-in template integrity checks at the production import boundary.
 */
final class BuiltInProfileImportIntegrityTest {
    private static final String SENTINEL = "profile-integrity-sentinel";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-30T10:00:00Z"), ZoneOffset.UTC);

    @Test
    void invalidBuiltInArtifactsFailBeforeStoreAuditOrDiagnosticMutation() throws Exception {
        BuiltInCertificateProfileTemplate server = builtIn("server-tls");
        BuiltInCertificateProfileTemplate email = builtIn("email-signing");
        byte[] noncanonical = (new String(server.canonicalJson(), StandardCharsets.UTF_8) + "\n")
                .getBytes(StandardCharsets.UTF_8);
        List<BuiltInCertificateProfileTemplate> invalid = List.of(
                new BuiltInCertificateProfileTemplate(server.definition(), server.canonicalJson(),
                        new byte[CertificateProfileRef.HASH_BYTES], SENTINEL),
                new BuiltInCertificateProfileTemplate(email.definition(), server.canonicalJson(),
                        server.canonicalSha256(), SENTINEL),
                new BuiltInCertificateProfileTemplate(server.definition(), noncanonical,
                        MessageDigest.getInstance("SHA-256").digest(noncanonical), SENTINEL));
        AtomicInteger storeCalls = new AtomicInteger();
        InMemoryAuditSink audit = new InMemoryAuditSink();
        DefaultProfileService service = new DefaultProfileService(countingStore(storeCalls), CLOCK, audit);
        CollectingHandler logs = new CollectingHandler();
        Logger root = Logger.getLogger("");
        root.addHandler(logs);
        try {
            for (BuiltInCertificateProfileTemplate template : invalid) {
                PkiException failure = assertThrows(PkiException.class, () -> service.importBuiltIn(template));
                assertEquals("Profile lifecycle operation failed: code=BUILT_IN_PROFILE_INVALID", failure.getMessage());
                assertEquals(null, failure.getCause());
                assertEquals(0, failure.getSuppressed().length);
                assertFalse(failure.getMessage().contains(SENTINEL));
            }
        } finally {
            root.removeHandler(logs);
            logs.close();
        }
        assertEquals(0, storeCalls.get());
        assertTrue(audit.snapshot().isEmpty());
        assertFalse(logs.text().contains(SENTINEL));
    }

    private static PkiStore countingStore(AtomicInteger calls) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "hashCode" -> System.identityHashCode(proxy);
                            case "equals" -> proxy == arguments[0];
                            case "toString" -> "CountingPkiStore";
                            default -> throw new AssertionError("unexpected Object method");
                        };
                    }
                    calls.incrementAndGet();
                    throw new AssertionError("store must not be called");
                });
    }

    private static BuiltInCertificateProfileTemplate builtIn(String profileId) {
        return BuiltInCertificateProfileCatalog.load(BuiltInProfileImportIntegrityTest.class.getClassLoader()).stream()
                .filter(template -> profileId.equals(template.definition().profileId())).findFirst().orElseThrow();
    }

    private static final class CollectingHandler extends Handler {
        private final List<String> messages = new ArrayList<>();

        @Override
        public void publish(LogRecord record) {
            if (record != null) {
                messages.add(String.valueOf(record.getMessage()));
                if (record.getThrown() != null) {
                    messages.add(String.valueOf(record.getThrown().getMessage()));
                }
            }
        }

        @Override
        public void flush() {
            // In-memory only.
        }

        @Override
        public void close() {
            // No external resource.
        }

        private String text() {
            return String.join("\n", messages);
        }
    }
}
