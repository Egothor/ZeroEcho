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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.spi.ProviderConfig;

final class LocalPkiConfigurationTest {
    private static final ProviderConfig SIGNER = new ProviderConfig("zeroecho-lib", Map.of());

    @Test
    void validatesFiniteLocalBoundsAndMatchesOneSignerBufferBudget(@TempDir Path root) {
        assertThrows(IllegalArgumentException.class, () -> signing(new ProviderConfig("remote", Map.of()),
                Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.empty()));
        assertFalse(Files.exists(root.resolve("store")), "Invalid signer requires no store allocation");
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofSeconds(-1), Duration.ofDays(1).plusNanos(1))) {
            assertThrows(IllegalArgumentException.class, () -> signing(SIGNER, invalid, Duration.ofSeconds(5), OptionalLong.empty()));
            assertThrows(IllegalArgumentException.class, () -> signing(SIGNER, Duration.ofSeconds(10), invalid, OptionalLong.empty()));
        }
        assertThrows(IllegalArgumentException.class, () -> signing(SIGNER, Duration.ofSeconds(5), Duration.ofSeconds(5), OptionalLong.empty()));
        for (long invalid : new long[] { -1, 0, Integer.MAX_VALUE - 7L }) {
            assertThrows(IllegalArgumentException.class, () -> signing(SIGNER, Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.of(invalid)));
        }
        LocalSigningConfiguration automatic = signing(SIGNER, Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.empty());
        assertEquals((1_000_000L / 2 - 16_384) / 3, automatic.resolvePureEdDsaMaximumTbsBytes(1_000_000));
        assertThrows(IllegalArgumentException.class, () -> automatic.resolvePureEdDsaMaximumTbsBytes(1));
        assertEquals(1234, signing(SIGNER, Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.of(1234))
                .resolvePureEdDsaMaximumTbsBytes(0));
        assertThrows(IllegalArgumentException.class, () -> new LocalSigningConfiguration(SIGNER, " ", Duration.ofSeconds(1),
                Optional.empty(), Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.empty()));
        assertThrows(IllegalArgumentException.class, () -> new LocalSigningConfiguration(SIGNER, "Ed25519", Duration.ZERO,
                Optional.empty(), Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.empty()));
        assertThrows(IllegalArgumentException.class, () -> new LocalSigningConfiguration(SIGNER, "Ed25519", Duration.ofSeconds(1),
                Optional.of("bad-name"), Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.empty()));
        for (String invalid : List.of("", " ", "x".repeat(257))) {
            assertThrows(IllegalArgumentException.class, () -> configuration(root, invalid));
        }
    }

    @Test
    void unsignedSessionReportsLocalSchemaAndAuditsDeclaredOperatorWithoutKeyAccess(@TempDir Path root) throws Exception {
        List<AuditEvent> events = new ArrayList<>();
        PkiSession session = PkiSession.openLocal(configuration(root, "declared-operator"),
                PkiSessionRuntimeDependencies.none().withAuditSink(events::add));
        PkiOperationExecutor operations = session.operations();
        assertTrue(session.localSigning().isEmpty());
        assertTrue(session.signing().isEmpty());
        assertTrue(session.signingCommands().isEmpty());
        assertTrue(session.semanticSigning().isEmpty());
        assertTrue(session.ocsp().isEmpty());
        PkiOperationResult result = assertInstanceOf(PkiOperationOutcome.Completed.class,
                operations.execute(new PkiOperation.ValidateConfiguration(), CancellationSignal.NONE)).result();
        assertEquals(new PkiOperationValue.IntegerValue(1), result.fields().get("version"));
        assertEquals(2, events.size());
        assertTrue(events.stream().allMatch(event -> event.principal().type().equals("LOCAL_OPERATOR")
                && event.principal().name().equals("declared-operator")));
        session.close();
        assertThrows(IllegalStateException.class, session::localSigning);
        assertThrows(IllegalStateException.class, () -> operations.execute(new PkiOperation.ValidateConfiguration(), CancellationSignal.NONE));
        try (PkiSession reopened = PkiSession.openLocal(configuration(root, "other"), PkiSessionRuntimeDependencies.none()
                .withAuditSink(event -> { throw new IllegalStateException("Best-effort sink unavailable"); }))) {
            assertInstanceOf(PkiOperationOutcome.Completed.class,
                    reopened.operations().execute(new PkiOperation.ValidateConfiguration(), CancellationSignal.NONE));
        }
    }

    private static LocalSigningConfiguration signing(ProviderConfig provider, Duration lease, Duration call, OptionalLong bound) {
        return new LocalSigningConfiguration(provider, "Ed25519", Duration.ofMinutes(1), Optional.empty(), lease, call, bound);
    }

    private static LocalPkiSessionConfiguration configuration(Path root, String operator) {
        return new LocalPkiSessionConfiguration(new ProviderConfig("fs", Map.of("root", root.resolve("store").toString())),
                new ProviderConfig("memory", Map.of()), operator, Optional.empty(), List.of(), List.of());
    }
}
