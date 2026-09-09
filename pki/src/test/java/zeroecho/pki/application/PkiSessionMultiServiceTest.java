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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;

/**
 * Composes a session that routes signing among several services and verifies the
 * multi-service composition path: two distinct workflows are opened and bound, the
 * X.509 services are composed, and all services close cleanly. Per-operation
 * routing correctness itself is proven at the bus level.
 */
public final class PkiSessionMultiServiceTest {

    private static final Clock CLOCK = Clock.fixed(java.time.Instant.parse("2026-09-05T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void multiServiceSessionComposesEveryServiceAndClosesCleanly(@TempDir Path tempDir) throws Exception {
        System.out.println("multiServiceSessionComposesEveryServiceAndClosesCleanly");
        List<String> openedServiceBackends = new CopyOnWriteArrayList<>();
        PkiSessionConfiguration configuration = multiServiceConfiguration(tempDir, "svc-b");
        try (PkiSession session = DefaultPkiSession.open(configuration, PkiSessionRuntimeDependencies.none(), CLOCK,
                dispatchingBootstrap(openedServiceBackends))) {
            assertTrue(session.authorities().isPresent());
            assertTrue(session.issuance().isPresent());
            assertEquals(List.of("svc-a", "svc-b"), openedServiceBackends);
        }
    }

    @Test
    void routingToUnknownServiceIsRejectedAtConfiguration(@TempDir Path tempDir) {
        System.out.println("routingToUnknownServiceIsRejectedAtConfiguration");
        assertThrows(IllegalArgumentException.class, () -> multiServiceConfiguration(tempDir, "svc-does-not-exist"));
    }

    @Test
    void serviceIdMustMatchWorkflowIdentity(@TempDir Path tempDir) {
        System.out.println("serviceIdMustMatchWorkflowIdentity");
        // Route to service id "svc-b", but its provider opens a workflow whose id is "svc-a-clone".
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                new ProviderConfig("svc-a", Map.of()), new ProviderConfig("x509-bc", Map.of()), "SHA256withRSA",
                Duration.ofSeconds(5), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_LANE_COUNT,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_QUEUE_CAPACITY,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION,
                List.of(new PkiSessionConfiguration.SigningServiceConfiguration("svc-b",
                        new ProviderConfig("mismatch", Map.of()))),
                Map.of("kref:b", "svc-b"));
        PkiSessionConfiguration configuration = session(tempDir, signing);
        assertThrows(Exception.class, () -> DefaultPkiSession.open(configuration,
                PkiSessionRuntimeDependencies.none(), CLOCK, dispatchingBootstrap(new CopyOnWriteArrayList<>())));
    }

    private static PkiSessionConfiguration multiServiceConfiguration(Path tempDir, String routedServiceId) {
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                new ProviderConfig("svc-a", Map.of()), new ProviderConfig("x509-bc", Map.of()), "SHA256withRSA",
                Duration.ofSeconds(5), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_LANE_COUNT,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_QUEUE_CAPACITY,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION,
                List.of(new PkiSessionConfiguration.SigningServiceConfiguration("svc-b",
                        new ProviderConfig("svc-b", Map.of()))),
                Map.of("kref:b", routedServiceId));
        return session(tempDir, signing);
    }

    private static PkiSessionConfiguration session(Path tempDir, PkiSessionConfiguration.SigningConfiguration signing) {
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", tempDir.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.of(signing), List.of());
    }

    private static DefaultPkiSession.Bootstrap dispatchingBootstrap(List<String> openedServiceBackends) {
        return new DefaultPkiSession.Bootstrap() {
            @Override
            public void validateStore(ProviderConfig configuration) {
                PkiBootstrap.validateStoreConfiguration(configuration);
            }

            @Override
            public void validateAudit(ProviderConfig configuration) {
                PkiBootstrap.validateAuditConfiguration(configuration);
            }

            @Override
            public PkiStore openStore(ProviderConfig configuration) {
                return PkiBootstrap.openStore(configuration);
            }

            @Override
            public AuditSink openAudit(ProviderConfig configuration) {
                return PkiBootstrap.openAudit(configuration);
            }

            @Override
            public void validateSignatureWorkflow(ProviderConfig configuration) {
                // Explicit deterministic test providers.
            }

            @Override
            public void validateCredentialFramework(ProviderConfig configuration) {
                PkiBootstrap.validateCredentialFrameworkConfiguration(configuration);
            }

            @Override
            public SignatureWorkflow openSignatureWorkflow(ProviderConfig configuration,
                    SignatureWorkflowRuntimeDependencies dependencies) {
                openedServiceBackends.add(configuration.backendId());
                String id = "mismatch".equals(configuration.backendId()) ? "svc-a-clone" : configuration.backendId();
                return new InMemorySignatureWorkflow(id, Map.of(), true);
            }
        };
    }
}
