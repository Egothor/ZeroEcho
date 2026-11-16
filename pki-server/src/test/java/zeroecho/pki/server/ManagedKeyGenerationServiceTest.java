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

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.spi.crypto.ManagedKeyGeneration;

/**
 * Checks pinned-administrator admission, idempotent public receipts and ambiguous generation reconciliation.
 */
class ManagedKeyGenerationServiceTest {
    /**
     * Checks immutable administrator pinning, idempotent public generation receipts and rejection of changed parameters or another administrator.
     *
     * @param root isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void retainsPublicReceiptAndRejectsChangedParametersAndOtherAdministrators(@TempDir Path root) throws Exception {
        var config = configuration(root);
        var provider = new Provider();
        Path log = root.resolve("generation.log");
        try (var store = new ServerControlStore(DurableTransactionalMetadataStore.create(log, ServerTestSupport.STORE_ID, java.util.OptionalLong.of(1048576)))) {
            principals(store);
            var service = new ManagedKeyGenerationService(config, store, Optional.of(provider));
            assertFalse(service.available());
            assertThrows(SecurityException.class, () -> service.generate("one", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
            ManagedKeyGenerationService.pinInitialAdministrator(config, store, "administrator");
            assertTrue(service.available());
            assertThrows(SecurityException.class, () -> service.generate("one", ManagedKeyGeneration.Parameters.ECDSA_P384, "approver"));
            var first = service.generate("one", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator");
            assertEquals(first.keyRef(), service.generate("one", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator").keyRef());
            assertThrows(IllegalStateException.class, () -> service.generate("one", ManagedKeyGeneration.Parameters.RSA_4096, "administrator"));
            assertEquals(1, provider.generations);
        }
        try (var store = new ServerControlStore(DurableTransactionalMetadataStore.open(log))) {
            var service = new ManagedKeyGenerationService(config, store, Optional.of(provider));
            service.generate("one", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator");
            assertEquals(1, provider.generations);
            store.replacePrincipal(store.requirePrincipal("administrator"), new SecurityPrincipal("administrator", SecurityPrincipal.Type.USER, "administrator", Optional.empty(), Map.of(), false));
            assertThrows(SecurityException.class, () -> service.generate("one", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
        }
    }

    /**
     * Checks a lost generation result is observed once while an unresolved empty reservation cannot trigger blind regeneration.
     *
     * @param root isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void reconcilesPublishedKeyAfterLostResultButNeverRegeneratesAnEmptyClaim(@TempDir Path root) throws Exception {
        var config = configuration(root);
        var provider = new Provider(); provider.failAfterPublication = true;
        try (var store = new ServerControlStore(DurableTransactionalMetadataStore.create(root.resolve("generation.log"), ServerTestSupport.STORE_ID, java.util.OptionalLong.of(1048576)))) {
            principals(store); ManagedKeyGenerationService.pinInitialAdministrator(config, store, "administrator");
            var service = new ManagedKeyGenerationService(config, store, Optional.of(provider));
            assertThrows(IllegalStateException.class, () -> service.generate("lost", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
            assertNotNull(new ManagedKeyGenerationService(config, store, Optional.of(provider))
                    .generate("lost", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
            assertEquals(1, provider.generations);
            provider.failBeforePublication = true;
            assertThrows(IllegalStateException.class, () -> service.generate("empty", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
            assertThrows(IllegalStateException.class, () -> service.generate("empty", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
            assertEquals(2, provider.generations);
        }
    }

    /**
     * Checks administrator designation cannot change and a busy generation lane rejects concurrent key creation.
     *
     * @param root isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void rejectsAChangedDesignationAndConcurrentGeneration(@TempDir Path root) throws Exception {
        var config = configuration(root); var provider = new Provider();
        provider.entered = new java.util.concurrent.CountDownLatch(1);
        provider.release = new java.util.concurrent.CountDownLatch(1);
        try (var store = new ServerControlStore(DurableTransactionalMetadataStore.create(root.resolve("generation.log"), ServerTestSupport.STORE_ID, java.util.OptionalLong.of(1048576)))) {
            principals(store); ManagedKeyGenerationService.pinInitialAdministrator(config, store, "administrator");
            assertThrows(SecurityException.class, () -> ManagedKeyGenerationService.pinInitialAdministrator(config, store, "approver"));
            var changed = new ServerRealmConfiguration(config.realmId(), config.displayName(), config.confirmationProofPolicy(),
                    config.pkiSessionConfiguration(), config.authorityExposure(), config.authorizationCommitment(),
                    config.approvalCommitment(), config.extendedApprovalCommitment(), config.disclosureCommitment(), config.disclosureDefaults(),
                    config.controlLogPath(), config.controlStoreId(), config.approvalPolicies(), Optional.of("approver"));
            assertThrows(SecurityException.class, () -> ManagedKeyGenerationService.pinInitialAdministrator(changed, store, "approver"));
            assertFalse(new ManagedKeyGenerationService(changed, store, Optional.of(provider)).available());
            var service = new ManagedKeyGenerationService(config, store, Optional.of(provider));
            try (var executor = java.util.concurrent.Executors.newSingleThreadExecutor()) {
                var running = executor.submit(() -> service.generate("one", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
                try {
                    assertTrue(provider.entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
                    assertThrows(IllegalStateException.class, () -> service.generate("two", ManagedKeyGeneration.Parameters.ECDSA_P384, "administrator"));
                } finally { provider.release.countDown(); }
                assertNotNull(running.get(5, java.util.concurrent.TimeUnit.SECONDS));
                assertEquals(1, provider.generations);
            }
        }
    }

    private static ServerRealmConfiguration configuration(Path root) throws Exception {
        var source = PkiAdminBootstrapTest.configuration(root).realm();
        return new ServerRealmConfiguration(source.realmId(), source.displayName(), source.confirmationProofPolicy(),
                source.pkiSessionConfiguration(), source.authorityExposure(), source.authorizationCommitment(),
                source.approvalCommitment(), source.extendedApprovalCommitment(), source.disclosureCommitment(),
                source.disclosureDefaults(), source.controlLogPath(), source.controlStoreId(), source.approvalPolicies(), Optional.of("administrator"));
    }

    private static void principals(ServerControlStore store) {
        for (String principal : java.util.List.of("administrator", "approver")) {
            store.createPrincipal(new SecurityPrincipal(principal, SecurityPrincipal.Type.USER, principal, Optional.empty(), Map.of(), true));
        }
    }

    private static final class Provider implements ManagedKeyGeneration {
        private final Map<String, Result> results = new HashMap<>();
        private int generations;
        private boolean failBeforePublication;
        private boolean failAfterPublication;
        private java.util.concurrent.CountDownLatch entered;
        private java.util.concurrent.CountDownLatch release;
        /**
         * {@inheritDoc}
         */
        @Override public Result generate(String id, Parameters parameters) {
            generations++;
            if (entered != null) {
                entered.countDown();
                try {
                    if (!release.await(5, java.util.concurrent.TimeUnit.SECONDS)) throw new IllegalStateException("test lane timed out");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt(); throw new IllegalStateException("test lane interrupted");
                }
            }
            if (failBeforePublication) throw new IllegalStateException("simulated interruption");
            var result = new Result(new KeyRef("test:" + id), parameters, new EncodedObject(Encoding.DER, new byte[] {1}));
            results.put(id, result);
            if (failAfterPublication) { failAfterPublication = false; throw new IllegalStateException("simulated lost receipt"); }
            return result;
        }
        /**
         * {@inheritDoc}
         */
        @Override public Optional<Result> observe(String id, Parameters parameters) { return Optional.ofNullable(results.get(id)); }
    }
}
