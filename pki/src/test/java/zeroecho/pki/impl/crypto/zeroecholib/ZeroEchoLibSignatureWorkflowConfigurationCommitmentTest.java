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
package zeroecho.pki.impl.crypto.zeroecholib;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;

final class ZeroEchoLibSignatureWorkflowConfigurationCommitmentTest {
    private static final String PROVIDER_ID = "zeroecho-lib";

    @TempDir
    Path temporaryDirectory;

    @Test
    void allocatedCommitmentUsesResolvedDefaultsAndChangesWithEffectiveConfiguration() throws Exception {
        Path first = temporaryDirectory.resolve("first.zek");
        Path second = temporaryDirectory.resolve("second.zek");
        createEmptyKeyring(first);
        createEmptyKeyring(second);

        SignatureWorkflow.ConfigurationCommitment baseline = commitment(first, Map.of());
        SignatureWorkflow.ConfigurationCommitment explicitDefaults = commitment(first, Map.of(
                "operationHorizon", "P90D", "keyRefPrefix", "zeroecho-lib:",
                "requireComponentSuffix", "true"));
        assertTrue(baseline.matches(explicitDefaults));

        assertFalse(baseline.matches(commitment(first, Map.of("operationHorizon", "P91D"))));
        assertFalse(baseline.matches(commitment(first, Map.of("keyRefPrefix", "alternate:"))));
        assertFalse(baseline.matches(commitment(first, Map.of("requireComponentSuffix", "false"))));
        assertFalse(baseline.matches(commitment(second, Map.of())));
    }

    @Test
    void commitmentChangesOnActualKeyReplacementAndIsStableAfterReopen() throws Exception {
        Path keyring = temporaryDirectory.resolve("replacement.zek");
        KeyPair first = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore store = KeyringStore.create(keyring, password)) {
            store.putPrivate("sign.prv", "RSA", first.getPrivate());
        }
        SignatureWorkflow.ConfigurationCommitment baseline = commitment(keyring, Map.of());

        KeyPair replacement = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore store = KeyringStore.open(keyring, password)) {
            store.putPrivate("sign.prv", "RSA", replacement.getPrivate());
        }
        SignatureWorkflow.ConfigurationCommitment replaced = commitment(keyring, Map.of());
        SignatureWorkflow.ConfigurationCommitment reopened = commitment(keyring, Map.of());

        assertFalse(baseline.matches(replaced));
        assertTrue(replaced.matches(reopened));
    }

    private static SignatureWorkflow.ConfigurationCommitment commitment(Path keyring, Map<String, String> overrides) {
        java.util.HashMap<String, String> properties = new java.util.HashMap<>(overrides);
        properties.put("keyringPath", keyring.toString());
        ZeroEchoLibSignatureWorkflowProvider provider =
                new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider());
        try (SignatureWorkflow workflow = provider.allocate(new ProviderConfig(PROVIDER_ID, properties),
                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(),
                        new TestLocalParticipant()))) {
            SignatureWorkflow.ConfigurationCommitment commitment = workflow.configurationCommitment();
            assertSame(commitment, workflow.configurationCommitment());
            return commitment;
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static void createEmptyKeyring(Path path) throws Exception {
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore ignored = KeyringStore.create(path, password)) {
            // Empty keyrings still have distinct master keys and store UUIDs.
        }
    }

    private static final class TestLocalParticipant implements LocalSigningLedgerParticipant {
        @Override public Instant signingNow() { return Instant.EPOCH; }
        @Override public String localSigningNamespace(String providerId) {
            return "0123456789abcdef0123456789abcdef." + providerId;
        }
        @Override public Duration signingHorizon() { return Duration.ofDays(90); }
        @Override public Acceptance acceptLocalSign(SignatureWorkflow.SignRequest request) { return Acceptance.EXECUTE; }
        @Override public boolean completeLocalSign(SignatureWorkflow.SignRequest request,
                SignatureWorkflow.OperationStatus terminal) { return true; }
        @Override public CancellationSignal localCancellation(PkiId operationId) {
            return CancellationSignal.NONE;
        }
        @Override public SignatureWorkflow.OperationStatus localSignStatus(PkiId operationId) {
            return new SignatureWorkflow.OperationStatus(SignatureWorkflow.State.FAILED, Instant.EPOCH,
                    Optional.of("UNKNOWN_OPERATION"), Optional.empty());
        }
        @Override public boolean cancelLocalSign(PkiId operationId, long fencingToken) { return false; }
    }
}
