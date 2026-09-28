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
package zeroecho.pki.impl.crypto.remote;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.CallControl;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.crypto.SigningProvider.SignRequest;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;
import zeroecho.pki.testkit.ReferenceRemoteSigner;

/** Provider-level wiring: ServiceLoader discovery, configuration, allocation, and capability declaration. */
public final class RemoteSigningProviderFactoryTest {

    @Test
    public void hasStableProviderIdentity() {
        System.out.println("hasStableProviderIdentity");
        assertEquals("zeroecho-remote", new RemoteSigningProviderFactory().id());
    }

    @Test
    public void requiresEndpointAndDeclaresCapability() {
        System.out.println("requiresEndpointAndDeclaresCapability");
        RemoteSigningProviderFactory provider = new RemoteSigningProviderFactory();
        assertThrows(IllegalArgumentException.class,
                () -> provider.validateConfig(new ProviderConfig("zeroecho-remote", Map.of())));
        assertEquals(RemoteSigningProviderFactory.IMPLEMENTATION_ID,
                provider.capabilities().get(0).implementationId());
    }

    @Test
    public void allocatesFromConfigWithNoneDependenciesAndSigns() throws Exception {
        System.out.println("allocatesFromConfigWithNoneDependenciesAndSigns");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of("rk-1", rsa()), false);
        RemoteSigningProviderFactory provider = new RemoteSigningProviderFactory() {
            @Override
            protected RemoteSigningTransport openTransport(ProviderConfig config) {
                assertEquals("reference://signer", config.require("endpoint"));
                return signer;
            }
        };
        ProviderConfig config = new ProviderConfig("zeroecho-remote", Map.of("endpoint", "reference://signer"));
        try (SigningProvider workflow = provider.allocate(config, SigningProviderRuntimeDependencies.none())) {
            byte[] content = "provider-signed".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            PkiId opId = new PkiId("prov-op-1");
            CallControl control = new CallControl(Instant.now().plusSeconds(60L), CancellationSignal.NONE);
            SignRequest request = SignRequest.create(opId, "store.zeroecho-remote",
                    workflow.configurationCommitment(), 1L,
                    new AccessContext(new Principal("USER", "tester"), new Purpose("TEST"), Optional.empty(),
                            Optional.empty()),
                    new KeyRef("zeroecho-remote:rk-1"),
                    zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                    ContentCommitment.sha256(content),
                    new ImmutableByteContent(content), Optional.of(Encoding.BINARY), Optional.empty());
            workflow.validateSigningDomain("store.zeroecho-remote", java.time.Duration.ofDays(90),
                    java.time.Duration.ZERO);
            assertEquals(ObservationState.SUCCEEDED, workflow.dispatch(request, control).state());
        }
    }

    @Test
    public void malformedEndpointDoesNotExposeParserInputInThrowableGraph() {
        String sentinel = "SENTINEL_REMOTE_ENDPOINT_SECRET";
        ProviderConfig config = new ProviderConfig("zeroecho-remote", Map.of(
                "endpoint", "https://[" + sentinel,
                "tlsKeystore", "unused-client.p12",
                "tlsKeystorePassword", "unused-password",
                "tlsTruststore", "unused-trust.p12",
                "tlsTruststorePassword", "unused-password"));

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> new RemoteSigningProviderFactory().allocate(config));

        assertThrowableGraphDoesNotContain(failure, sentinel);
    }

    private static void assertThrowableGraphDoesNotContain(Throwable failure, String sentinel) {
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        ArrayDeque<Throwable> pending = new ArrayDeque<>();
        pending.add(failure);
        while (!pending.isEmpty()) {
            Throwable current = pending.removeFirst();
            if (!visited.add(current)) {
                continue;
            }
            assertTrue(!current.toString().contains(sentinel));
            for (StackTraceElement frame : current.getStackTrace()) {
                assertTrue(!frame.toString().contains(sentinel));
            }
            if (current.getCause() != null) {
                pending.addLast(current.getCause());
            }
            Collections.addAll(pending, current.getSuppressed());
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
