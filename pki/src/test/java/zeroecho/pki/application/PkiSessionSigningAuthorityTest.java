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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.api.PkiId;

/** Tests the exact authority factory used by session composition, without reflective access. */
final class PkiSessionSigningAuthorityTest {
    @Test void declaredSignAlgorithmsKeepSuiteBindingDirectionAndExactExecutorChecks() {
        SigningProvider provider = provider();
        AlgorithmExecutionCapability declaration = declared("both", Set.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE), Direction.SIGN);
        X509AuthoritySnapshot authority = DefaultPkiSession.signingAuthority(
                new PkiBootstrap.SigningComposition(provider, List.of(declaration)), List.of());
        X509ExecutionPlan<SigningProvider> rsa = authority.plan(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY, Direction.SIGN, Optional.empty(), "explicit", SigningProvider.class);
        X509ExecutionPlan<SigningProvider> ed = authority.plan(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY, Direction.SIGN, Optional.empty(), "explicit", SigningProvider.class);
        authority.authorize(rsa, provider, Direction.SIGN);
        authority.authorize(ed, provider, Direction.SIGN);
        assertSame(provider, ed.executor());
        assertEquals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE, ed.selection().suite().signature());
        assertThrows(IllegalArgumentException.class, () -> authority.authorize(ed, provider(), Direction.SIGN));
        assertThrows(IllegalArgumentException.class, () -> authority.authorize(ed, provider, Direction.VERIFY));
        assertThrows(IllegalArgumentException.class, () -> authority.plan(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY, Direction.SIGN, Optional.empty(), "explicit", SigningProvider.class));
        assertThrows(IllegalArgumentException.class, () -> authority.plan(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY, Direction.VERIFY, Optional.empty(), "explicit", SigningProvider.class));
        assertThrows(IllegalArgumentException.class, () -> authority.plan(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY, Direction.SIGN, Optional.empty(), "explicit",
                "zeroecho.signature.rsa-pkcs1-sha256", SigningProvider.class));
        AlgorithmIdentity sha1 = new AlgorithmIdentity(AlgorithmIdentity.Kind.SIGNATURE,
                new AlgorithmIdentity.Family("test", "sha1-signature"), AlgorithmIdentity.NoParameters.INSTANCE);
        assertThrows(IllegalArgumentException.class, () -> authority.plan(sha1, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                Direction.SIGN, Optional.empty(), "explicit", SigningProvider.class));
    }

    @Test void supportedAlgorithmMembershipCannotGrantUndeclaredOrVerifyOnlySigning() {
        for (List<AlgorithmExecutionCapability> declarations : List.of(
                List.of(declared("rsa-only", Set.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256), Direction.SIGN)),
                List.of(declared("verify-only", Set.of(BootstrapAlgorithmIdentities.ED25519_SIGNATURE), Direction.VERIFY)))) {
            X509AuthoritySnapshot authority = DefaultPkiSession.signingAuthority(
                    new PkiBootstrap.SigningComposition(provider(), declarations), List.of());
            assertThrows(IllegalArgumentException.class, () -> authority.plan(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                    BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY, Direction.SIGN, Optional.empty(), "explicit", SigningProvider.class));
        }
    }

    private static SigningProvider provider() {
        return new SigningProvider() {
            @Override public String id() { return "session-authority-test"; }
            @Override public ConfigurationCommitment configurationCommitment() {
                return new ConfigurationCommitment(new byte[ConfigurationCommitment.BYTE_LENGTH]);
            }
            @Override public Set<String> supportedAlgorithms() {
                return Set.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                        BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm());
            }
            @Override public SigningInputCapabilities inputCapabilities() {
                return new SigningInputCapabilities(Long.MAX_VALUE, Map.of());
            }
            @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
                throw new AssertionError("Authority planning must not dispatch");
            }
            @Override public OperationObservation reconcile(PkiId operationId, CallControl control) {
                throw new AssertionError("Authority planning must not reconcile");
            }
            @Override public OperationObservation cancel(PkiId operationId, long fencingToken,
                    CancellationReason reason, CallControl control) {
                throw new AssertionError("Authority planning must not cancel");
            }
            @Override public void close() { }
        };
    }

    private static AlgorithmExecutionCapability declared(String name, Set<AlgorithmIdentity> identities, Direction allowed) {
        return new AlgorithmExecutionCapability() {
            @Override public String implementationId() { return "session-algorithm." + name; }
            @Override public String domainFingerprint() { return "session-algorithm:v1:" + name; }
            @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == allowed && identity.equals(suite.signature()) && identities.contains(identity);
            }
        };
    }
}
