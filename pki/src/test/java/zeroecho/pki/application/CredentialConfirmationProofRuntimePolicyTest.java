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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.core.storage.KeyringPassword;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.spi.confirmation.KeyPossessionProofChallengeContext;
import zeroecho.pki.spi.confirmation.KeyPossessionProofCredential;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;
import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofProvider;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;
import zeroecho.pki.spi.confirmation.KeyPossessionProofVerification;

final class CredentialConfirmationProofRuntimePolicyTest {
    private static final ConfirmationRealmBinding REALM = new ConfirmationRealmBinding("realm");
    private static final ConfirmationProofSuiteBinding BINDING = new ConfirmationProofSuiteBinding(
            new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1", "a".repeat(64)), 8_192);

    @Test
    void acceptsExactUuidV4UrnVariantsAndInclusiveTtlBoundaries() {
        for (char variant : new char[] { '8', '9', 'a', 'b' }) {
            String audience = "urn:uuid:123e4567-e89b-42d3-" + variant + "456-426614174000";
            CredentialConfirmationProofRuntimePolicy minimum = new CredentialConfirmationProofRuntimePolicy(
                    REALM, new CredentialConfirmationProofAudience(audience),
                    Duration.ofSeconds(10L), BINDING);
            CredentialConfirmationProofRuntimePolicy maximum = new CredentialConfirmationProofRuntimePolicy(
                    REALM, new CredentialConfirmationProofAudience(audience),
                    Duration.ofHours(1L), BINDING);
            assertEquals(audience, minimum.audience().value());
            assertEquals(audience, minimum.audience().toString());
            assertEquals(Duration.ofHours(1L), maximum.challengeTimeToLive());
        }
    }

    @Test
    void rejectsNoncanonicalUuidAudienceAndInvalidPolicyCoordinates() {
        List<String> invalid = List.of(
                "URN:UUID:123e4567-e89b-42d3-a456-426614174000",
                "urn:uuid:123E4567-e89b-42d3-a456-426614174000",
                "urn:uuid:123e4567-e89b-42d3-c456-426614174000",
                "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
                "urn:uuid:00000000-0000-0000-0000-000000000000",
                "urn:uuid:123e4567-e89b-42d3-a456-426614174000?x=1",
                "urn:uuid:123e4567-e89b-42d3-a456-426614174000#x",
                "urn:uuid:123e4567-e89b-42d3-a456-426614174000/suffix",
                "urn:uuid:123e4567-e89b-42d3-a456-42661417400%30",
                "urn:uuid:123e4567-e89b-42d3-a456-42661417400é",
                " urn:uuid:123e4567-e89b-42d3-a456-426614174000");
        for (String audience : invalid) {
            assertThrows(IllegalArgumentException.class,
                    () -> new CredentialConfirmationProofAudience(audience));
        }
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofAudience(null));
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofRuntimePolicy(
                null, validAudience(), Duration.ofSeconds(10L), BINDING));
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofRuntimePolicy(
                REALM, null, Duration.ofSeconds(10L), BINDING));
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofRuntimePolicy(
                REALM, validAudience(), null, BINDING));
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofRuntimePolicy(
                REALM, validAudience(), Duration.ofSeconds(10L), null));
        assertThrows(IllegalArgumentException.class,
                () -> policy(validAudience(), Duration.ofSeconds(9L)));
        assertThrows(IllegalArgumentException.class,
                () -> policy(validAudience(), Duration.ofSeconds(3_601L)));
        assertThrows(IllegalArgumentException.class,
                () -> policy(validAudience(), Duration.ofSeconds(10L).plusNanos(1L)));
    }

    @Test
    void optionalRuntimePolicyIsPreservedAcrossDependencyComposition() {
        CredentialConfirmationProofRuntimePolicy policy =
                policy(validAudience(), Duration.ofSeconds(30L));
        KeyPossessionProofProvider provider = new StubProvider();
        PkiSessionRuntimeDependencies dependencies =
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                        () -> new KeyringPassword(new char[] { 'x' }))
                        .withCredentialConfirmationProofPolicy(policy)
                        .withAuditSink(event -> { })
                        .withKeyPossessionProofProviders(List.of(provider));

        assertSame(policy, dependencies.credentialConfirmationProofPolicy().orElseThrow());
        assertSame(provider, dependencies.keyPossessionProofProviders().getFirst());
        assertTrue(dependencies.auditSink().isPresent());
        assertTrue(dependencies.keyringUnlockProvider().isPresent());
        assertTrue(PkiSessionRuntimeDependencies.none().credentialConfirmationProofPolicy().isEmpty());
    }

    private static CredentialConfirmationProofRuntimePolicy policy(
            CredentialConfirmationProofAudience audience, Duration ttl) {
        return new CredentialConfirmationProofRuntimePolicy(REALM, audience, ttl, BINDING);
    }

    private static CredentialConfirmationProofAudience validAudience() {
        return new CredentialConfirmationProofAudience(
                "urn:uuid:123e4567-e89b-42d3-a456-426614174000");
    }

    private static final class StubProvider implements KeyPossessionProofProvider {
        @Override public String suiteId() { return BINDING.proofSuiteRef().suiteId(); }
        @Override public KeyPossessionProofDescriptor descriptor(int maximumBits) {
            throw new UnsupportedOperationException();
        }
        @Override public void validateCredential(KeyPossessionProofCredential credential) {
            throw new UnsupportedOperationException();
        }
        @Override public KeyPossessionProofPresentation createChallenge(
                KeyPossessionProofChallengeContext context) {
            throw new UnsupportedOperationException();
        }
        @Override public KeyPossessionProofVerification verify(KeyPossessionProofChallengeContext context,
                KeyPossessionProofCredential credential, KeyPossessionProofResponse response) {
            throw new UnsupportedOperationException();
        }
    }
}
