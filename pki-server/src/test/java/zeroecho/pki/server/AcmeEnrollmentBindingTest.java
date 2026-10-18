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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.server.acme.AcmeControlStore;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;

/** Mandatory ACME policy bindings survive restart and concurrent administration. */
class AcmeEnrollmentBindingTest {
    private static final Instant NOW = Instant.parse("2026-10-11T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    @TempDir Path directory;

    @Test
    void requiresActiveCompatibleBindingAndPreservesSuspendedBindingAcrossRestart() throws Exception {
        Path log;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            log = opened.log();
            EnrollmentProfileService profiles = new EnrollmentProfileService(opened.store());
            AcmeControlStore acme = new AcmeControlStore(opened.store());
            assertThrows(IllegalStateException.class, () -> acme.create(directory("policy", AcmeState.DirectoryStatus.ACTIVE)));
            profiles.register(profile("policy", "other"));
            assertThrows(IllegalStateException.class, () -> acme.create(directory("policy", AcmeState.DirectoryStatus.ACTIVE)));
            profiles.update(profile("policy", "leaf"));
            profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
            assertThrows(IllegalStateException.class, () -> acme.create(directory("policy", AcmeState.DirectoryStatus.ACTIVE)));
            profiles.setState("policy", EnrollmentProfileState.ACTIVE);
            AcmeState.Directory committed = acme.create(directory("policy", AcmeState.DirectoryStatus.ACTIVE));
            assertEquals("policy", acme.get(AcmeState.Directory.class, committed.directoryId()).orElseThrow().enrollmentProfileId());
            assertThrows(IllegalStateException.class, () -> profiles.update(profile("policy", "other")));
            profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
            acme.validateAndRecover(CLOCK);
        }
        try (ServerControlStore control = new ServerControlStore(DurableTransactionalMetadataStore.open(log, OptionalLong.of(1_048_576)))) {
            AcmeControlStore acme = new AcmeControlStore(control);
            acme.validateAndRecover(CLOCK);
            EnrollmentProfileService profiles = new EnrollmentProfileService(control);
            assertEquals(EnrollmentProfileState.SUSPENDED, profiles.find("policy").orElseThrow().state());
            AcmeState.Directory prior = acme.get(AcmeState.Directory.class, "directory:test").orElseThrow();
            acme.replace(List.of(new AcmeControlStore.Replacement(prior, directory("policy", AcmeState.DirectoryStatus.INACTIVE))));
            profiles.update(profile("policy", "other"));
            AcmeState.Directory inactive = acme.get(AcmeState.Directory.class, "directory:test").orElseThrow();
            assertThrows(IllegalStateException.class, () -> acme.replace(List.of(new AcmeControlStore.Replacement(inactive,
                    directory("policy", AcmeState.DirectoryStatus.ACTIVE)))));
        }
    }

    @Test
    void concurrentRegistrationAndIncompatiblePolicyUpdateCannotBothCommit() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                java.util.concurrent.ExecutorService executor = Executors.newFixedThreadPool(2)) {
            EnrollmentProfileService profiles = new EnrollmentProfileService(opened.store());
            profiles.register(profile("policy", "leaf"));
            AcmeControlStore acme = new AcmeControlStore(opened.store());
            CountDownLatch start = new CountDownLatch(1);
            Future<Boolean> registered = executor.submit(() -> {
                start.await();
                try { acme.create(directory("policy", AcmeState.DirectoryStatus.ACTIVE)); return true; }
                catch (IllegalArgumentException | IllegalStateException expected) { return false; }
            });
            Future<Boolean> changed = executor.submit(() -> {
                start.await();
                try { profiles.update(profile("policy", "other")); return true; }
                catch (IllegalStateException expected) { return false; }
            });
            start.countDown();
            assertNotEquals(registered.get(10, TimeUnit.SECONDS), changed.get(10, TimeUnit.SECONDS));
            acme.validateAndRecover(CLOCK);
        }
    }

    private static EnrollmentProfile profile(String id, String certificate) {
        return new EnrollmentProfile(id, "ACME policy", EnrollmentProfileState.ACTIVE, certificate,
                Set.of("ca:test"), Optional.empty(), List.of(), false);
    }

    private static AcmeState.Directory directory(String policy, AcmeState.DirectoryStatus state) {
        CredentialConfirmationPolicy confirmation = new CredentialConfirmationPolicy(ConfirmationDisclosurePolicy.OWNER_ONLY,
                Duration.ofHours(24), new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1", "7".repeat(64)));
        return new AcmeState.Directory("directory:test", "test", 1, ServerTestSupport.REALM, new PkiId("ca:test"),
                new CertificateProfileRef("leaf", 1, new byte[32]), policy, new PkiId("issuer:test"),
                new PkiId("path:test"), "1".repeat(64), Set.of(AcmeState.IdentifierType.DNS),
                Set.of("example.test"), Duration.ofDays(30), Set.of("RSA"), Set.of("STANDARD_ONLY"),
                Set.of(AcmeState.ChallengeType.HTTP_01), Set.of("http"), Optional.empty(), false,
                confirmation, confirmation.configurationCommitment(), state, "2".repeat(64), NOW, "0".repeat(64));
    }
}
