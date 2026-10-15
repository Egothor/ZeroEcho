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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;

/** Durable enrollment policy and complete approval-binding regression coverage. */
class EnrollmentProfileServiceTest {
    @TempDir Path directory;

    @Test
    void persistsCreateUpdateAndStateAcrossRestart() throws Exception {
        Path log;
        EnrollmentProfile expected = profile("Updated", EnrollmentProfileState.SUSPENDED,
                "certificate", Set.of("authority"), Optional.of("CN=.*"), List.of("example.test"), true);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            log = opened.log();
            EnrollmentProfileService service = new EnrollmentProfileService(opened.store());
            assertTrue(service.find("profile").isEmpty());
            service.register(baseline());
            assertThrows(IllegalStateException.class, () -> service.register(baseline()));
            assertThrows(IllegalArgumentException.class, () -> service.setState("missing", EnrollmentProfileState.ACTIVE));
            service.update(profile("Updated", EnrollmentProfileState.ACTIVE,
                    "certificate", Set.of("authority"), Optional.of("CN=.*"), List.of("example.test"), true));
            assertEquals(expected, service.setState("profile", EnrollmentProfileState.SUSPENDED));
            assertEquals(List.of(expected), service.list(0, 1).values());
            assertTrue(service.list(1, 1).values().isEmpty());
            opened.store().validateAll();
        }
        try (ServerControlStore reopened = new ServerControlStore(DurableTransactionalMetadataStore.open(
                log, OptionalLong.of(1_048_576)))) {
            EnrollmentProfileService service = new EnrollmentProfileService(reopened);
            assertEquals(expected, service.find("profile").orElseThrow());
            assertEquals(List.of(expected), service.list());
        }
    }

    @Test
    void staleCommitmentCannotOverwriteAnInterveningUpdateEvenAfterPolicyReturns() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            EnrollmentProfileService first = new EnrollmentProfileService(opened.store());
            EnrollmentProfileService second = new EnrollmentProfileService(opened.store());
            first.register(baseline());
            ServerControlStore.ProtocolRecord original = stored(opened.store());
            second.setState("profile", EnrollmentProfileState.SUSPENDED);
            second.setState("profile", EnrollmentProfileState.ACTIVE);
            assertEquals(baseline(), first.find("profile").orElseThrow());
            assertNotEquals(original.commitment(), stored(opened.store()).commitment());
            assertThrows(IllegalStateException.class, () -> opened.store().mutateProtocol(List.of(
                    new ServerControlStore.ProtocolMutation(original, Optional.of(original.commitment())))));
            assertEquals(baseline(), second.find("profile").orElseThrow());
        }
    }

    @Test
    void rejectsUnsupportedVersionCorruptionIdentityMismatchAndNoncanonicalPayloadAtStartup() throws Exception {
        for (int variant = 0; variant < 8; variant++) {
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(
                    java.nio.file.Files.createDirectory(directory.resolve("case-" + variant)))) {
                new EnrollmentProfileService(opened.store()).register(baseline());
                ServerControlStore.ProtocolRecord original = stored(opened.store());
                byte[] payload = original.payload();
                String id = original.recordId();
                switch (variant) {
                    case 0 -> ByteBuffer.wrap(payload).putInt(0);
                    case 1 -> ByteBuffer.wrap(payload).putInt(2);
                    case 2 -> payload = Arrays.copyOf(payload, payload.length - 1);
                    case 3 -> payload = Arrays.copyOf(payload, payload.length + 1);
                    case 4 -> ByteBuffer.wrap(payload).putLong(4, 0);
                    case 5 -> id = "different";
                    case 6 -> payload[payload.length - 1] = 2; // Noncanonical true.
                    case 7 -> {
                        byte[] name = "certificate".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        int position = -1;
                        for (int index = 0; index <= payload.length - name.length; index++) {
                            if (Arrays.equals(Arrays.copyOfRange(payload, index, index + name.length), name)) {
                                position = index;
                                break;
                            }
                        }
                        assertTrue(position >= 0);
                        Arrays.fill(payload, position, position + name.length, (byte) ' ');
                    }
                    default -> throw new AssertionError();
                }
                String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
                ServerControlStore.ProtocolRecord corrupt = new ServerControlStore.ProtocolRecord(
                        ServerControlStore.ENROLLMENT_PROFILE, id, digest, payload);
                opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(corrupt,
                        variant == 5 ? Optional.empty() : Optional.of(original.commitment()))));
                assertThrows(IllegalStateException.class, () -> new EnrollmentProfileService(opened.store()),
                        "variant " + variant);
            }
        }
    }

    @Test
    void rejectsIncorrectCommitmentAndOversizedOrInvalidUnicodeBeforePersistence() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            EnrollmentProfileService service = new EnrollmentProfileService(opened.store());
            assertThrows(IllegalArgumentException.class, () -> service.register(profile("x".repeat(16_385),
                    EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.empty(), List.of(), false)));
            assertThrows(IllegalArgumentException.class, () -> service.register(profile("\uD800",
                    EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.empty(), List.of(), false)));
            assertTrue(service.list().isEmpty());
            service.register(baseline());
            ServerControlStore.ProtocolRecord original = stored(opened.store());
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                    new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_PROFILE, "profile",
                            "0".repeat(64), original.payload()), Optional.of(original.commitment()))));
            assertThrows(IllegalStateException.class, () -> service.find("profile"));
            assertThrows(IllegalStateException.class, () -> new EnrollmentProfileService(opened.store()));
        }
    }

    @Test
    void approvalCannotBeReusedAfterSubstitutingAnyProfileField() throws Exception {
        List<EnrollmentProfile> substitutions = List.of(
                profile("Other", EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.empty(), List.of(), false),
                baseline().withState(EnrollmentProfileState.SUSPENDED),
                profile("Profile", EnrollmentProfileState.ACTIVE, "other", Set.of(), Optional.empty(), List.of(), false),
                profile("Profile", EnrollmentProfileState.ACTIVE, "certificate", Set.of("authority"), Optional.empty(), List.of(), false),
                profile("Profile", EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.of("CN=.*"), List.of(), false),
                profile("Profile", EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.empty(), List.of("example.test"), false),
                profile("Profile", EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.empty(), List.of(), true),
                new EnrollmentProfile("other", "Profile", EnrollmentProfileState.ACTIVE, "certificate",
                        Set.of(), Optional.empty(), List.of(), false));
        OperationSecurityDescriptors descriptors = new OperationSecurityDescriptors();
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("requester"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            for (boolean update : List.of(false, true)) {
                ServerControlOperation original = update ? new ServerControlOperation.UpdateEnrollmentProfile(baseline())
                        : new ServerControlOperation.RegisterEnrollmentProfile(baseline());
                String commitment = descriptors.commitment(ServerTestSupport.REALM,
                        new AdministrativeOperation.Control(original), ServerTestSupport.authorityResource());
                String approvalId = update ? "update" : "create";
                approvals.request(approvalId, original.name(), commitment, ServerTestSupport.scope(), "requester",
                        new ApprovalService.Policy("policy", 1, Set.of("approver"), Set.of(), true, Duration.ofHours(1), true));
                approvals.decide(approvalId, "approver", ApprovalService.Choice.APPROVE, "reviewed");
                for (EnrollmentProfile replacement : substitutions) {
                    ServerControlOperation changed = update ? new ServerControlOperation.UpdateEnrollmentProfile(replacement)
                            : new ServerControlOperation.RegisterEnrollmentProfile(replacement);
                    String changedCommitment = descriptors.commitment(ServerTestSupport.REALM,
                            new AdministrativeOperation.Control(changed), ServerTestSupport.authorityResource());
                    assertNotEquals(commitment, changedCommitment);
                    assertThrows(IllegalStateException.class, () -> approvals.claim(approvalId, changed.name(),
                            changedCommitment, ServerTestSupport.scope()));
                }
            }
        }
    }

    private static ServerControlStore.ProtocolRecord stored(ServerControlStore store) {
        return store.protocolRecord(ServerControlStore.ENROLLMENT_PROFILE, "profile").orElseThrow();
    }

    private static EnrollmentProfile baseline() {
        return profile("Profile", EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.empty(), List.of(), false);
    }

    private static EnrollmentProfile profile(String displayName, EnrollmentProfileState state,
            String certificateProfile, Set<String> authorities, Optional<String> pattern, List<String> domains,
            boolean approval) {
        return new EnrollmentProfile("profile", displayName, state, certificateProfile, authorities, pattern, domains, approval);
    }
}
