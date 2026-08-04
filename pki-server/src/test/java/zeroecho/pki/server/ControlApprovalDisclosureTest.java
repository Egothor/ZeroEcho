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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.impl.fs.PosixTransactionalMetadataStore;

/** Durable control, approval, break-glass, audit-view and disclosure tests. */
class ControlApprovalDisclosureTest {
    @TempDir Path temporaryDirectory;

    @Test
    void persistsPrincipalsAssignmentsAndGrantsAcrossRestart() throws Exception {
        System.out.println("persistsPrincipalsAssignmentsAndGrantsAcrossRestart");
        Path log;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            log = opened.log();
            opened.store().createPrincipal(ServerTestSupport.principal("officer"));
            opened.store().createAssignment(new RoleTemplateCatalog.Assignment("assignment-a", "officer",
                    "ca-security-officer", 1, ServerTestSupport.scope(), true));
            opened.store().createGrant(ServerTestSupport.grant("grant-a", "officer", Permission.Effect.ALLOW,
                    Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY, ServerTestSupport.scope(),
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            opened.store().validateAll();
        }
        try (ServerControlStore reopened = new ServerControlStore(PosixTransactionalMetadataStore.open(log,
                OptionalLong.of(1_048_576)))) {
            reopened.validateAll();
            assertEquals("officer", reopened.requirePrincipal("officer").principalId());
            assertEquals(1, reopened.assignmentsFor("officer").size());
            assertEquals(1, reopened.grantsFor("officer").size());
            System.out.println("...recovered-records=3");
        }
        System.out.println("...ok");
    }

    @Test
    void enforcesTwoPartyApprovalCommitmentAndExactOnceExecution() throws Exception {
        System.out.println("enforcesTwoPartyApprovalCommitmentAndExactOnceExecution");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("requester"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver-a"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver-b"));
            ApprovalService service = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            ApprovalService.Policy policy = new ApprovalService.Policy("high-risk", 2,
                    Set.of("approver-a", "approver-b"), Set.of(), true, Duration.ofHours(2), true);
            ApprovalService.Request request = service.request("approval-a", "ca.create",
                    ServerTestSupport.DIGEST, ServerTestSupport.scope(), "requester", policy);
            assertThrows(IllegalStateException.class, () -> service.decide(request.approvalId(),
                    "requester", ApprovalService.Choice.APPROVE, "self"));
            service.decide(request.approvalId(), "approver-a",
                    ApprovalService.Choice.APPROVE, "reviewed-a");
            ApprovalService.Request approved = service.decide(request.approvalId(),
                    "approver-b", ApprovalService.Choice.APPROVE, "reviewed-b");
            assertEquals(ApprovalService.State.APPROVED, approved.state());
            assertThrows(IllegalStateException.class, () -> service.claim(request.approvalId(), "ca.create",
                    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                    ServerTestSupport.scope()));
            service.claim(request.approvalId(), "ca.create", ServerTestSupport.DIGEST, ServerTestSupport.scope());
            ApprovalService.Request executed = service.complete(request.approvalId(), "SUCCEEDED");
            assertEquals(ApprovalService.State.EXECUTED, executed.state());
            assertThrows(IllegalStateException.class, () -> service.claim(request.approvalId(), "ca.create",
                    ServerTestSupport.DIGEST, ServerTestSupport.scope()));
            ApprovalService.Request rejected = service.request("approval-rejected", "ca.create",
                    ServerTestSupport.DIGEST, ServerTestSupport.scope(), "requester", policy);
            assertEquals(ApprovalService.State.REJECTED, service.decide(rejected.approvalId(), "approver-a",
                    ApprovalService.Choice.REJECT, "policy mismatch").state());
            ApprovalService.Request cancelled = service.request("approval-cancelled", "ca.create",
                    ServerTestSupport.DIGEST, ServerTestSupport.scope(), "requester", policy);
            assertEquals(ApprovalService.State.CANCELLED,
                    service.cancel(cancelled.approvalId(), "requester").state());
            ApprovalService.Request expiring = service.request("approval-expired", "ca.create",
                    ServerTestSupport.DIGEST, ServerTestSupport.scope(), "requester", policy);
            Clock afterExpiry = Clock.fixed(expiring.expiresAt(), ZoneOffset.UTC);
            ApprovalService recovered = new ApprovalService(opened.store(), afterExpiry, opened.audit());
            assertEquals(ApprovalService.State.EXPIRED, recovered.requireCurrent(expiring.approvalId()).state());
            System.out.println("...approvals=" + approved.decisions().size() + ", state=" + executed.state());
        }
        System.out.println("...ok");
    }

    @Test
    void breakGlassIsScopedAuditedAndExpires() throws Exception {
        System.out.println("breakGlassIsScopedAuditedAndExpires");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("officer"));
            opened.store().createPrincipal(ServerTestSupport.principal("security-admin"));
            Permission.Grant emergency = ServerTestSupport.grant("emergency-grant", "officer",
                    Permission.Effect.ALLOW, Permission.Action.CERTIFICATE_REVOKE,
                    Permission.ResourceType.REVOCATION, ServerTestSupport.scope(), Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED);
            BreakGlassService service = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            BreakGlassService.Record active = service.activate("break-a", "officer", emergency,
                    "incident-response", "security-admin", Optional.empty(),
                    ServerTestSupport.CLOCK.instant().plus(Duration.ofHours(1)));
            assertEquals(BreakGlassService.State.ACTIVE, active.state());
            assertEquals(1, service.activeFor("officer").grants().size());
            assertThrows(IllegalArgumentException.class, () -> service.activate("break-b", "officer", emergency,
                    "incident", "officer", Optional.empty(), ServerTestSupport.CLOCK.instant().plusSeconds(60)));
            assertTrue(opened.audit().events().stream().anyMatch(event -> event.action().contains("ACTIVATE")));
            BreakGlassService expired = new BreakGlassService(opened.store(),
                    Clock.fixed(active.expiresAt(), ZoneOffset.UTC), opened.audit());
            assertTrue(expired.activeFor("officer").grants().isEmpty());
            System.out.println("...scope-authority=" + active.grant().scope().authorityId().orElseThrow());
        }
        System.out.println("...ok");
    }

    @Test
    void disclosureSeparatesIdentityOwnershipPublicationAndCapability() throws Exception {
        System.out.println("disclosureSeparatesIdentityOwnershipPublicationAndCapability");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("owner-a"));
            SecureRandom deterministic = SecureRandom.getInstance("SHA1PRNG");
            deterministic.setSeed(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            DisclosureService service = new DisclosureService(ServerTestSupport.REALM, opened.store(),
                    DisclosureService.Defaults.recommended(), ServerTestSupport.CLOCK, deterministic, opened.audit());
            assertEquals(DisclosureService.Policy.PUBLIC,
                    service.defaultPolicy(DisclosureService.ObjectType.CA_CERTIFICATE, true, false));
            assertEquals(DisclosureService.Policy.PUBLIC,
                    service.defaultPolicy(DisclosureService.ObjectType.CA_CHAIN, false, false));
            assertEquals(DisclosureService.Policy.PUBLIC,
                    service.defaultPolicy(DisclosureService.ObjectType.CRL, false, false));
            assertEquals(DisclosureService.Policy.OWNER_ONLY,
                    service.defaultPolicy(DisclosureService.ObjectType.LEAF_CERTIFICATE, false, false));
            assertEquals(DisclosureService.Policy.RESTRICTED,
                    service.defaultPolicy(DisclosureService.ObjectType.LEAF_CERTIFICATE, false, true));
            PkiId leaf = new PkiId("leaf-a");
            service.register(leaf, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                    DisclosureService.Policy.OWNER_ONLY, Optional.of("owner-a"), ServerTestSupport.DIGEST,
                    "officer");
            assertEquals(DisclosureService.Decision.DENIED,
                    service.decide(leaf, Optional.empty(), false, false, Optional.empty()));
            assertEquals(DisclosureService.Decision.ALLOWED,
                    service.decide(leaf, Optional.of(ServerTestSupport.principal("owner-a")), true, false,
                            Optional.empty()));
            assertThrows(IllegalStateException.class, () -> service.change(leaf, DisclosureService.Policy.PUBLIC,
                    true, false, "officer"));
            service.change(leaf, DisclosureService.Policy.PUBLIC_UNLISTED, true, true, "officer");
            DisclosureService.IssuedCapability issued = service.issueCapability(leaf,
                    ServerTestSupport.CLOCK.instant().plusSeconds(600), "officer");
            assertNotEquals(java.util.HexFormat.of().formatHex(issued.token()),
                    java.util.HexFormat.of().formatHex(issued.capability().tokenCommitment()));
            assertEquals(DisclosureService.Decision.ALLOWED,
                    service.decide(leaf, Optional.empty(), false, false, Optional.of(issued.token())));
            DisclosureService.Capability wrongAction = new DisclosureService.Capability("cap-wrong-action",
                    ServerTestSupport.REALM, leaf, "INSPECT", issued.capability().tokenCommitment(),
                    issued.capability().expiresAt(), false);
            opened.store().createCapability(wrongAction);
            service.revokeCapability(issued.capability().capabilityId(), "officer");
            assertEquals(DisclosureService.Decision.DENIED,
                    service.decide(leaf, Optional.empty(), false, false, Optional.of(issued.token())));
            byte[] wrong = issued.token();
            wrong[0] ^= 1;
            assertEquals(DisclosureService.Decision.DENIED,
                    service.decide(leaf, Optional.empty(), false, false, Optional.of(wrong)));
            assertArrayEquals(issued.capability().tokenCommitment(),
                    opened.store().requireCapability(issued.capability().capabilityId()).tokenCommitment());
            System.out.println("...token-bytes=" + issued.token().length + ", persisted=commitment-only");
        }
        System.out.println("...ok");
    }

    @Test
    void auditorViewsKeepMetadataContentAndPiiSeparate() {
        System.out.println("auditorViewsKeepMetadataContentAndPiiSeparate");
        ServerTestSupport.RecordingAudit audit = new ServerTestSupport.RecordingAudit();
        AuditorViews views = new AuditorViews(ServerTestSupport.CLOCK, audit);
        AuditorViews.Source source = new AuditorViews.Source(new PkiId("credential-a"),
                Permission.ResourceType.CERTIFICATE, ServerTestSupport.scope(), "VALID",
                Instant.parse("2026-08-04T10:00:00Z"), "ed25519", Optional.of("standard.ed25519"),
                ServerTestSupport.DIGEST, true, 2, Optional.of("CN=private"), List.of("private.example"),
                Optional.of(new byte[] { 0x30, 0x01, 0x00 }));
        AuditorViews.Redacted redacted = views.redacted(source);
        assertTrue(redacted.subjectPresent());
        assertThrows(SecurityException.class, () -> views.fullContent(source, true, false));
        assertThrows(SecurityException.class, () -> views.pii(source, ServerTestSupport.principal("auditor"),
                "case-1", true, false));
        assertEquals("CN=private", views.pii(source, ServerTestSupport.principal("auditor"),
                "case-1", true, true).subject().orElseThrow());
        assertFalse(audit.events().isEmpty());
        System.out.println("...redacted-san-count=" + redacted.subjectAlternativeNameCount());
        System.out.println("...ok");
    }
}
