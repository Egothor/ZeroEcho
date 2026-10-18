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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiResourceScopeResolver;

class AdminCredentialPublicationEnrollmentTest {
    private static final String ACTOR = "publication-admin";
    private static final String OWNER = "certificate-owner";
    private static final PkiId CREDENTIAL_ID = new PkiId("credential-admin-enrollment");
    private static final PkiId PUBLICATION_ID = new PkiId("publication-delayed-result");

    @TempDir
    Path temporaryDirectory;

    @Test
    void authorizedEnrollmentUsesExactScopeExplicitOwnerAndReplaysExactly() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            Fixture fixture = fixture(opened, ConfirmationDisclosurePolicy.OWNER_ONLY);
            addPrincipal(opened, ACTOR);
            addPrincipal(opened, OWNER);
            addPrincipal(opened, "different-owner");
            opened.store().createGrant(grant("publication-change", Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                    fixture.scope()));

            ServerOperationGateway.Outcome first = fixture.gateway().execute(
                    request(Optional.of(OWNER)), CancellationSignal.NONE);
            ServerOperationGateway.Outcome replay = fixture.gateway().execute(
                    request(Optional.of(OWNER)), CancellationSignal.NONE);

            assertCompleted(first);
            assertCompleted(replay);
            DisclosureService.Record disclosure = opened.store().requireDisclosure(CREDENTIAL_ID);
            assertEquals(Optional.of(OWNER), disclosure.ownerPrincipalId());
            assertEquals(DisclosureService.Policy.OWNER_ONLY, disclosure.policy());
            assertEquals(CredentialConfirmationLifecycle.State.PENDING,
                    fixture.confirmation().get().state());

            ServerControlOperationOutcome conflict = assertInstanceOf(
                    ServerOperationGateway.Outcome.ControlExecuted.class,
                    fixture.gateway().execute(request(Optional.of("different-owner")), CancellationSignal.NONE))
                    .outcome();
            PkiOperationOutcome failed = assertInstanceOf(ServerControlOperationOutcome.Ordinary.class,
                    conflict).outcome();
            assertInstanceOf(PkiOperationOutcome.Failed.class, failed);
        }
    }

    @Test
    void ownerOnlyRequiresExistingExplicitOwnerAndNeverSubstitutesActor() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            Fixture fixture = fixture(opened, ConfirmationDisclosurePolicy.OWNER_ONLY);
            addPrincipal(opened, ACTOR);
            opened.store().createGrant(grant("publication-change", Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                    fixture.scope()));

            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    fixture.gateway().execute(request(Optional.empty()), CancellationSignal.NONE));
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    fixture.gateway().execute(request(Optional.of("missing-owner")), CancellationSignal.NONE));
            assertNull(fixture.confirmation().get());
            assertTrue(opened.store().findDisclosure(CREDENTIAL_ID).isEmpty());
        }
    }

    @Test
    void publicEnrollmentPreservesOptionalOwnerAbsence() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            Fixture fixture = fixture(opened, ConfirmationDisclosurePolicy.PUBLIC);
            addPrincipal(opened, ACTOR);
            opened.store().createGrant(grant("publication-change", Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                    fixture.scope()));

            assertCompleted(fixture.gateway().execute(request(Optional.empty()), CancellationSignal.NONE));

            DisclosureService.Record disclosure = opened.store().requireDisclosure(CREDENTIAL_ID);
            assertEquals(Optional.empty(), disclosure.ownerPrincipalId());
            assertEquals(Optional.empty(), disclosure.ownerAcmeAccountId());
            assertEquals(CredentialConfirmationLifecycle.State.NOT_REQUIRED,
                    fixture.confirmation().get().state());
        }
    }

    @Test
    void issueAndReadPermissionsOrWrongProfileScopeCannotEnroll() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            Fixture fixture = fixture(opened, ConfirmationDisclosurePolicy.OWNER_ONLY);
            addPrincipal(opened, ACTOR);
            addPrincipal(opened, OWNER);
            opened.store().createGrant(grant("issue", Permission.Action.CERTIFICATE_ISSUE, fixture.scope()));
            opened.store().createGrant(grant("read", Permission.Action.CERTIFICATE_READ_METADATA, fixture.scope()));
            Permission.Scope wrongProfile = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("vpn-server"));
            opened.store().createGrant(grant("wrong-scope",
                    Permission.Action.CERTIFICATE_PUBLICATION_CHANGE, wrongProfile));

            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    fixture.gateway().execute(request(Optional.of(OWNER)), CancellationSignal.NONE));
            assertNull(fixture.confirmation().get());
            assertTrue(opened.store().findDisclosure(CREDENTIAL_ID).isEmpty());
        }
    }

    @Test
    void delayedIssuancePollingNeverEnrollsOrAcquiresOwnership() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            Fixture fixture = fixture(opened, ConfirmationDisclosurePolicy.OWNER_ONLY);
            addPrincipal(opened, ACTOR);
            opened.store().createGrant(new Permission.Grant("publication-read", ACTOR, Permission.Effect.ALLOW,
                    Permission.Action.PUBLICATION_READ, Permission.ResourceType.PUBLICATION,
                    new Permission.Scope(ServerTestSupport.REALM, Optional.of(ServerTestSupport.AUTHORITY),
                            Optional.empty(), Optional.empty()), Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true));
            Permission.Resource resource = new Permission.Resource(Permission.ResourceType.PUBLICATION,
                    new Permission.Scope(ServerTestSupport.REALM, Optional.of(ServerTestSupport.AUTHORITY),
                            Optional.empty(), Optional.empty()), Optional.of(PUBLICATION_ID), Optional.empty());
            ServerOperationGateway.Request poll = new ServerOperationGateway.Request(ServerTestSupport.REALM,
                    ACTOR, new PkiOperation.InspectPublication(PUBLICATION_ID), resource,
                    Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(), "poll-a");

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    fixture.gateway().execute(poll, CancellationSignal.NONE));
            assertEquals(1, fixture.pkiCalls().get());
            assertNull(fixture.confirmation().get());
            assertTrue(opened.store().findDisclosure(CREDENTIAL_ID).isEmpty());
        }
    }

    private static Fixture fixture(ServerTestSupport.OpenedStore opened,
            ConfirmationDisclosurePolicy disclosurePolicy) {
        ImportedCertificateProfileVersion imported = imported(disclosurePolicy);
        PkiRepository repository = mock(PkiRepository.class);
        ProfileService profiles = mock(ProfileService.class);
        Credential credential = mock(Credential.class);
        when(credential.credentialId()).thenReturn(CREDENTIAL_ID);
        when(credential.issuerRef()).thenReturn(new IssuerRef(ServerTestSupport.AUTHORITY));
        when(credential.profileBinding()).thenReturn(new EndEntityProfileBinding(imported.reference()));
        when(repository.credential(CREDENTIAL_ID)).thenReturn(Optional.of(credential));
        when(profiles.getImportedVersion(imported.reference().profileId(), imported.reference().profileVersion()))
                .thenReturn(Optional.of(imported));
        AtomicReference<CredentialConfirmationLifecycle> confirmation = new AtomicReference<>();
        CredentialConfirmationService confirmations = mock(CredentialConfirmationService.class);
        when(confirmations.get(CREDENTIAL_ID)).thenAnswer(ignored -> Optional.ofNullable(confirmation.get()));
        when(confirmations.initialize(any(CredentialConfirmationInitialization.class))).thenAnswer(invocation -> {
            CredentialConfirmationLifecycle initialized = CredentialConfirmationLifecycle.initialize(
                    invocation.getArgument(0));
            if (confirmation.compareAndSet(null, initialized) || confirmation.get().equals(initialized)) {
                return confirmation.get();
            }
            throw new IllegalStateException("confirmation conflict");
        });
        DisclosureService disclosure = new DisclosureService(ServerTestSupport.REALM, opened.store(),
                DisclosureService.Defaults.recommended(), ServerTestSupport.CLOCK, new SecureRandom(),
                opened.audit());
        CredentialPublicationGate publication = new CredentialPublicationGate(repository, profiles,
                confirmations, disclosure, ServerTestSupport.CLOCK, () -> { });
        AtomicInteger pkiCalls = new AtomicInteger();
        AuthorizationEngine authorization = new AuthorizationEngine(ServerTestSupport.CLOCK);
        ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
        BreakGlassService breakGlass = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
        PkiResourceScopeResolver scopes = new PkiResourceScopeResolver() {
            @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                return Optional.of(new CredentialScope(ServerTestSupport.AUTHORITY, "profile-a"));
            }
            @Override public Optional<PkiId> statusObjectAuthority(PkiId statusObjectId) {
                return Optional.of(ServerTestSupport.AUTHORITY);
            }
            @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) {
                return Optional.of(ServerTestSupport.AUTHORITY);
            }
        };
        ServerOperationGateway gateway = new ServerOperationGateway(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                opened.store(), RoleTemplateCatalog.load(AdminCredentialPublicationEnrollmentTest.class
                        .getClassLoader()), authorization, approvals, breakGlass, disclosure,
                publication, new AuditorViews(ServerTestSupport.CLOCK, opened.audit()), Optional.empty(),
                new OperationSecurityDescriptors(), (operation, cancellation) -> {
                    pkiCalls.incrementAndGet();
                    return new PkiOperationOutcome.Completed(new PkiOperationResult(operation.name(), Map.of()));
                }, (request, evidence, cancellation) -> { throw new AssertionError("Unexpected signing"); },
                scopes, Map.of(),
                profileId -> zeroecho.pki.api.profile.IssuanceApprovalRequirement.NONE,
                ServerTestSupport.CLOCK, opened.audit(), () -> { });
        Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM,
                Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(),
                Optional.of(imported.reference().profileId()));
        return new Fixture(gateway, scope, confirmation, pkiCalls);
    }

    private static ServerOperationGateway.Request request(Optional<String> ownerPrincipalId) {
        ServerControlOperation operation = new ServerControlOperation.EnrollCredentialPublication(
                CREDENTIAL_ID, ownerPrincipalId);
        Permission.Resource unresolved = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                new Permission.Scope(ServerTestSupport.REALM, Optional.empty(), Optional.empty(), Optional.empty()),
                Optional.of(CREDENTIAL_ID), Optional.empty());
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, ACTOR,
                new AdministrativeOperation.Control(operation), unresolved, Permission.Relationship.ANY,
                Permission.Context.empty(), Optional.empty(), "enroll-a");
    }

    private static Permission.Grant grant(String id, Permission.Action action, Permission.Scope scope) {
        return new Permission.Grant(id, ACTOR, Permission.Effect.ALLOW, action,
                Permission.ResourceType.CERTIFICATE, scope, Permission.Relationship.ANY,
                Permission.DataView.METADATA_FULL, Set.of(), Optional.empty(), true);
    }

    private static void addPrincipal(ServerTestSupport.OpenedStore opened, String principalId) {
        opened.store().createPrincipal(ServerTestSupport.principal(principalId));
    }

    private static ImportedCertificateProfileVersion imported(ConfirmationDisclosurePolicy disclosurePolicy) {
        BuiltInCertificateProfileTemplate template = BuiltInCertificateProfileCatalog
                .load(AdminCredentialPublicationEnrollmentTest.class.getClassLoader()).stream()
                .filter(candidate -> candidate.definition().profileId().equals("server-tls"))
                .findFirst().orElseThrow();
        CertificateProfileDefinition base = template.definition();
        CredentialConfirmationPolicy standard = base.confirmationPolicy().orElseThrow();
        CredentialConfirmationPolicy policy = new CredentialConfirmationPolicy(disclosurePolicy,
                standard.confirmationWindow(), standard.proofSuite());
        CertificateProfileDefinition definition = new CertificateProfileDefinition(base.certificateType(),
                base.profileId(), base.profileVersion(), base.formatId(), base.displayName(), base.maximumValidity(),
                base.subjectPolicy(), base.certificatePolicy(), base.algorithmBindingPolicy(), Optional.of(policy));
        byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
        CertificateProfileRef reference = new CertificateProfileRef(definition.profileId(),
                definition.profileVersion(), new byte[CertificateProfileRef.HASH_BYTES]);
        return new ImportedCertificateProfileVersion(reference, CertificateProfileDefinition.SCHEMA_VERSION,
                definition, canonical, Instant.EPOCH);
    }

    private static void assertCompleted(ServerOperationGateway.Outcome outcome) {
        ServerControlOperationOutcome control = assertInstanceOf(
                ServerOperationGateway.Outcome.ControlExecuted.class, outcome).outcome();
        PkiOperationOutcome pki = assertInstanceOf(ServerControlOperationOutcome.Ordinary.class, control).outcome();
        assertInstanceOf(PkiOperationOutcome.Completed.class, pki);
    }

    private record Fixture(ServerOperationGateway gateway, Permission.Scope scope,
            AtomicReference<CredentialConfirmationLifecycle> confirmation, AtomicInteger pkiCalls) { }
}
