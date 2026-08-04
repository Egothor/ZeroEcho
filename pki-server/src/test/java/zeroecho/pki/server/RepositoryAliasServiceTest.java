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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.impl.framework.x509.bc.SimpleAttributeSet;

/** Durable explicit repository-alias authority coverage. */
final class RepositoryAliasServiceTest {
    @TempDir Path directory;

    @Test
    void currentCrlUsesExpectedCurrentAndSurvivesRecovery() throws Exception {
        System.out.println("currentCrlUsesExpectedCurrentAndSurvivesRecovery");
        PkiId statusId = new PkiId("status-current-crl");
        RepositoryFixtures repository = new RepositoryFixtures(statusId);
        RepositoryAliasService.Record created;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("alias-admin"));
            RepositoryAliasService aliases = service(opened, repository);
            created = aliases.setCurrentCrl(ServerTestSupport.AUTHORITY, statusId, Optional.empty(), "alias-admin");
            assertEquals(RepositoryAliasService.Type.CURRENT_CRL, created.type());
            assertEquals(created, aliases.setCurrentCrl(ServerTestSupport.AUTHORITY, statusId,
                    Optional.empty(), "alias-admin"));
            assertThrows(IllegalStateException.class, () -> aliases.setCurrentCrl(ServerTestSupport.AUTHORITY,
                    new PkiId("status-other"), Optional.empty(), "alias-admin"));
            System.out.println("...alias=" + created.aliasId() + " commitment="
                    + created.recordCommitment().substring(0, 12));
        }
        try (ServerControlStore store = new ServerControlStore(
                zeroecho.pki.impl.fs.PosixTransactionalMetadataStore.open(
                        directory.resolve("server-control.log"), java.util.OptionalLong.of(1_048_576)))) {
            ServerTestSupport.OpenedStore reopened = new ServerTestSupport.OpenedStore(
                    directory.resolve("server-control.log"), store, new ServerTestSupport.RecordingAudit());
            assertEquals(created, service(reopened, repository).require(ServerTestSupport.AUTHORITY,
                    RepositoryAliasService.Type.CURRENT_CRL));
        }
        System.out.println("...ok");
    }

    @Test
    void currentChainBindsExactIssuerPathWithoutChangingIssuanceAuthority() throws Exception {
        System.out.println("currentChainBindsExactIssuerPathWithoutChangingIssuanceAuthority");
        RepositoryFixtures repository = new RepositoryFixtures(new PkiId("status-current-crl"));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("alias-admin"));
            DisclosureService disclosure = disclosure(opened);
            RepositoryAliasService aliases = service(opened, repository, disclosure);
            RepositoryAliasService.Record alias = aliases.setCurrentChain(ServerTestSupport.AUTHORITY,
                    repository.issuer.issuerId(), repository.path.pathId(), Optional.empty(), "alias-admin");
            assertEquals(repository.path.pathCommitment(), alias.targetCommitment());
            assertEquals(repository.path.pathId(), alias.pathId().orElseThrow());
            assertEquals(repository.issuer.issuerId(), alias.issuerId().orElseThrow());
            assertEquals(repository.authority.issuanceChainPathId(), repository.path.pathId());
            PublicRepositoryGateway gateway = gateway(opened, repository, disclosure, aliases);
            PublicRepositoryGateway.Chain publicChain = gateway.currentChain(ServerTestSupport.AUTHORITY,
                    new PublicRepositoryGateway.Access(Optional.empty(), Optional.empty(), "request-chain"));
            assertEquals(repository.path.orderedCredentialIds(), publicChain.orderedCredentialIds());
            assertEquals(repository.path.pathCommitment(), publicChain.commitment());
            RepositoryAliasService.Record removed = aliases.remove(ServerTestSupport.AUTHORITY,
                    RepositoryAliasService.Type.CURRENT_CHAIN, alias.recordCommitment(), "alias-admin");
            assertEquals(RepositoryAliasService.State.REMOVED, removed.state());
            assertEquals(repository.path.pathId(), repository.authority.issuanceChainPathId());
            assertThrows(IllegalArgumentException.class, () -> gateway.currentChain(ServerTestSupport.AUTHORITY,
                    new PublicRepositoryGateway.Access(Optional.empty(), Optional.empty(), "request-removed")));
            System.out.println("...path=" + repository.path.pathId().value() + " state=" + removed.state());
        }
        System.out.println("...ok");
    }

    private RepositoryAliasService service(ServerTestSupport.OpenedStore opened, PkiRepository repository)
            throws Exception {
        return service(opened, repository, disclosure(opened));
    }

    private RepositoryAliasService service(ServerTestSupport.OpenedStore opened, PkiRepository repository,
            DisclosureService disclosure) {
        return new RepositoryAliasService(ServerTestSupport.REALM, opened.store(), repository, disclosure,
                ServerTestSupport.CLOCK, opened.audit());
    }

    private DisclosureService disclosure(ServerTestSupport.OpenedStore opened) throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 7, 6, 5, 4 });
        return new DisclosureService(ServerTestSupport.REALM, opened.store(),
                DisclosureService.Defaults.recommended(), ServerTestSupport.CLOCK, random, opened.audit());
    }

    private PublicRepositoryGateway gateway(ServerTestSupport.OpenedStore opened, PkiRepository repository,
            DisclosureService disclosure, RepositoryAliasService aliases) {
        return new PublicRepositoryGateway(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                repository, opened.store(), RoleTemplateCatalog.load(getClass().getClassLoader()),
                new AuthorizationEngine(ServerTestSupport.CLOCK),
                new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit()),
                disclosure, aliases, () -> { });
    }

    private static final class RepositoryFixtures implements PkiRepository {
        private static final String ZERO = "0".repeat(64);
        private final PkiId credentialId = new PkiId("credential-authority");
        private final IssuerGeneration issuer = new IssuerGeneration(
                IssuerGeneration.idFor(ServerTestSupport.AUTHORITY, credentialId), ServerTestSupport.AUTHORITY,
                credentialId, new KeyRef("issuer-key"), IssuerGenerationState.ACTIVE, ZERO, ZERO);
        private final IssuerChainPath path = IssuerChainPath.create(ServerTestSupport.AUTHORITY,
                issuer.issuerId(), List.of(credentialId));
        private final CaRecord authority = new CaRecord(ServerTestSupport.AUTHORITY,
                zeroecho.pki.api.ca.CaKind.ROOT, zeroecho.pki.api.ca.CaState.ACTIVE,
                new KeyRef("issuer-key"), new zeroecho.pki.api.SubjectRef("CN=Authority"),
                List.of(issuer.issuerId()), issuer.issuerId(), path.pathId());
        private final StatusObject status;

        private RepositoryFixtures(PkiId statusId) {
            status = new StatusObject(statusId, new FormatId("x509"), ServerTestSupport.AUTHORITY,
                    StatusObjectType.CRL, Instant.EPOCH, Optional.empty(), reference(statusId),
                    new SimpleAttributeSet());
        }

        @Override public Optional<CaRecord> authority(PkiId id) {
            return authority.caId().equals(id) ? Optional.of(authority) : Optional.empty();
        }
        @Override public List<CaRecord> authorities(Optional<PkiId> after, int limit) { return List.of(authority); }
        @Override public Optional<IssuerGeneration> issuer(PkiId id) {
            return issuer.issuerId().equals(id) ? Optional.of(issuer) : Optional.empty();
        }
        @Override public Optional<IssuerChainPath> chainPath(PkiId id) {
            return path.pathId().equals(id) ? Optional.of(path) : Optional.empty();
        }
        @Override public Optional<Credential> credential(PkiId id) { return Optional.empty(); }
        @Override public Optional<StatusObject> statusObject(PkiId id) {
            if (status.statusObjectId().equals(id)) return Optional.of(status);
            if ("status-other".equals(id.value())) {
                return Optional.of(new StatusObject(id, status.formatId(), status.issuerCaId(), status.type(),
                        status.thisUpdate(), status.nextUpdate(), reference(id), status.attributes()));
            }
            return Optional.empty();
        }
        @Override public PkiRepositoryContent openCredential(PkiId id) { throw new UnsupportedOperationException(); }
        @Override public PkiRepositoryContent openStatusObject(PkiId id) { throw new UnsupportedOperationException(); }

        private static DurableContentReference reference(PkiId id) {
            return new DurableContentReference() {
                @Override public String storeId() { return "store"; }
                @Override public String contentId() { return id.value(); }
                @Override public Encoding encoding() { return Encoding.DER; }
                @Override public long length() { return 1L; }
                @Override public String sha256() { return ZERO; }
                @Override public Lifecycle lifecycle() { return Lifecycle.PERSISTED; }
            };
        }
    }
}
