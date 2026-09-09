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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;

/** Transport-neutral, read-only disclosed repository gateway. */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.FieldDeclarationsShouldBeAtStartOfClass",
        "PMD.ExcessiveParameterList" })
public final class PublicRepositoryGateway {
    /** Cache policy classes with distinct privacy semantics. */
    public enum CacheClass {
        /** Immutable public content may be cached indefinitely. */ PUBLIC_IMMUTABLE,
        /** Public alias responses require revalidation. */ PUBLIC_ALIAS,
        /** Authenticated responses must remain private. */ PRIVATE_AUTHENTICATED,
        /** Capability-authorized responses must not be stored. */ NO_STORE_CAPABILITY
    }

    /**
     * Safe public authority metadata.
     *
     * @param authorityId exact logical authority identifier
     * @param kind authority kind
     * @param issuerIds immutable issuer-generation identifiers
     * @param currentIssuanceIssuerId current issuance generation
     */
    public record Authority(PkiId authorityId, zeroecho.pki.api.ca.CaKind kind,
            List<PkiId> issuerIds, PkiId currentIssuanceIssuerId) {
        /** Snapshots finite issuer identities. */
        public Authority { issuerIds = List.copyOf(issuerIds); }
    }

    /**
     * Exact explicit chain path represented as ordered immutable certificate links.
     *
     * @param authorityId exact logical authority identifier
     * @param issuerId exact issuer generation
     * @param pathId exact chain-path identifier
     * @param orderedCredentialIds leaf-to-root credential identifiers
     * @param commitment immutable path commitment
     * @param etag response entity tag
     * @param cacheClass cache policy
     */
    public record Chain(PkiId authorityId, PkiId issuerId, PkiId pathId,
            List<PkiId> orderedCredentialIds, String commitment, String etag, CacheClass cacheClass) {
        /** Snapshots exact order. */
        public Chain { orderedCredentialIds = List.copyOf(orderedCredentialIds); }
    }

    /**
     * Lifecycle-owned binary response descriptor.
     *
     * @param lease content lease owned by this descriptor
     * @param mediaType response media type
     * @param etag response entity tag
     * @param cacheClass cache policy
     */
    public record Content(PkiRepositoryContent lease, String mediaType, String etag, CacheClass cacheClass)
            implements AutoCloseable {
        /** Validates response metadata. */
        public Content {
            Objects.requireNonNull(lease); Permission.requireBounded(mediaType, 128, "media type");
            Permission.requireBounded(etag, 256, "ETag"); Objects.requireNonNull(cacheClass);
        }
        /** Closes the underlying immutable-content lease. */
        @Override public void close() throws java.io.IOException { lease.close(); }
    }

    /**
     * Safe request identity, without certificate or bearer-token logging fields.
     *
     * @param principal optional authenticated principal
     * @param capabilityBearer optional point-addressable capability bearer
     * @param correlationId bounded non-secret request correlation identifier
     */
    public record Access(Optional<SecurityPrincipal> principal, Optional<String> capabilityBearer,
            String correlationId) {
        /** Validates mutually exclusive principal and capability authority. */
        public Access {
            principal = Objects.requireNonNull(principal); capabilityBearer = Objects.requireNonNull(capabilityBearer);
            Permission.requireBounded(correlationId, 256, "correlation ID");
            if (principal.isPresent() && capabilityBearer.isPresent()) {
                throw new IllegalArgumentException("Principal and capability authority cannot be combined");
            }
        }
    }

    private final RealmId realmId;
    private final AuthorityExposurePolicy exposure;
    private final PkiRepository repository;
    private final ServerControlStore control;
    private final RoleTemplateCatalog roles;
    private final AuthorizationEngine authorization;
    private final BreakGlassService breakGlass;
    private final DisclosureService disclosure;
    private final RepositoryAliasService aliases;
    private final Runnable openCheck;

    /** Creates one gateway over the realm's existing authorities. */
    /* default */ PublicRepositoryGateway(RealmId realmId, AuthorityExposurePolicy exposure,
            PkiRepository repository,
            ServerControlStore control, RoleTemplateCatalog roles, AuthorizationEngine authorization,
            BreakGlassService breakGlass, DisclosureService disclosure, RepositoryAliasService aliases,
            Runnable openCheck) {
        this.realmId = Objects.requireNonNull(realmId); this.exposure = Objects.requireNonNull(exposure);
        this.repository = Objects.requireNonNull(repository); this.control = Objects.requireNonNull(control);
        this.roles = Objects.requireNonNull(roles); this.authorization = Objects.requireNonNull(authorization);
        this.breakGlass = Objects.requireNonNull(breakGlass); this.disclosure = Objects.requireNonNull(disclosure);
        this.aliases = Objects.requireNonNull(aliases); this.openCheck = Objects.requireNonNull(openCheck);
    }

    /**
     * Returns one bounded keyset page of exposed public authority metadata.
     *
     * @param after optional exclusive authority cursor
     * @param limit positive maximum result count
     * @return bounded immutable authority page
     */
    public List<Authority> authorities(Optional<PkiId> after, int limit) {
        openCheck.run();
        if (limit <= 0 || limit > 1_000) {
            throw new IllegalArgumentException("Public authority limit is invalid");
        }
        List<Authority> result = new ArrayList<>(limit);
        Optional<PkiId> cursor = Objects.requireNonNull(after, "after");
        while (result.size() < limit) {
            List<CaRecord> page = repository.authorities(cursor, Math.min(1_000, Math.max(64, limit)));
            if (page.isEmpty()) {
                break;
            }
            for (CaRecord value : page) {
                if (exposure.allows(value.caId())) {
                    result.add(authority(value));
                    if (result.size() == limit) {
                        break;
                    }
                }
            }
            cursor = Optional.of(page.getLast().caId());
            if (page.size() < Math.min(1_000, Math.max(64, limit))) {
                break;
            }
        }
        return List.copyOf(result);
    }

    /**
     * Returns one exact exposed authority.
     *
     * @param authorityId exact exposed authority identifier
     * @return safe public authority metadata
     */
    public Authority authority(PkiId authorityId) {
        return authority(requireAuthority(authorityId));
    }

    /**
     * Opens one exact issuer-generation certificate after disclosure enforcement.
     *
     * @param authorityId exact exposed authority identifier
     * @param issuerId exact issuer generation
     * @param access authenticated or capability request authority
     * @return lifecycle-owned certificate response
     */
    public Content issuerCertificate(PkiId authorityId, PkiId issuerId, Access access) {
        requireAuthority(authorityId);
        IssuerGeneration issuer = repository.issuer(issuerId).orElseThrow(PublicRepositoryGateway::unavailable);
        if (!authorityId.equals(issuer.authorityId())) {
            throw unavailable();
        }
        Credential credential = repository.credential(issuer.credentialId())
                .orElseThrow(PublicRepositoryGateway::unavailable);
        AccessDecision decision = decide(credential.credentialId(), authorityId,
                DisclosureService.ObjectType.CA_CERTIFICATE, true, Permission.Action.CERTIFICATE_DOWNLOAD, access);
        return content(repository.openCredential(credential.credentialId()), "application/pkix-cert", decision);
    }

    /**
     * Resolves one explicit chain path without constructing or preferring a path.
     *
     * @param authorityId exact exposed authority identifier
     * @param issuerId exact issuer generation
     * @param pathId exact chain path
     * @param access authenticated or capability request authority
     * @return exact disclosed chain path
     */
    public Chain chainPath(PkiId authorityId, PkiId issuerId, PkiId pathId, Access access) {
        requireAuthority(authorityId);
        IssuerChainPath path = repository.chainPath(pathId).orElseThrow(PublicRepositoryGateway::unavailable);
        if (!authorityId.equals(path.authorityId()) || !issuerId.equals(path.issuerId())) {
            throw unavailable();
        }
        AccessDecision decision = decide(pathId, authorityId, DisclosureService.ObjectType.CA_CHAIN, true,
                Permission.Action.CA_CHAIN_DOWNLOAD, access);
        return chain(path, decision, path.pathCommitment(), false);
    }

    /**
     * Resolves the stable chain route only through CURRENT_CHAIN metadata.
     *
     * @param authorityId exact exposed authority identifier
     * @param access authenticated or capability request authority
     * @return currently aliased disclosed chain path
     */
    public Chain currentChain(PkiId authorityId, Access access) {
        requireAuthority(authorityId);
        RepositoryAliasService.Record alias = aliases.require(authorityId, RepositoryAliasService.Type.CURRENT_CHAIN);
        if (alias.state() != RepositoryAliasService.State.ACTIVE) {
            throw unavailable();
        }
        IssuerChainPath path = repository.chainPath(alias.pathId().orElseThrow())
                .orElseThrow(PublicRepositoryGateway::unavailable);
        if (!authorityId.equals(path.authorityId()) || !alias.issuerId().orElseThrow().equals(path.issuerId())
                || !alias.targetCommitment().equals(path.pathCommitment())) {
            throw unavailable();
        }
        AccessDecision decision = decide(path.pathId(), authorityId, DisclosureService.ObjectType.CA_CHAIN, true,
                Permission.Action.CA_CHAIN_DOWNLOAD, access);
        return chain(path, decision, alias.recordCommitment(), true);
    }

    /**
     * Opens one exact leaf certificate; object identity alone grants no access.
     *
     * @param credentialId exact credential identifier
     * @param access authenticated or capability request authority
     * @return lifecycle-owned certificate response
     */
    public Content credential(PkiId credentialId, Access access) {
        Credential credential = repository.credential(credentialId).orElseThrow(PublicRepositoryGateway::unavailable);
        PkiId authorityId = credential.issuerRef().caId();
        requireAuthority(authorityId);
        AccessDecision decision = decide(credentialId, authorityId, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                false, Permission.Action.CERTIFICATE_DOWNLOAD, access);
        return content(repository.openCredential(credentialId), "application/pkix-cert", decision);
    }

    /**
     * Opens one exact status object after role and disclosure checks.
     *
     * @param statusObjectId exact status-object identifier
     * @param access authenticated or capability request authority
     * @return lifecycle-owned status-object response
     */
    public Content statusObject(PkiId statusObjectId, Access access) {
        StatusObject status = repository.statusObject(statusObjectId).orElseThrow(PublicRepositoryGateway::unavailable);
        requireAuthority(status.issuerCaId());
        DisclosureService.ObjectType type = switch (status.type()) {
            case CRL -> DisclosureService.ObjectType.CRL;
            case DELTA_CRL -> DisclosureService.ObjectType.DELTA_CRL;
            case OCSP -> DisclosureService.ObjectType.STATUS_OBJECT;
        };
        boolean crlFamily = status.type() == StatusObjectType.CRL || status.type() == StatusObjectType.DELTA_CRL;
        String mediaType = switch (status.type()) {
            case CRL, DELTA_CRL -> "application/pkix-crl";
            case OCSP -> "application/ocsp-response";
        };
        AccessDecision decision = decide(statusObjectId, status.issuerCaId(), type, crlFamily,
                crlFamily ? Permission.Action.CRL_DOWNLOAD : Permission.Action.CERTIFICATE_READ_CONTENT, access);
        return content(repository.openStatusObject(statusObjectId), mediaType, decision);
    }

    /**
     * Resolves the stable current-delta-CRL route only through CURRENT_DELTA_CRL metadata.
     *
     * @param authorityId exact exposed authority identifier
     * @param access authenticated or capability request authority
     * @return lifecycle-owned current delta-CRL response
     */
    public Content currentDeltaCrl(PkiId authorityId, Access access) {
        requireAuthority(authorityId);
        RepositoryAliasService.Record alias = aliases.require(authorityId,
                RepositoryAliasService.Type.CURRENT_DELTA_CRL);
        if (alias.state() != RepositoryAliasService.State.ACTIVE) {
            throw unavailable();
        }
        StatusObject status = repository.statusObject(alias.targetObjectId())
                .orElseThrow(PublicRepositoryGateway::unavailable);
        if (!authorityId.equals(status.issuerCaId()) || status.type() != StatusObjectType.DELTA_CRL
                || !alias.targetCommitment().equals(status.content().sha256())) {
            throw unavailable();
        }
        AccessDecision decision = decide(status.statusObjectId(), authorityId, DisclosureService.ObjectType.DELTA_CRL,
                true, Permission.Action.CRL_DOWNLOAD, access);
        PkiRepositoryContent lease = repository.openStatusObject(status.statusObjectId());
        return new Content(lease, "application/pkix-crl", etag(alias.recordCommitment(), decision.commitment()),
                decision.cacheClass() == CacheClass.PUBLIC_IMMUTABLE ? CacheClass.PUBLIC_ALIAS
                        : decision.cacheClass());
    }

    /**
     * Resolves the stable current-CRL route only through CURRENT_CRL metadata.
     *
     * @param authorityId exact exposed authority identifier
     * @param access authenticated or capability request authority
     * @return lifecycle-owned current CRL response
     */
    public Content currentCrl(PkiId authorityId, Access access) {
        requireAuthority(authorityId);
        RepositoryAliasService.Record alias = aliases.require(authorityId, RepositoryAliasService.Type.CURRENT_CRL);
        if (alias.state() != RepositoryAliasService.State.ACTIVE) {
            throw unavailable();
        }
        StatusObject status = repository.statusObject(alias.targetObjectId())
                .orElseThrow(PublicRepositoryGateway::unavailable);
        if (!authorityId.equals(status.issuerCaId()) || status.type() != StatusObjectType.CRL
                || !alias.targetCommitment().equals(status.content().sha256())) {
            throw unavailable();
        }
        AccessDecision decision = decide(status.statusObjectId(), authorityId, DisclosureService.ObjectType.CRL,
                true, Permission.Action.CRL_DOWNLOAD, access);
        PkiRepositoryContent lease = repository.openStatusObject(status.statusObjectId());
        return new Content(lease, "application/pkix-crl", etag(alias.recordCommitment(), decision.commitment()),
                decision.cacheClass() == CacheClass.PUBLIC_IMMUTABLE ? CacheClass.PUBLIC_ALIAS
                        : decision.cacheClass());
    }

    private AccessDecision decide(PkiId objectId, PkiId authorityId, DisclosureService.ObjectType type,
            boolean normativePublic, Permission.Action action, Access access) {
        Objects.requireNonNull(access);
        Optional<DisclosureService.Record> record = control.findDisclosure(objectId);
        if (record.isEmpty()) {
            if (!normativePublic || access.capabilityBearer().isPresent()) {
                throw unavailable();
            }
            DisclosureService.Policy policy = disclosure.defaultPolicy(type, false, false);
            if (policy != DisclosureService.Policy.PUBLIC) {
                throw unavailable();
            }
            return new AccessDecision(CacheClass.PUBLIC_IMMUTABLE, "default:" + type.name());
        }
        DisclosureService.Record exact = record.orElseThrow();
        if (exact.objectType() != type) {
            throw unavailable();
        }
        boolean owner = access.principal().map(SecurityPrincipal::principalId)
                .flatMap(id -> exact.ownerPrincipalId().filter(id::equals)).isPresent();
        boolean permitted = access.principal().filter(SecurityPrincipal::enabled)
                .map(principal -> explicit(principal, action, authorityId, objectId, owner, type)).orElse(false);
        if (disclosure.decideRepository(objectId, access.principal(), owner, permitted,
                access.capabilityBearer()) != DisclosureService.Decision.ALLOWED) {
            throw unavailable();
        }
        CacheClass cache = access.capabilityBearer().isPresent() ? CacheClass.NO_STORE_CAPABILITY
                : access.principal().isPresent() ? CacheClass.PRIVATE_AUTHENTICATED
                        : CacheClass.PUBLIC_IMMUTABLE;
        return new AccessDecision(cache, exact.policyCommitment() + ':' + exact.updatedAt().toEpochMilli());
    }

    private boolean explicit(SecurityPrincipal principal, Permission.Action action, PkiId authorityId,
            PkiId objectId, boolean owner, DisclosureService.ObjectType objectType) {
        List<Permission.Grant> grants = new ArrayList<>(control.grantsFor(principal.principalId()));
        for (RoleTemplateCatalog.Assignment assignment : control.assignmentsFor(principal.principalId())) {
            grants.addAll(roles.instantiate(assignment));
        }
        BreakGlassService.ActiveGrants emergency = breakGlass.activeFor(principal.principalId());
        grants.addAll(emergency.grants());
        Permission.ResourceType resourceType = switch (objectType) {
            case CRL, DELTA_CRL, STATUS_OBJECT -> Permission.ResourceType.STATUS_OBJECT;
            case CA_CHAIN -> Permission.ResourceType.AUTHORITY;
            case CA_CERTIFICATE, LEAF_CERTIFICATE -> Permission.ResourceType.CERTIFICATE;
        };
        Permission.Resource resource = new Permission.Resource(resourceType,
                new Permission.Scope(realmId, Optional.of(authorityId), Optional.empty(), Optional.empty()),
                Optional.of(objectId), Optional.empty());
        return authorization.authorize(new AuthorizationEngine.Request(realmId, exposure, principal, action,
                resource, owner ? Permission.Relationship.OWN : Permission.Relationship.ANY,
                Permission.DataView.CONTENT_FULL, Permission.Context.empty(), grants, emergency.grantIds())).allowed();
    }

    private CaRecord requireAuthority(PkiId authorityId) {
        openCheck.run();
        if (!exposure.allows(authorityId)) {
            throw unavailable();
        }
        return repository.authority(authorityId).orElseThrow(PublicRepositoryGateway::unavailable);
    }

    private static Content content(PkiRepositoryContent lease, String mediaType, AccessDecision decision) {
        return new Content(lease, mediaType, etag(lease.sha256(), decision.commitment()), decision.cacheClass());
    }

    private static Chain chain(IssuerChainPath path, AccessDecision decision, String routeCommitment,
            boolean aliasRoute) {
        return new Chain(path.authorityId(), path.issuerId(), path.pathId(), path.orderedCredentialIds(),
                path.pathCommitment(), etag(routeCommitment, decision.commitment()),
                aliasRoute && decision.cacheClass() == CacheClass.PUBLIC_IMMUTABLE ? CacheClass.PUBLIC_ALIAS
                        : decision.cacheClass());
    }

    private static Authority authority(CaRecord value) {
        return new Authority(value.caId(), value.kind(), value.issuerIds(), value.currentIssuanceIssuerId());
    }

    private static String etag(String first, String second) {
        try {
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest((first + '\n' + second).getBytes(StandardCharsets.UTF_8)));
            return '"' + hash + '"';
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static IllegalArgumentException unavailable() {
        return new IllegalArgumentException("Repository resource unavailable");
    }

    private record AccessDecision(CacheClass cacheClass, String commitment) { }
}
