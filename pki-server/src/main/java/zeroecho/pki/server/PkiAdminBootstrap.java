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

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.storage.KeyringPassword;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;

/**
 * Offline, one-shot creation of the initial administrator pair and nginx transport identity.
 *
 * <p>Run only against a fresh filesystem PKI store before the permanent server starts.
 * Configuration supplies certificate commitments and an unchanged independent approval policy.
 * A durable reservation is retained on success or failure; partial bootstrap must be inspected
 * rather than retried. This tool never opens an HTTP listener or issues certificates.</p>
 */
public final class PkiAdminBootstrap {
    private static final String ACTOR = "system";
    private static final String HELP = "Usage: zeroecho-pki-admin-bootstrap --config PATH --admin-id ID "
            + "--approver-id ID --proxy-id ID\n";

    private PkiAdminBootstrap() { }

    /**
     * Creates initial identities using an explicit local operator invocation.
     *
     * @param arguments configuration path and three distinct mapped principal IDs; no passwords
     */
    public static void main(String[] arguments) {
        int result = run(arguments);
        if (result != 0) System.exit(result);
    }

    static int run(String[] arguments) {
        if (arguments.length == 1 && "--help".equals(arguments[0])) {
            System.out.print(HELP);
            return 0;
        }
        try {
            Map<String, String> options = options(arguments);
            PkiServerConfiguration configuration = PkiServerConfigurationCodec.read(Path.of(options.get("--config")));
            bootstrap(configuration, options.get("--admin-id"), options.get("--approver-id"), options.get("--proxy-id"));
            System.out.println("Initial administrator identities created; bootstrap cannot be repeated.");
            return 0;
        } catch (IllegalArgumentException | IOException failure) {
            System.err.println("Administrator bootstrap refused: " + failure.getMessage());
            return 2;
        } catch (RuntimeException failure) {
            System.err.println("Administrator bootstrap failed; inspect retained state before recovery.");
            return 3;
        }
    }

    private static Map<String, String> options(String[] arguments) {
        Set<String> names = Set.of("--config", "--admin-id", "--approver-id", "--proxy-id");
        if (arguments.length != names.size() * 2) throw new IllegalArgumentException(HELP.strip());
        Map<String, String> options = new HashMap<>();
        for (int index = 0; index < arguments.length; index += 2) {
            if (!names.contains(arguments[index]) || options.putIfAbsent(arguments[index], arguments[index + 1]) != null) {
                throw new IllegalArgumentException("Unknown or repeated option");
            }
        }
        return options;
    }

    static void bootstrap(PkiServerConfiguration configuration, String administrator, String approver, String proxy)
            throws IOException {
        validate(configuration, administrator, approver, proxy);
        configuration.realm().initialAdministratorPrincipalId().ifPresent(initial -> {
            if (!initial.equals(administrator)) throw new IllegalArgumentException("Initial administrator differs from bootstrap");
        });
        Path control = configuration.realm().controlLogPath();
        Path root = Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        requireFresh(control, root);
        Files.createDirectories(control.getParent());
        Path reservation = control.resolveSibling(control.getFileName() + ".admin-bootstrap-started");
        try (FileChannel channel = FileChannel.open(reservation, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            channel.force(true);
        }
        try (FileChannel parent = FileChannel.open(control.getParent(), StandardOpenOption.READ)) {
            parent.force(true);
        }
        // A second check closes races with processes that initialized state before our reservation.
        requireFresh(control, root);
        try (ServerRealmContext context = ServerRealmContext.open(configuration.realm(), dependencies(configuration))) {
            Permission.Scope scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(),
                    Optional.empty(), Optional.empty());
            context.createPrincipal(new SecurityPrincipal(proxy, SecurityPrincipal.Type.SERVICE,
                    "Initial reverse proxy", Optional.empty(), Map.of(), true), ACTOR);
            context.grant(grant("bootstrap.proxy-forward", proxy, Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY,
                    Permission.ResourceType.REALM, scope, Permission.DataView.METADATA_REDACTED), ACTOR);
            for (String principal : List.of(administrator, approver)) {
                context.createPrincipal(new SecurityPrincipal(principal, SecurityPrincipal.Type.USER,
                        principal, Optional.empty(), Map.of(), true), ACTOR);
                if (principal.equals(administrator)) context.recordInitialAdministrator(administrator);
                String prefix = principal.equals(administrator) ? "bootstrap.admin." : "bootstrap.approver.";
                for (Permission.Grant permission : catalogGrants(principal, prefix, scope)) context.grant(permission, ACTOR);
                context.grant(realmReadGrant(principal, prefix, scope), ACTOR);
                for(Permission.Grant permission:certificateAccessGrants(principal,prefix,scope))context.grant(permission,ACTOR);
                context.grant(statusAccessGrant(principal,prefix,scope),ACTOR);
                if (principal.equals(administrator)) context.grant(rootApprovalGrant(administrator, scope), ACTOR);
                if (principal.equals(administrator) && configuration.realm().initialAdministratorPrincipalId().isPresent()) {
                    context.grant(managedGenerationGrant(administrator, scope), ACTOR);
                }
            }
        }
    }

    static void provisionRootAdmin(PkiServerConfiguration configuration, String administrator, String approver, String proxy)
            throws IOException {
        provisionInitialCapabilities(configuration,administrator,approver,proxy,true,false,false);
    }

    static void provisionCertificateAccess(PkiServerConfiguration configuration,String administrator,String approver,String proxy)
            throws IOException {
        provisionInitialCapabilities(configuration,administrator,approver,proxy,false,true,false);
    }

    static void provisionStatusAccess(PkiServerConfiguration configuration,String administrator,String approver,String proxy)throws IOException {
        provisionInitialCapabilities(configuration,administrator,approver,proxy,false,false,true);
    }

    private static void provisionInitialCapabilities(PkiServerConfiguration configuration,String administrator,String approver,String proxy,
            boolean rootApproval,boolean certificateAccess,boolean statusAccess)throws IOException {
        validate(configuration, administrator, approver, proxy);
        Path control = configuration.realm().controlLogPath();
        Path reservation = control.resolveSibling(control.getFileName() + ".admin-bootstrap-started");
        Path root = Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        if (!Files.isRegularFile(control, LinkOption.NOFOLLOW_LINKS)
                || !Files.isRegularFile(reservation, LinkOption.NOFOLLOW_LINKS) || Files.size(reservation) != 0
                || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
                || !Files.isRegularFile(root.resolve("VERSION"), LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Root designation requires an existing initial bootstrap");
        }
        try (ServerRealmContext context = ServerRealmContext.open(configuration.realm(), dependencies(configuration))) {
            Permission.Scope scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            Permission.Grant own = rootApprovalGrant(administrator, scope);
            for (String principal : List.of(proxy, administrator, approver)) {
                SecurityPrincipal expected = new SecurityPrincipal(principal,
                        principal.equals(proxy) ? SecurityPrincipal.Type.SERVICE : SecurityPrincipal.Type.USER,
                        principal.equals(proxy) ? "Initial reverse proxy" : principal, Optional.empty(), Map.of(), true);
                if (!context.principal(principal).equals(expected)) throw new IllegalArgumentException("Initial principal changed; root designation refused");
                Map<String, Permission.Grant> grants = new java.util.LinkedHashMap<>();
                if (principal.equals(proxy)) {
                    Permission.Grant forwarding = grant("bootstrap.proxy-forward", proxy, Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY,
                            Permission.ResourceType.REALM, scope, Permission.DataView.METADATA_REDACTED);
                    grants.put(forwarding.grantId(), forwarding);
                } else {
                    String prefix = principal.equals(administrator) ? "bootstrap.admin." : "bootstrap.approver.";
                    catalogGrants(principal, prefix, scope).forEach(permission -> grants.put(permission.grantId(), permission));
                    Permission.Grant realm = realmReadGrant(principal, prefix, scope);
                    grants.put(realm.grantId(), realm);
                    if (principal.equals(administrator)) {
                        grants.put(own.grantId(), own);
                        var generation = managedGenerationGrant(administrator, scope);
                        grants.put(generation.grantId(), generation);
                    }
                    certificateAccessGrants(principal,prefix,scope).forEach(permission -> grants.put(permission.grantId(),permission));
                    var status=statusAccessGrant(principal,prefix,scope);grants.put(status.grantId(),status);
                }
                for (Permission.Grant permission : context.directGrants(principal)) {
                    if (!permission.equals(grants.remove(permission.grantId()))) {
                        throw new IllegalArgumentException("Initial permissions changed; root designation refused");
                    }
                }
                if(!principal.equals(proxy)) {
                    String prefix=principal.equals(administrator)?"bootstrap.admin.":"bootstrap.approver.";
                    for(var optional:certificateAccessGrants(principal,prefix,scope))grants.remove(optional.grantId());
                    grants.remove(statusAccessGrant(principal,prefix,scope).grantId());
                    if(principal.equals(administrator)) {
                        grants.remove(own.grantId());
                        grants.remove(managedGenerationGrant(administrator, scope).grantId());
                    }
                }
                if(!grants.isEmpty())throw new IllegalArgumentException("Initial permissions incomplete; capability provisioning refused");
            }
            if (rootApproval && context.directGrants(administrator).stream().noneMatch(permission -> permission.grantId().equals(own.grantId()))) {
                context.grant(own, administrator);
            }
            context.recordInitialAdministrator(administrator);
            if (configuration.realm().initialAdministratorPrincipalId().isPresent()) {
                var generation = managedGenerationGrant(administrator, scope);
                if (context.directGrants(administrator).stream().noneMatch(value -> value.grantId().equals(generation.grantId()))) {
                    context.grant(generation, administrator);
                }
            }
            if(certificateAccess)for(String principal:List.of(administrator,approver)) {
                String prefix=principal.equals(administrator)?"bootstrap.admin.":"bootstrap.approver.";
                for(var permission:certificateAccessGrants(principal,prefix,scope)) {
                    if(context.directGrants(principal).stream().noneMatch(value -> value.grantId().equals(permission.grantId())))context.grant(permission,administrator);
                }
            }
            if(statusAccess)for(String principal:List.of(administrator,approver)) {
                String prefix=principal.equals(administrator)?"bootstrap.admin.":"bootstrap.approver.";
                var permission=statusAccessGrant(principal,prefix,scope);
                if(context.directGrants(principal).stream().noneMatch(value -> value.grantId().equals(permission.grantId())))context.grant(permission,administrator);
            }
        }
    }

    private static Permission.Grant statusAccessGrant(String principal,String prefix,Permission.Scope scope) {
        return grant(prefix+"status-download",principal,Permission.Action.CRL_DOWNLOAD,Permission.ResourceType.STATUS_OBJECT,scope,Permission.DataView.CONTENT_FULL);
    }

    private static List<Permission.Grant> certificateAccessGrants(String principal,String prefix,Permission.Scope scope) {
        return List.of(grant(prefix+"certificate-read-content",principal,Permission.Action.CERTIFICATE_READ_CONTENT,
                        Permission.ResourceType.CERTIFICATE,scope,Permission.DataView.CONTENT_FULL),
                grant(prefix+"certificate-download",principal,Permission.Action.CERTIFICATE_DOWNLOAD,
                        Permission.ResourceType.CERTIFICATE,scope,Permission.DataView.CONTENT_FULL));
    }

    private static Permission.Grant rootApprovalGrant(String principal, Permission.Scope scope) {
        return new Permission.Grant("bootstrap.admin.approval-own", principal, Permission.Effect.ALLOW,
                Permission.Action.APPROVAL_DECIDE_OWN, Permission.ResourceType.APPROVAL, scope, Permission.Relationship.OWN,
                Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true);
    }

    private static Permission.Grant managedGenerationGrant(String principal, Permission.Scope scope) {
        return grant("bootstrap.admin.managed-key-generate", principal, Permission.Action.MANAGED_KEY_GENERATE,
                Permission.ResourceType.MANAGED_KEY, scope, Permission.DataView.METADATA_REDACTED);
    }

    private static List<Permission.Grant> catalogGrants(String principal, String prefix, Permission.Scope scope) {
        List<Permission.Grant> permissions = new ArrayList<>();
        int index = 0;
        for (OperationSecurityDescriptors.Descriptor descriptor : new OperationSecurityDescriptors()
                .descriptors().values().stream()
                .filter(descriptor -> !descriptor.operationId().equals(ServerControlOperation.GenerateManagedKey.NAME))
                // Inventory aliases the existing search permission; preserve every historical numbered grant.
                .filter(descriptor -> !descriptor.operationId().equals(zeroecho.pki.application.PkiOperation.ListCredentials.NAME))
                .sorted(java.util.Comparator.comparing(
                        OperationSecurityDescriptors.Descriptor::operationId)).toList()) {
            permissions.add(grant(prefix + index++, principal, descriptor.action(), descriptor.resourceType(),
                    scope, descriptor.dataView()));
        }
        return List.copyOf(permissions);
    }

    private static Permission.Grant realmReadGrant(String principal, String prefix, Permission.Scope scope) {
        return grant(prefix + "realm-read", principal, Permission.Action.REALM_READ, Permission.ResourceType.REALM,
                scope, Permission.DataView.METADATA_REDACTED);
    }

    private static PkiSessionRuntimeDependencies dependencies(PkiServerConfiguration configuration) {
        Optional<String> environment = configuration.runtime().keyUnlockEnvironmentVariable();
        if (environment.isEmpty()) return PkiSessionRuntimeDependencies.none();
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(() -> {
            String value = System.getenv(environment.orElseThrow());
            if (value == null || value.isEmpty()) throw new IOException("Configured key unlock source is unavailable");
            char[] secret = value.toCharArray();
            try {
                return new KeyringPassword(secret);
            } finally {
                java.util.Arrays.fill(secret, '\0');
            }
        });
    }

    private static void requireFresh(Path control, Path root) throws IOException {
        if (Files.exists(control, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Server-control log already exists");
        }
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(root) || !Files.isDirectory(root)) {
                throw new IllegalArgumentException("PKI root is not a fresh directory");
            }
            try (var entries = Files.list(root)) {
                if (entries.findAny().isPresent()) throw new IllegalArgumentException("PKI store is not empty");
            }
        }
    }

    private static void validate(PkiServerConfiguration configuration, String administrator, String approver, String proxy) {
        configuration.realm().initialAdministratorPrincipalId().ifPresent(initial -> {
            if (!initial.equals(administrator)) throw new IllegalArgumentException("Initial administrator differs from bootstrap");
        });
        List<String> identities = List.of(administrator, approver, proxy);
        identities.forEach(Permission::requirePrincipal);
        if (new HashSet<>(identities).size() != 3) throw new IllegalArgumentException("Bootstrap identities must differ");
        if (!"fs".equals(configuration.realm().pkiSessionConfiguration().store().backendId())) {
            throw new IllegalArgumentException("Bootstrap requires a filesystem store");
        }
        var authentication = configuration.authentication();
        if (authentication.mode() != AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY
                || !authentication.trustedProxyPrincipalIds().equals(Set.of(proxy))) {
            throw new IllegalArgumentException("Bootstrap requires the selected trusted reverse proxy");
        }
        Set<String> hashes = new HashSet<>();
        for (String identity : identities) {
            var mappings = identity.equals(proxy) ? authentication.proxyTransportMappings()
                    : authentication.forwardedClientMappings();
            var selected = mappings.stream().filter(mapping -> mapping.principalId().equals(identity)).toList();
            if (selected.size() != 1 || selected.getFirst().certificateSha256().isEmpty()
                    || selected.getFirst().subjectPublicKeyInfoSha256().isPresent()
                    || selected.getFirst().issuerSerialSha256().isPresent()
                    || !hashes.add(selected.getFirst().certificateSha256().orElseThrow())) {
                throw new IllegalArgumentException("Each bootstrap identity needs a distinct certificate-only mapping");
            }
        }
        if (authentication.proxyTransportMappings().size() != 1
                || authentication.forwardedClientMappings().size() != 2) {
            throw new IllegalArgumentException("Bootstrap config must map exactly the three initial identities");
        }
        for (ApprovalService.Policy policy : configuration.realm().approvalPolicies().values()) {
            if (!policy.requesterSeparation() || policy.threshold() != 1
                    || !policy.eligibleApprovers().contains(approver) || !policy.eligibleApprovers().contains(administrator)
                    || !policy.requiredRoleTemplateIds().isEmpty()
                    || !Set.of(administrator, approver).containsAll(policy.eligibleApprovers())) {
                throw new IllegalArgumentException("Bootstrap requires independent approval by an initial administrator");
            }
        }
    }

    private static Permission.Grant grant(String id, String principal, Permission.Action action,
            Permission.ResourceType resource, Permission.Scope scope, Permission.DataView view) {
        return new Permission.Grant(id, principal, Permission.Effect.ALLOW, action, resource, scope,
                Permission.Relationship.ANY, view, Set.of(), Optional.empty(), true);
    }
}
