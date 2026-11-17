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
package zeroecho.pki.server.http;

import zeroecho.pki.server.AuthorizationEngine;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;

import java.util.Optional;

/**
 * Authorizes access to retained signing scope before returning operation observations.
 */
final class AdminSigningObservation {
    private final PkiServerConfiguration configuration;
    private final ServerRealmContext realm;

    /* default */ AdminSigningObservation(
            PkiServerConfiguration configuration, ServerRealmContext realm) {
        this.configuration = configuration;
        this.realm = realm;
    }

    /* default */ HttpResponses.Response observe(
            String requestId, String principalId, String signingId) {
        try {
            zeroecho.pki.api.SemanticSigningService service =
                    realm.session().semanticSigning().orElseThrow();
            zeroecho.pki.api.signing.SemanticSigningOperation snapshot =
                    service.find(new zeroecho.pki.api.PkiId(signingId)).orElseThrow();
            zeroecho.pki.api.signing.SemanticSigningScope scope = snapshot.scope();
            PollScope poll = pollScope(scope);
            Permission.Resource resource =
                    new Permission.Resource(
                            poll.type(),
                            new Permission.Scope(
                                    configuration.realm().realmId(),
                                    poll.authority(),
                                    Optional.empty(),
                                    poll.profile()),
                            poll.object(),
                            Optional.empty());
            AuthorizationEngine.Decision decision =
                    realm.gateway()
                            .authorizeControl(
                                    principalId,
                                    poll.action(),
                                    resource,
                                    Permission.Context.empty(),
                                    requestId);
            if (!decision.allowed()) {
                return HttpResponses.signingNotFound(requestId);
            }
            return HttpResponses.signingOperation(requestId, signingOutcome(snapshot));
        } catch (IllegalArgumentException | java.util.NoSuchElementException unavailable) {
            return HttpResponses.signingNotFound(requestId);
        }
    }

    private static PollScope pollScope(zeroecho.pki.api.signing.SemanticSigningScope scope) {
        return switch (scope.kind()) {
            case ISSUANCE ->
                    new PollScope(
                            Permission.Action.CERTIFICATE_ISSUE,
                            Permission.ResourceType.CERTIFICATE,
                            scope.authorityId(),
                            scope.profileId(),
                            Optional.empty());
            case STATUS ->
                    new PollScope(
                            Permission.Action.CRL_GENERATE,
                            Permission.ResourceType.STATUS_OBJECT,
                            scope.authorityId(),
                            Optional.empty(),
                            Optional.empty());
            case KEY_PROOF ->
                    throw new IllegalArgumentException("Signing operation is not exposed");
            case CA ->
                    switch (scope.operation()) {
                        case "CREATE_ROOT" ->
                                new PollScope(
                                        Permission.Action.AUTHORITY_CREATE,
                                        Permission.ResourceType.AUTHORITY,
                                        Optional.empty(),
                                        Optional.empty(),
                                        Optional.empty());
                        case "CREATE_INTERMEDIATE" ->
                                new PollScope(
                                        Permission.Action.AUTHORITY_CREATE,
                                        Permission.ResourceType.AUTHORITY,
                                        scope.authorityId(),
                                        scope.profileId(),
                                        scope.subjectAuthorityId());
                        case "ISSUE_INTERMEDIATE" ->
                                new PollScope(
                                        Permission.Action.ISSUER_CREATE,
                                        Permission.ResourceType.ISSUER,
                                        scope.subjectAuthorityId(),
                                        scope.profileId(),
                                        Optional.empty());
                        case "ROLLOVER_ROOT" ->
                                new PollScope(
                                        Permission.Action.AUTHORITY_READ,
                                        Permission.ResourceType.AUTHORITY,
                                        scope.authorityId(),
                                        scope.profileId(),
                                        scope.authorityId());
                        case "ROLLOVER_INTERMEDIATE" ->
                                new PollScope(
                                        Permission.Action.AUTHORITY_READ,
                                        Permission.ResourceType.AUTHORITY,
                                        scope.subjectAuthorityId(),
                                        scope.profileId(),
                                        scope.subjectAuthorityId());
                        default ->
                                throw new IllegalArgumentException(
                                        "Signing operation is not exposed");
                    };
        };
    }

    private zeroecho.pki.application.PkiOperationOutcome signingOutcome(
            zeroecho.pki.api.signing.SemanticSigningOperation snapshot) {
        String name = "signing.operation";
        return switch (snapshot.state()) {
            case SIGNING, PUBLISHING ->
                    new zeroecho.pki.application.PkiOperationOutcome.Pending(
                            name, snapshot.submissionId().id());
            case FAILED ->
                    new zeroecho.pki.application.PkiOperationOutcome.Failed(
                            name,
                            zeroecho.pki.application.PkiOperationFailure.POLICY_REJECTION,
                            snapshot.detailCode().orElse("SIGNING_FAILED"));
            case EXPIRED ->
                    new zeroecho.pki.application.PkiOperationOutcome.Failed(
                            name,
                            zeroecho.pki.application.PkiOperationFailure.CANCELLED,
                            "SIGNING_EXPIRED");
            case COMPLETED ->
                    new zeroecho.pki.application.PkiOperationOutcome.Completed(
                            realm.session()
                                    .signingCommands()
                                    .orElseThrow()
                                    .completedResult(snapshot));
        };
    }

    private record PollScope(
            Permission.Action action,
            Permission.ResourceType type,
            Optional<zeroecho.pki.api.PkiId> authority,
            Optional<String> profile,
            Optional<zeroecho.pki.api.PkiId> object) {}
}
