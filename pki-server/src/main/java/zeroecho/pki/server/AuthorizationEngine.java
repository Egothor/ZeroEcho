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

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Deterministic side-effect-free default-deny authorization engine.
 *
 * <p>Evaluation is linear in the number of supplied grants and uses constant
 * auxiliary memory. Callers supply an immutable snapshot of assignments for one
 * decision; the engine never reads persistence or invokes external code.</p>
 */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.FieldDeclarationsShouldBeAtStartOfClass" })
public final class AuthorizationEngine {
    /** Safe decision codes that reveal no protected-object existence. */
    public enum Code {
        ALLOWED, NO_MATCHING_GRANT, EXPLICITLY_DENIED, OUTSIDE_REALM,
        OUTSIDE_AUTHORITY_SCOPE, INSUFFICIENT_DATA_VIEW, APPROVAL_REQUIRED,
        GRANT_EXPIRED, PRINCIPAL_DISABLED, CONDITION_NOT_SATISFIED
    }

    /**
     * One complete authorization input.
     *
     * @param realmId active realm identity
     * @param exposure process authority-exposure policy
     * @param principal authenticated or public principal
     * @param action requested action
     * @param resource exact target reference
     * @param relationship established object relationship
     * @param dataView requested view
     * @param context safe closed-condition context
     * @param grants enabled assignments and grants captured for this decision
     * @param breakGlassGrantIds grant identities originating from active break-glass records
     */
    public record Request(RealmId realmId, AuthorityExposurePolicy exposure, SecurityPrincipal principal,
            Permission.Action action, Permission.Resource resource, Permission.Relationship relationship,
            Permission.DataView dataView, Permission.Context context, List<Permission.Grant> grants,
            java.util.Set<String> breakGlassGrantIds) {
        /** Validates and snapshots the authorization input. */
        public Request {
            Objects.requireNonNull(realmId, "realmId");
            Objects.requireNonNull(exposure, "exposure");
            Objects.requireNonNull(principal, "principal");
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(resource, "resource");
            Objects.requireNonNull(relationship, "relationship");
            Objects.requireNonNull(dataView, "dataView");
            Objects.requireNonNull(context, "context");
            grants = List.copyOf(Objects.requireNonNull(grants, "grants"));
            breakGlassGrantIds = java.util.Set.copyOf(
                    Objects.requireNonNull(breakGlassGrantIds, "breakGlassGrantIds"));
        }
    }

    /**
     * Finite safe authorization result.
     *
     * @param code decision code
     * @param usedBreakGlass whether the allowing grant came from break-glass authority
     */
    public record Decision(Code code, boolean usedBreakGlass) {
        /** Validates result invariants. */
        public Decision {
            Objects.requireNonNull(code, "code");
            if (code != Code.ALLOWED && usedBreakGlass) {
                throw new IllegalArgumentException("Denied decisions cannot report break-glass use");
            }
        }

        /** @return whether execution is authorized */
        public boolean allowed() {
            return code == Code.ALLOWED;
        }
    }

    private final Clock clock;

    /**
     * Creates an engine using an injected authoritative decision clock.
     *
     * @param clock injected clock
     */
    public AuthorizationEngine(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Evaluates one request with explicit-deny precedence.
     *
     * @param request complete immutable input
     * @return safe finite decision
     */
    public Decision authorize(Request request) {
        Request exact = Objects.requireNonNull(request, "request");
        if (!exact.realmId().equals(exact.resource().scope().realmId())) {
            return denied(Code.OUTSIDE_REALM);
        }
        if (!exact.principal().enabled()) {
            return denied(Code.PRINCIPAL_DISABLED);
        }
        if (exact.resource().scope().authorityId().isPresent()
                && !exact.exposure().allows(exact.resource().scope().authorityId().orElseThrow())) {
            return denied(Code.OUTSIDE_AUTHORITY_SCOPE);
        }
        Instant now = clock.instant();
        boolean matchingExpired = false;
        boolean matchingView = false;
        boolean matchingCondition = false;
        boolean approvalMissing = false;
        Permission.Grant allowed = null;
        for (Permission.Grant grant : exact.grants()) {
            if (!basicMatch(exact, grant)) {
                continue;
            }
            if (grant.expiresAt().filter(expiry -> !now.isBefore(expiry)).isPresent()) {
                matchingExpired = true;
                continue;
            }
            if (!grant.dataView().permits(exact.dataView())) {
                matchingView = true;
                continue;
            }
            if (!conditionsMatch(grant, exact)) {
                matchingCondition = true;
                approvalMissing |= grant.conditions().contains(Permission.Condition.APPROVAL_REQUIRED)
                        && !exact.context().approvalPresent();
                continue;
            }
            if (grant.effect() == Permission.Effect.DENY) {
                return denied(Code.EXPLICITLY_DENIED);
            }
            allowed = grant;
        }
        if (allowed != null) {
            return new Decision(Code.ALLOWED, exact.breakGlassGrantIds().contains(allowed.grantId()));
        }
        if (matchingExpired) return denied(Code.GRANT_EXPIRED);
        if (matchingView) return denied(Code.INSUFFICIENT_DATA_VIEW);
        if (approvalMissing) return denied(Code.APPROVAL_REQUIRED);
        if (matchingCondition) return denied(Code.CONDITION_NOT_SATISFIED);
        return denied(Code.NO_MATCHING_GRANT);
    }

    private static boolean basicMatch(Request request, Permission.Grant grant) {
        if (!grant.enabled() || !grant.principalId().equals(request.principal().principalId())
                || grant.action() != request.action() || grant.resourceType() != request.resource().type()
                || !grant.scope().realmId().equals(request.realmId())) {
            return false;
        }
        if (grant.scope().authorityId().isPresent()
                && !grant.scope().authorityId().equals(request.resource().scope().authorityId())) return false;
        if (grant.scope().issuerId().isPresent()
                && !grant.scope().issuerId().equals(request.resource().scope().issuerId())) return false;
        if (grant.scope().profileId().isPresent()
                && !grant.scope().profileId().equals(request.resource().scope().profileId())) return false;
        return grant.relationship() == Permission.Relationship.ANY
                || request.relationship() == Permission.Relationship.OWN
                && request.resource().ownedBy(request.principal());
    }

    private static boolean conditionsMatch(Permission.Grant grant, Request request) {
        for (Permission.Condition condition : grant.conditions()) {
            boolean matches = switch (condition) {
                case REASON_REQUIRED -> request.context().reason().isPresent();
                case APPROVAL_REQUIRED -> request.context().approvalPresent();
                case REQUESTER_APPROVER_SEPARATION -> request.context().safeAttributes()
                        .getOrDefault("requester", "").isBlank()
                        || !request.principal().principalId().equals(
                                request.context().safeAttributes().get("requester"));
                case AUTHORITY_ACTIVE -> request.context().authorityActive();
                case PROFILE_MATCH_REQUIRED -> request.resource().scope().profileId().isPresent();
            };
            if (!matches) return false;
        }
        return true;
    }

    private static Decision denied(Code code) {
        return new Decision(code, false);
    }
}
