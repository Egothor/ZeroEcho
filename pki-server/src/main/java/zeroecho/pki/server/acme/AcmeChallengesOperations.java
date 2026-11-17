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
package zeroecho.pki.server.acme;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.server.jfr.AcmeChallengeEvent;

/**
 * Provides challenges operations for the ACME service.
 */
final class AcmeChallengesOperations {
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeChallengesOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Validates a challenge using its configured provider and updates the retained challenge
     * state.
     */
    // Retains the established safe diagnostic or standalone monitor boundary.
    @SuppressWarnings({ "PMD.AvoidSynchronizedStatement", "PMD.AvoidCatchingGenericException" })
    /* default */ AcmeState.Challenge validateChallenge(String accountId, String expectedAccountCommitment,
            String challengeId, String accountKeyThumbprint, Instant deadline, CancellationSignal cancellation){
        AcmeState.Challenge current; AcmeState.Authorization authorization;
        synchronized (owner) {
            owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment);
            current = owner.operations.shared.requireChallenge(challengeId); authorization = owner.operations.shared.requireAuthorization(current.authorizationId());
            if (!authorization.accountId().equals(accountId)) { throw new IllegalArgumentException("ACME challenge unavailable"); }
            if (current.status() == AcmeState.ChallengeStatus.VALID) { return current; }
            if (current.status() == AcmeState.ChallengeStatus.PROCESSING) { throw new IllegalStateException("ACME challenge is processing"); }
            current = (AcmeState.Challenge) owner.store.replace(List.of(new AcmeControlStore.Replacement(current,
                    new AcmeState.Challenge(current.challengeId(), current.authorizationId(), current.type(),
                            current.token(), AcmeState.ChallengeStatus.PROCESSING, current.providerId(),
                            Math.addExact(current.attempt(), 1), Optional.empty(), Optional.empty(),
                            current.createdAt(), owner.clock.instant(), AcmeService.ZERO)))).get(0);
        }
        AcmeState.Order order = owner.operations.shared.requireOrder(authorization.orderId());
        AcmeState.Directory directory = owner.operations.shared.requireDirectory(order.directoryId());
        owner.operations.policy.validateFrozenOrder(order, directory);
        String keyAuthorization = current.token() + "." + owner.operations.shared.accountKeyAuthorizationThumbprint(accountKeyThumbprint);
        AcmeChallengeProvider provider = owner.providers.get(current.providerId());
        AcmeChallengeEvent jfrChallenge = new AcmeChallengeEvent();
        jfrChallenge.challengeType = current.type().name();
        jfrChallenge.identifier = authorization.identifier().value();
        jfrChallenge.begin();
        AcmeChallengeProvider.Result result = null;
        try {
            result = provider.validate(new AcmeChallengeProvider.Context(directory.directoryId(),
                    authorization.authorizationId(), authorization.identifier(), current.type(), current.token(),
                    keyAuthorization, current.attempt(), owner.clock.instant(), deadline),
                    owner.providerConfigurations.get(provider.id()), cancellation);
        } catch (RuntimeException failure) {
            result = new AcmeChallengeProvider.Result(false, "PROVIDER_FAILURE", owner.clock.instant(), owner.clock.instant().plus(Duration.ofMinutes(5)));
        } finally {
            if (jfrChallenge.shouldCommit() && result != null) {
                jfrChallenge.succeeded = result.valid();
                if (!result.valid()) {
                    jfrChallenge.failureReason = result.classification();
                }
                jfrChallenge.commit();
            }
        }
        if (cancellation.isCancelled()) { throw new IllegalStateException("ACME validation was cancelled"); }
        return owner.operations.challenges.completeChallenge(current, authorization, order, directory, accountId, expectedAccountCommitment,
                accountKeyThumbprint, keyAuthorization, result);
    }

    /**
     * Returns an authorization belonging to the supplied account.
     */
    /* default */ AcmeState.Authorization authorization(String accountId, String authorizationId){
        AcmeState.Authorization value = owner.operations.shared.requireAuthorization(authorizationId);
        if (!value.accountId().equals(accountId)) { throw new IllegalArgumentException("ACME authorization unavailable"); }
        return value;
    }

    /**
     * Returns a challenge belonging to the supplied account.
     */
    /* default */ AcmeState.Challenge challenge(String accountId, String challengeId){
        AcmeState.Challenge value = owner.operations.shared.requireChallenge(challengeId);
        owner.authorization(accountId, value.authorizationId());
        return value;
    }

    /**
     * Records a challenge result and updates the associated authorization and order.
     */
    // Retains the established safe diagnostic or standalone monitor boundary.
    @SuppressWarnings({ "PMD.AvoidSynchronizedStatement" })
    /* default */ AcmeState.Challenge completeChallenge(AcmeState.Challenge claimed,
            AcmeState.Authorization authorization, AcmeState.Order order, AcmeState.Directory directory,
            String accountId, String expectedAccountCommitment, String accountKey, String keyAuthorization,
            AcmeChallengeProvider.Result result){ synchronized (owner) {
        owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Challenge current = owner.operations.shared.requireChallenge(claimed.challengeId());
        if (!current.commitment().equals(claimed.commitment()) || current.status() != AcmeState.ChallengeStatus.PROCESSING) {
            throw new IllegalStateException("ACME challenge attempt changed");
        }
        String evidenceId = owner.operations.shared.id("evidence"); Instant observed = result.observedAt();
        AcmeState.AuthorizationEvidence evidence = challengeEvidence(evidenceId, authorization, current, directory, accountKey, keyAuthorization, result, observed);
        AcmeState.Challenge updatedChallenge = completedChallenge(current, evidence, result);
        AcmeState.Authorization updatedAuthorization = completedAuthorization(authorization, evidence, result);
        AcmeState.OrderStatus orderStatus = completedOrderStatus(order, authorization, result);
        AcmeState.Order updatedOrder = owner.operations.shared.copyOrder(order, orderStatus, Optional.empty());
        AcmeControlStore.Transition transition = owner.store.transition(List.of(new AcmeControlStore.Replacement(current, updatedChallenge),
                new AcmeControlStore.Replacement(authorization, updatedAuthorization),
                new AcmeControlStore.Replacement(order, updatedOrder)), List.of(evidence));
        owner.operations.shared.audit("ACME_CHALLENGE_RESULT", authorization.accountId(), Map.of("challenge", current.challengeId(),
                "outcome", result.valid() ? "VALID" : "INVALID"));
        return (AcmeState.Challenge) transition.replaced().get(0);
    } }

    /**
     * Tests whether every other authorization for the order is valid.
     */
    /* default */ boolean allOtherAuthorizationsValid(AcmeState.Order order, String currentId){
        return order.authorizationIds().stream().filter(id -> !id.equals(currentId))
                .map(owner.operations.shared::requireAuthorization).allMatch(value -> value.status() == AcmeState.AuthorizationStatus.VALID);
    }

    private AcmeState.AuthorizationEvidence challengeEvidence(String evidenceId, AcmeState.Authorization authorization, AcmeState.Challenge current, AcmeState.Directory directory, String accountKey, String keyAuthorization, AcmeChallengeProvider.Result result, Instant observed) {
        return new AcmeState.AuthorizationEvidence(evidenceId,
                authorization.authorizationId(), current.providerId(), current.type(), authorization.identifier(),
                owner.operations.shared.digest(accountKey), owner.operations.shared.digest(keyAuthorization), directory.policyCommitment(), current.attempt(), observed,
                result.expiresAt(), result.valid() ? AcmeState.EvidenceResult.VALID : AcmeState.EvidenceResult.INVALID,
                result.valid() ? Optional.empty() : Optional.of(result.classification()), AcmeService.ZERO);
    }

    private AcmeState.Challenge completedChallenge(AcmeState.Challenge current, AcmeState.AuthorizationEvidence evidence, AcmeChallengeProvider.Result result) {
        return new AcmeState.Challenge(current.challengeId(), current.authorizationId(),
                current.type(), current.token(), result.valid() ? AcmeState.ChallengeStatus.VALID : AcmeState.ChallengeStatus.INVALID,
                current.providerId(), current.attempt(), result.valid() ? Optional.empty() : Optional.of(result.classification()),
                result.valid() ? Optional.of(evidence.evidenceId()) : Optional.empty(), current.createdAt(), owner.clock.instant(), AcmeService.ZERO);
    }

    private AcmeState.Authorization completedAuthorization(AcmeState.Authorization authorization, AcmeState.AuthorizationEvidence evidence, AcmeChallengeProvider.Result result) {
        return new AcmeState.Authorization(authorization.authorizationId(),
                authorization.orderId(), authorization.accountId(), authorization.identifier(),
                result.valid() ? AcmeState.AuthorizationStatus.VALID : AcmeState.AuthorizationStatus.INVALID,
                authorization.challengeIds(), authorization.expiresAt(),
                result.valid() ? Optional.of(evidence.evidenceId()) : Optional.empty(), AcmeService.ZERO);
    }

    private AcmeState.OrderStatus completedOrderStatus(AcmeState.Order order, AcmeState.Authorization authorization, AcmeChallengeProvider.Result result) {
        return result.valid() && owner.operations.challenges.allOtherAuthorizationsValid(order, authorization.authorizationId())
                ? AcmeState.OrderStatus.READY : result.valid() ? AcmeState.OrderStatus.PENDING : AcmeState.OrderStatus.INVALID;
    }

}
