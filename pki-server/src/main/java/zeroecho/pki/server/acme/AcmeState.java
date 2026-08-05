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
package zeroecho.pki.server.acme;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.server.DisclosureService;
import zeroecho.pki.server.RealmId;

/**
 * Closed durable ACME domain records.
 *
 * <p>Protocol URLs are never state authority. Every relationship is represented
 * by a canonical identity and every mutable record carries a complete SHA-256
 * commitment used for compare-and-set persistence.</p>
 */
@SuppressWarnings("PMD")
public final class AcmeState {
    /** Supported identifier kinds. */
    public enum IdentifierType { DNS }
    /** Supported proof challenges. */
    public enum ChallengeType { HTTP_01, DNS_01 }
    /** Directory lifecycle. */
    public enum DirectoryStatus { INACTIVE, ACTIVE }
    /** Account lifecycle. */
    public enum AccountStatus { VALID, DEACTIVATED, REVOKED }
    /** Order lifecycle. */
    public enum OrderStatus { PENDING, READY, PROCESSING, VALID, INVALID }
    /** Authorization lifecycle. */
    public enum AuthorizationStatus { PENDING, VALID, INVALID, EXPIRED, DEACTIVATED }
    /** Challenge lifecycle. */
    public enum ChallengeStatus { PENDING, PROCESSING, VALID, INVALID }
    /** Durable validation result. */
    public enum EvidenceResult { VALID, INVALID }

    /** One canonical DNS identifier with an explicit wildcard bit. */
    public record Identifier(IdentifierType type, String value, boolean wildcard) {
        /** Validates the canonical lower-case ASCII DNS representation. */
        public Identifier {
            Objects.requireNonNull(type, "type");
            value = Objects.requireNonNull(value, "value");
            if (!value.equals(value.toLowerCase(java.util.Locale.ROOT)) || value.length() > 253
                    || value.startsWith(".") || value.endsWith(".")) {
                throw new IllegalArgumentException("ACME DNS identifier is not canonical");
            }
            String[] labels = value.split("\\.", -1);
            for (String label : labels) {
                if (label.isEmpty() || label.length() > 63 || !label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
                    throw new IllegalArgumentException("ACME DNS label is invalid");
                }
            }
        }

        /** Returns the ACME presentation form. */
        public String presentation() { return wildcard ? "*." + value : value; }
    }

    /** Immutable directory policy revision bound to one exact PKI authority. */
    public record Directory(String directoryId, String alias, int revision, RealmId realmId,
            PkiId authorityId, CertificateProfileRef profile, PkiId issuerId, PkiId issuancePathId,
            String issuancePathCommitment, Set<IdentifierType> identifierTypes, Set<String> dnsNamespaces,
            Duration maximumValidity, Set<String> publicKeyAlgorithms, Set<String> x509BindingPolicies,
            Set<ChallengeType> challengeTypes, Set<String> challengeProviderIds,
            Optional<String> eabProviderId, boolean eabRequired, DisclosureService.Policy disclosurePolicy,
            DirectoryStatus status, String policyCommitment, Instant createdAt, String commitment) {
        /** Validates the complete frozen directory revision. */
        public Directory {
            id(directoryId); AcmeState.alias(alias); positive(revision, "directory revision");
            Objects.requireNonNull(realmId, "realmId"); Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(profile, "profile"); Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(issuancePathId, "issuancePathId"); digest(issuancePathCommitment);
            identifierTypes = nonEmpty(identifierTypes, "identifier types");
            dnsNamespaces = nonEmptyStrings(dnsNamespaces, "DNS namespaces");
            if (!identifierTypes.equals(Set.of(IdentifierType.DNS))) {
                throw new IllegalArgumentException("Only DNS ACME identifiers are supported");
            }
            positive(maximumValidity, Duration.ofDays(398), "maximum validity");
            publicKeyAlgorithms = nonEmptyStrings(publicKeyAlgorithms, "public-key algorithms");
            x509BindingPolicies = nonEmptyStrings(x509BindingPolicies, "X.509 binding policies");
            challengeTypes = nonEmpty(challengeTypes, "challenge types");
            challengeProviderIds = nonEmptyStrings(challengeProviderIds, "challenge providers");
            eabProviderId = Objects.requireNonNull(eabProviderId, "eabProviderId");
            eabProviderId.ifPresent(AcmeState::id);
            if (eabRequired && eabProviderId.isEmpty()) {
                throw new IllegalArgumentException("ACME EAB policy is contradictory");
            }
            Objects.requireNonNull(disclosurePolicy, "disclosurePolicy");
            Objects.requireNonNull(status, "status"); digest(policyCommitment);
            Objects.requireNonNull(createdAt, "createdAt"); digest(commitment);
        }
    }

    /** Durable protocol-scoped ACME account. */
    public record Account(String accountId, String directoryId, int directoryRevision,
            String directoryCommitment, String keyThumbprint, byte[] publicKeySpki,
            AccountStatus status, List<String> contacts, boolean termsAgreed,
            Optional<String> eabPolicyCommitment, Instant createdAt, Instant updatedAt, String commitment) {
        /** Validates account identity, bounded public material, PII and commitments. */
        public Account {
            id(accountId); id(directoryId); positive(directoryRevision, "directory revision");
            digest(directoryCommitment); digest(keyThumbprint);
            publicKeySpki = Objects.requireNonNull(publicKeySpki, "publicKeySpki").clone();
            if (publicKeySpki.length < 32 || publicKeySpki.length > 16_384) {
                throw new IllegalArgumentException("ACME account public key bound is invalid");
            }
            Objects.requireNonNull(status, "status");
            contacts = List.copyOf(Objects.requireNonNull(contacts, "contacts"));
            if (contacts.size() > 16 || contacts.stream().anyMatch(value -> value.length() > 512
                    || !value.startsWith("mailto:") || value.indexOf('@') < 8)) {
                throw new IllegalArgumentException("ACME account contact is invalid");
            }
            eabPolicyCommitment = Objects.requireNonNull(eabPolicyCommitment, "eabPolicyCommitment");
            eabPolicyCommitment.ifPresent(AcmeState::digest);
            Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(updatedAt, "updatedAt");
            digest(commitment);
        }
        @Override public byte[] publicKeySpki() { return publicKeySpki.clone(); }
    }

    /** Durable ACME order frozen to one directory revision and issuance selection. */
    public record Order(String orderId, String accountId, String directoryId, int directoryRevision,
            String directoryCommitment, PkiId authorityId, CertificateProfileRef profile,
            PkiId issuerId, PkiId issuancePathId, String issuancePathCommitment,
            List<Identifier> identifiers, Optional<Instant> notBefore, Optional<Instant> notAfter,
            OrderStatus status, List<String> authorizationIds, Optional<PkiId> credentialId,
            Instant createdAt, Instant expiresAt, String commitment) {
        /** Validates exact policy and object bindings. */
        public Order {
            id(orderId); id(accountId); id(directoryId); positive(directoryRevision, "directory revision");
            digest(directoryCommitment); Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(profile, "profile"); Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(issuancePathId, "issuancePathId"); digest(issuancePathCommitment);
            identifiers = distinctIdentifiers(identifiers);
            notBefore = Objects.requireNonNull(notBefore, "notBefore");
            notAfter = Objects.requireNonNull(notAfter, "notAfter");
            if (notBefore.isPresent() != notAfter.isPresent()
                    || notBefore.isPresent() && !notAfter.orElseThrow().isAfter(notBefore.orElseThrow())) {
                throw new IllegalArgumentException("ACME order validity is invalid");
            }
            Objects.requireNonNull(status, "status");
            authorizationIds = distinctIds(authorizationIds, identifiers.size(), "authorization");
            credentialId = Objects.requireNonNull(credentialId, "credentialId");
            if ((status == OrderStatus.VALID) != credentialId.isPresent()) {
                throw new IllegalArgumentException("ACME order credential state mismatch");
            }
            Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(expiresAt, "expiresAt");
            if (!expiresAt.isAfter(createdAt)) throw new IllegalArgumentException("ACME order expiry is invalid");
            digest(commitment);
        }
    }

    /** Durable identifier authorization owned by one account order. */
    public record Authorization(String authorizationId, String orderId, String accountId,
            Identifier identifier, AuthorizationStatus status, List<String> challengeIds,
            Instant expiresAt, Optional<String> evidenceId, String commitment) {
        /** Validates exact ownership and evidence state. */
        public Authorization {
            id(authorizationId); id(orderId); id(accountId); Objects.requireNonNull(identifier, "identifier");
            Objects.requireNonNull(status, "status");
            challengeIds = distinctIds(challengeIds, 16, "challenge");
            Objects.requireNonNull(expiresAt, "expiresAt");
            evidenceId = Objects.requireNonNull(evidenceId, "evidenceId"); evidenceId.ifPresent(AcmeState::id);
            if ((status == AuthorizationStatus.VALID) != evidenceId.isPresent()) {
                throw new IllegalArgumentException("ACME authorization evidence state mismatch");
            }
            digest(commitment);
        }
    }

    /** Durable explicitly triggered challenge attempt. */
    public record Challenge(String challengeId, String authorizationId, ChallengeType type,
            String token, ChallengeStatus status, String providerId, int attempt,
            Optional<String> failureCode, Optional<String> evidenceId,
            Instant createdAt, Instant updatedAt, String commitment) {
        /** Validates token, provider, monotonic attempt and state. */
        public Challenge {
            id(challengeId); id(authorizationId); Objects.requireNonNull(type, "type");
            if (token == null || !token.matches("[A-Za-z0-9_-]{43,128}")) {
                throw new IllegalArgumentException("ACME challenge token is invalid");
            }
            Objects.requireNonNull(status, "status"); id(providerId);
            if (attempt < 0) throw new IllegalArgumentException("ACME challenge attempt is invalid");
            failureCode = Objects.requireNonNull(failureCode, "failureCode");
            failureCode.ifPresent(value -> { if (!value.matches("[A-Z0-9_]{1,64}")) throw new IllegalArgumentException("ACME failure code is invalid"); });
            evidenceId = Objects.requireNonNull(evidenceId, "evidenceId"); evidenceId.ifPresent(AcmeState::id);
            if ((status == ChallengeStatus.VALID) != evidenceId.isPresent()) {
                throw new IllegalArgumentException("ACME challenge evidence state mismatch");
            }
            Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(updatedAt, "updatedAt");
            digest(commitment);
        }
    }

    /** Immutable validator evidence; no control operation may construct it. */
    public record AuthorizationEvidence(String evidenceId, String authorizationId, String providerId,
            ChallengeType challengeType, Identifier identifier, String accountKeyCommitment,
            String keyAuthorizationCommitment, String directoryPolicyCommitment, int attempt,
            Instant validatedAt, Instant expiresAt, EvidenceResult result,
            Optional<String> failureCode, String commitment) {
        /** Validates complete authorization-evidence binding. */
        public AuthorizationEvidence {
            id(evidenceId); id(authorizationId); id(providerId); Objects.requireNonNull(challengeType, "challengeType");
            Objects.requireNonNull(identifier, "identifier"); digest(accountKeyCommitment);
            digest(keyAuthorizationCommitment); digest(directoryPolicyCommitment);
            positive(attempt, "validation attempt"); Objects.requireNonNull(validatedAt, "validatedAt");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (!expiresAt.isAfter(validatedAt)) throw new IllegalArgumentException("ACME evidence expiry is invalid");
            Objects.requireNonNull(result, "result");
            failureCode = Objects.requireNonNull(failureCode, "failureCode");
            if ((result == EvidenceResult.INVALID) != failureCode.isPresent()) {
                throw new IllegalArgumentException("ACME evidence result classification mismatch");
            }
            digest(commitment);
        }
    }

    private AcmeState() { }

    private static void id(String value) {
        if (value == null || !value.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException("ACME identity is invalid");
        }
    }
    private static void alias(String value) {
        if (value == null || !value.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
            throw new IllegalArgumentException("ACME directory alias is invalid");
        }
    }
    private static void digest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("ACME commitment is invalid");
        }
    }
    private static void positive(int value, String name) {
        if (value <= 0) throw new IllegalArgumentException(name + " is invalid");
    }
    private static void positive(Duration value, Duration maximum, String name) {
        if (value == null || value.isZero() || value.isNegative() || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }
    private static <T> Set<T> nonEmpty(Set<T> source, String name) {
        Set<T> result = Set.copyOf(Objects.requireNonNull(source, name));
        if (result.isEmpty() || result.size() > 64) throw new IllegalArgumentException(name + " is invalid");
        return result;
    }
    private static Set<String> nonEmptyStrings(Set<String> source, String name) {
        Set<String> result = nonEmpty(source, name);
        result.forEach(value -> { if (value.isBlank() || value.length() > 256) throw new IllegalArgumentException(name + " is invalid"); });
        return result;
    }
    private static List<Identifier> distinctIdentifiers(List<Identifier> source) {
        List<Identifier> result = List.copyOf(Objects.requireNonNull(source, "identifiers"));
        if (result.isEmpty() || result.stream().distinct().count() != result.size()) {
            throw new IllegalArgumentException("ACME identifiers are invalid");
        }
        return result;
    }
    private static List<String> distinctIds(List<String> source, int maximum, String name) {
        List<String> result = List.copyOf(Objects.requireNonNull(source, name));
        result.forEach(AcmeState::id);
        if (result.isEmpty() || result.size() > maximum || result.stream().distinct().count() != result.size()) {
            throw new IllegalArgumentException("ACME " + name + " identities are invalid");
        }
        return result;
    }
}
