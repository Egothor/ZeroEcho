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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.profile.CertificateProfileRef;
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
    public enum IdentifierType {
        /** Domain Name System identifier. */ DNS
    }
    /** Supported proof challenges. */
    public enum ChallengeType {
        /** HTTP token-file validation. */ HTTP_01,
        /** DNS TXT-record validation. */ DNS_01
    }
    /** Directory lifecycle. */
    public enum DirectoryStatus {
        /** Directory exists but does not accept protocol operations. */ INACTIVE,
        /** Directory accepts protocol operations. */ ACTIVE
    }
    /** Account lifecycle. */
    public enum AccountStatus {
        /** Account may perform protocol operations. */ VALID,
        /** Account was voluntarily deactivated. */ DEACTIVATED,
        /** Account authority was revoked. */ REVOKED
    }
    /** Order lifecycle. */
    public enum OrderStatus {
        /** Order awaits successful identifier authorization. */ PENDING,
        /** Order is authorized and ready for finalization. */ READY,
        /** Finalization and issuance are in progress. */ PROCESSING,
        /** Order completed with an issued credential. */ VALID,
        /** Order cannot complete successfully. */ INVALID
    }
    /** Authorization lifecycle. */
    public enum AuthorizationStatus {
        /** Authorization awaits challenge validation. */ PENDING,
        /** Authorization has current validation evidence. */ VALID,
        /** Authorization validation failed terminally. */ INVALID,
        /** Authorization evidence expired. */ EXPIRED,
        /** Authorization was administratively deactivated. */ DEACTIVATED
    }
    /** Challenge lifecycle. */
    public enum ChallengeStatus {
        /** Challenge awaits an explicit trigger. */ PENDING,
        /** Challenge validation is in progress. */ PROCESSING,
        /** Challenge validation succeeded. */ VALID,
        /** Challenge validation failed. */ INVALID
    }
    /** Durable validation result. */
    public enum EvidenceResult {
        /** Validator proved the authorization. */ VALID,
        /** Validator rejected the authorization. */ INVALID
    }

    /**
     * One canonical DNS identifier with an explicit wildcard bit.
     *
     * @param type identifier type
     * @param value canonical lowercase ASCII value without wildcard prefix
     * @param wildcard whether the presentation represents the wildcard subdomain
     */
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

        /**
         * Returns the ACME presentation form.
         *
         * @return canonical value, prefixed with {@code *.} when wildcard
         */
        public String presentation() { return wildcard ? "*." + value : value; }
    }

    /**
     * Immutable directory policy revision bound to one exact PKI authority.
     *
     * @param directoryId stable directory identifier
     * @param alias unique public directory alias
     * @param revision positive policy revision
     * @param realmId owning security realm
     * @param authorityId exact logical authority
     * @param profile frozen certificate profile reference
     * @param enrollmentProfileId mandatory enrollment admission policy identity
     * @param issuerId exact issuer generation
     * @param issuancePathId exact issuance chain path
     * @param issuancePathCommitment expected chain-path commitment
     * @param identifierTypes accepted identifier types
     * @param dnsNamespaces permitted DNS namespace suffixes
     * @param maximumValidity maximum issued credential validity
     * @param publicKeyAlgorithms accepted public-key algorithm identifiers
     * @param x509BindingPolicies accepted X.509 binding-policy identifiers
     * @param challengeTypes enabled proof challenge types
     * @param challengeProviderIds enabled challenge-provider identifiers
     * @param eabProviderId optional external-account-binding provider
     * @param eabRequired whether new accounts require external account binding
     * @param confirmationPolicy credential-confirmation policy
     * @param confirmationPolicyCommitment expected confirmation-policy commitment
     * @param status directory lifecycle state
     * @param policyCommitment commitment to protocol policy
     * @param createdAt server-authoritative creation time
     * @param commitment commitment to the complete record
     */
    public record Directory(String directoryId, String alias, int revision, RealmId realmId,
            PkiId authorityId, CertificateProfileRef profile, String enrollmentProfileId, PkiId issuerId, PkiId issuancePathId,
            String issuancePathCommitment, Set<IdentifierType> identifierTypes, Set<String> dnsNamespaces,
            Duration maximumValidity, Set<String> publicKeyAlgorithms, Set<String> x509BindingPolicies,
            Set<ChallengeType> challengeTypes, Set<String> challengeProviderIds,
            Optional<String> eabProviderId, boolean eabRequired,
            CredentialConfirmationPolicy confirmationPolicy, String confirmationPolicyCommitment,
            DirectoryStatus status, String policyCommitment, Instant createdAt, String commitment) {
        /** Validates the complete frozen directory revision. */
        public Directory {
            id(directoryId); AcmeState.alias(alias); positive(revision, "directory revision");
            Objects.requireNonNull(realmId, "realmId"); Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(profile, "profile"); Objects.requireNonNull(issuerId, "issuerId");
            zeroecho.pki.server.enrollment.EnrollmentEndpoint.requireProfileId(enrollmentProfileId);
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
            Objects.requireNonNull(confirmationPolicy, "confirmationPolicy");
            digest(confirmationPolicyCommitment);
            if (!confirmationPolicy.configurationCommitment().equals(confirmationPolicyCommitment)) {
                throw new IllegalArgumentException("ACME confirmation policy commitment differs");
            }
            Objects.requireNonNull(status, "status"); digest(policyCommitment);
            Objects.requireNonNull(createdAt, "createdAt"); digest(commitment);
        }
    }

    /**
     * Durable protocol-scoped ACME account.
     *
     * @param accountId stable account identifier
     * @param directoryId owning directory identifier
     * @param directoryRevision frozen directory revision
     * @param directoryPolicyCommitment frozen directory-policy commitment
     * @param keyThumbprint SHA-256 account-key thumbprint
     * @param publicKeySpki canonical account public-key encoding
     * @param status account lifecycle state
     * @param contacts bounded account contact URIs
     * @param termsAgreed whether the subscriber agreed to current terms
     * @param eabPolicyCommitment optional external-account-binding policy commitment
     * @param createdAt server-authoritative creation time
     * @param updatedAt server-authoritative last-update time
     * @param commitment commitment to the complete account record
     * @param keyHistory append-only authenticated key identities and known administrative exclusions
     */
    public record Account(String accountId, String directoryId, int directoryRevision,
            String directoryPolicyCommitment, String keyThumbprint, byte[] publicKeySpki,
            AccountStatus status, List<String> contacts, boolean termsAgreed,
            Optional<String> eabPolicyCommitment, Instant createdAt, Instant updatedAt, String commitment,
            List<AccountKeyIdentity> keyHistory) {
        /** Validates account identity, bounded public material, PII and commitments. */
        public Account {
            id(accountId); id(directoryId); positive(directoryRevision, "directory revision");
            digest(directoryPolicyCommitment); digest(keyThumbprint);
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
            keyHistory = List.copyOf(Objects.requireNonNull(keyHistory, "keyHistory"));
            if (keyHistory.isEmpty() || keyHistory.size() > 256) throw new IllegalArgumentException("ACME key history bound is invalid");
            java.util.HashSet<String> identities = new java.util.HashSet<>();
            for (AccountKeyIdentity key : keyHistory) {
                if (!identities.add(key.canonicalSha256())) throw new IllegalArgumentException("ACME key history contains duplicate keys");
            }
            zeroecho.pkix.PublicKeyIdentity current = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(publicKeySpki);
            if (keyHistory.stream().noneMatch(key -> key.canonicalSha256().equals(current.canonicalSha256())
                    && key.legacySpkiSha256().equals(current.equivalentSubjectPublicKeyInfoSha256()))) {
                throw new IllegalArgumentException("ACME current key is absent from its history");
            }
        }

        /**
         * Creates an account with its initial validated key identity. The enrollment
         * authority adds configured exclusion aliases before durable creation.
         * @param accountId account identity
         * @param directoryId owning directory identity
         * @param directoryRevision exact directory revision
         * @param directoryPolicyCommitment frozen directory policy
         * @param keyThumbprint authenticated JWK thumbprint
         * @param publicKeySpki validated account public key
         * @param status account status
         * @param contacts bounded contacts
         * @param termsAgreed terms acceptance
         * @param eabPolicyCommitment optional external binding commitment
         * @param createdAt creation time
         * @param updatedAt update time
         * @param commitment complete record commitment
         */
        public Account(String accountId, String directoryId, int directoryRevision, String directoryPolicyCommitment,
                String keyThumbprint, byte[] publicKeySpki, AccountStatus status, List<String> contacts, boolean termsAgreed,
                Optional<String> eabPolicyCommitment, Instant createdAt, Instant updatedAt, String commitment) {
            this(accountId, directoryId, directoryRevision, directoryPolicyCommitment, keyThumbprint, publicKeySpki,
                    status, contacts, termsAgreed, eabPolicyCommitment, createdAt, updatedAt, commitment,
                    List.of(AccountKeyIdentity.fromKey(publicKeySpki, Set.of())));
        }
        /**
         * Returns the account public key.
         *
         * @return defensive copy of canonical subject-public-key information
         */
        @Override public byte[] publicKeySpki() { return publicKeySpki.clone(); }
    }

    /**
     * Exclusion-only evidence for one authenticated account key, retained across
     * rollover. Neither this record nor an alias grants authentication authority.
     * @param canonicalSha256 mathematical public-key commitment
     * @param legacySpkiSha256 finite supported equivalent SPKI commitments
     * @param aliases known administrative principal exclusions at observation time
     */
    public record AccountKeyIdentity(String canonicalSha256, Set<String> legacySpkiSha256, Set<String> aliases) {
        /** Validates immutable bounded public commitments and aliases. */
        public AccountKeyIdentity {
            digest(canonicalSha256);
            legacySpkiSha256 = Set.copyOf(Objects.requireNonNull(legacySpkiSha256, "legacySpkiSha256"));
            if (legacySpkiSha256.isEmpty() || legacySpkiSha256.size() > 3) throw new IllegalArgumentException("ACME key encoding bound is invalid");
            legacySpkiSha256.forEach(AcmeState::digest);
            aliases = Set.copyOf(Objects.requireNonNull(aliases, "aliases"));
            if (aliases.size() > 20_000) throw new IllegalArgumentException("ACME key alias bound is invalid");
            aliases.forEach(AcmeState::id);
        }

        /**
         * Derives supported canonical commitments from validated public-key material.
         * @param spki exact public key
         * @param aliases exclusion-only aliases
         * @return immutable key identity
         */
        public static AccountKeyIdentity fromKey(byte[] spki, Set<String> aliases) {
            zeroecho.pkix.PublicKeyIdentity identity = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(spki);
            return new AccountKeyIdentity(identity.canonicalSha256(), identity.equivalentSubjectPublicKeyInfoSha256(), aliases);
        }

        @Override public String toString() { return "AcmeState.AccountKeyIdentity[redacted]"; }
    }

    /**
     * Durable ACME order frozen to one directory revision and issuance selection.
     *
     * @param orderId stable order identifier
     * @param accountId owning account identifier
     * @param directoryId owning directory identifier
     * @param directoryRevision frozen directory revision
     * @param directoryPolicyCommitment frozen directory-policy commitment
     * @param authorityId exact logical authority
     * @param profile frozen certificate profile reference
     * @param issuerId exact issuer generation
     * @param issuancePathId exact issuance chain path
     * @param issuancePathCommitment expected chain-path commitment
     * @param identifiers distinct ordered requested identifiers
     * @param notBefore optional requested validity start
     * @param notAfter optional requested validity end, present with {@code notBefore}
     * @param status order lifecycle state
     * @param authorizationIds authorization identifiers corresponding to requested identifiers
     * @param credentialId issued credential identifier, present exactly for a valid order
     * @param issuanceCommitment optional frozen issuance-input commitment
     * @param signingOperationId optional durable signing operation identifier
     * @param createdAt server-authoritative creation time
     * @param expiresAt order expiration time
     * @param commitment commitment to the complete order record
     */
    public record Order(String orderId, String accountId, String directoryId, int directoryRevision,
            String directoryPolicyCommitment, PkiId authorityId, CertificateProfileRef profile,
            PkiId issuerId, PkiId issuancePathId, String issuancePathCommitment,
            List<Identifier> identifiers, Optional<Instant> notBefore, Optional<Instant> notAfter,
            OrderStatus status, List<String> authorizationIds, Optional<PkiId> credentialId,
            Optional<String> issuanceCommitment, Optional<PkiId> signingOperationId,
            Instant createdAt, Instant expiresAt, String commitment) {
        /** Validates exact policy and object bindings. */
        public Order {
            id(orderId); id(accountId); id(directoryId); positive(directoryRevision, "directory revision");
            digest(directoryPolicyCommitment); Objects.requireNonNull(authorityId, "authorityId");
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
            issuanceCommitment = Objects.requireNonNull(issuanceCommitment, "issuanceCommitment");
            issuanceCommitment.ifPresent(AcmeState::digest);
            signingOperationId = Objects.requireNonNull(signingOperationId, "signingOperationId");
            if ((status == OrderStatus.VALID) != credentialId.isPresent()) {
                throw new IllegalArgumentException("ACME order credential state mismatch");
            }
            if (signingOperationId.isPresent() && issuanceCommitment.isEmpty()
                    || status == OrderStatus.PROCESSING && issuanceCommitment.isEmpty()) {
                throw new IllegalArgumentException("ACME order lacks its durable issuance binding");
            }
            Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(expiresAt, "expiresAt");
            if (!expiresAt.isAfter(createdAt)) throw new IllegalArgumentException("ACME order expiry is invalid");
            digest(commitment);
        }
    }

    /**
     * Durable identifier authorization owned by one account order.
     *
     * @param authorizationId stable authorization identifier
     * @param orderId owning order identifier
     * @param accountId owning account identifier
     * @param identifier exact identifier being authorized
     * @param status authorization lifecycle state
     * @param challengeIds available challenge identifiers
     * @param expiresAt authorization expiration time
     * @param evidenceId validator evidence identifier, present exactly when valid
     * @param commitment commitment to the complete authorization record
     */
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

    /**
     * Durable explicitly triggered challenge attempt.
     *
     * @param challengeId stable challenge identifier
     * @param authorizationId owning authorization identifier
     * @param type challenge type
     * @param token unpredictable ACME challenge token
     * @param status challenge lifecycle state
     * @param providerId selected validator provider
     * @param attempt nonnegative attempt number
     * @param failureCode optional stable safe failure classification
     * @param evidenceId validator evidence identifier, present exactly when valid
     * @param createdAt server-authoritative creation time
     * @param updatedAt server-authoritative last-update time
     * @param commitment commitment to the complete challenge record
     */
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

    /**
     * Immutable validator evidence; no control operation may construct it.
     *
     * @param evidenceId stable evidence identifier
     * @param authorizationId authorized identifier record
     * @param providerId validator provider identifier
     * @param challengeType validated challenge type
     * @param identifier exact validated identifier
     * @param accountKeyCommitment account-key commitment used in validation
     * @param keyAuthorizationCommitment derived key-authorization commitment
     * @param directoryPolicyCommitment frozen directory-policy commitment
     * @param attempt positive challenge attempt
     * @param validatedAt server-authoritative validation time
     * @param expiresAt evidence expiration time
     * @param result validator result
     * @param failureCode safe failure classification, present exactly when invalid
     * @param commitment commitment to the complete evidence record
     */
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
