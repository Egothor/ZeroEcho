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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.server.DisclosureService;

/**
 * Provides shared operations for the ACME service.
 */
final class AcmeSharedOperations {
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeSharedOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Checks that the published credential matches the account, order and issuance bindings.
     */
    /* default */ void validatePublicationCorrelation(AcmeState.Account account, AcmeState.Order order,
            AcmeState.Directory directory, PkiId credentialId){
        owner.operations.policy.requireAccountDirectory(account, directory);
        if (!account.accountId().equals(order.accountId())) {
            throw new IllegalStateException("ACME publication account binding mismatch");
        }
        owner.operations.policy.validateFrozenOrder(order, directory);
        zeroecho.pki.api.credential.Credential credential = owner.realm.session().repository()
                .credential(credentialId)
                .orElseThrow(() -> new IllegalStateException("ACME publication credential is unavailable"));
        if (!credential.credentialId().equals(credentialId)
                || !credential.issuerRef().caId().equals(order.authorityId())
                || !credential.issuerRef().issuerId().equals(order.issuerId())
                || !credential.issuerRef().chainPathId().equals(order.issuancePathId())
                || !(credential.profileBinding() instanceof EndEntityProfileBinding binding)
                || !binding.reference().equals(order.profile())) {
            throw new IllegalStateException("ACME publication credential correlation differs");
        }
    }

    /**
     * Registers credential publication with the ACME account as its disclosure owner.
     */
    /* default */ void registerPublication(PkiId credentialId, String accountId){
        owner.realm.credentialPublication().register(credentialId,
                Optional.of(DisclosureService.Owner.acmeAccount(accountId)), AcmeService.PUBLICATION_AUDIT_ACTOR);
    }

    /**
     * Returns distinct, ordered identifiers after checking the directory namespace policy.
     */
    /* default */ List<AcmeState.Identifier> canonicalIdentifiers(List<AcmeState.Identifier> requested,
            AcmeState.Directory directory){
        List<AcmeState.Identifier> values = requested.stream()
                .map(value -> new AcmeState.Identifier(value.type(), value.value(), value.wildcard()))
                .distinct().sorted(Comparator.comparing(AcmeState.Identifier::presentation)).toList();
        if (values.isEmpty()) { throw new IllegalArgumentException("ACME identifier count is invalid"); }
        for (AcmeState.Identifier value : values) {
            if (directory.dnsNamespaces().stream().noneMatch(namespace -> value.value().equals(namespace)
                    || value.value().endsWith("." + namespace))) {
                throw new IllegalArgumentException("ACME identifier namespace is rejected");
            }
            if (value.wildcard() && !directory.challengeTypes().contains(AcmeState.ChallengeType.DNS_01)) {
                throw new IllegalArgumentException("Wildcard ACME identifier requires DNS-01");
            }
        }
        return values;
    }

    /**
     * Returns the X.509 binding policies declared by the selected profile.
     */
    /* default */ Set<String> bindingPolicy(ActiveCertificateProfile profile){
        zeroecho.pki.api.profile.X509AlgorithmBindingPolicy policy = profile.definition().algorithmBindingPolicy();
        if (policy.mode() == zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.Mode.STANDARD_ONLY) {
            return Set.of("STANDARD_ONLY");
        }
        return java.util.stream.Stream.of(policy.subjectPublicKey(), policy.csrSignature(),
                policy.certificateSignature(), policy.crlSignature()).flatMap(Optional::stream)
                .map(zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference::bindingId)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    /**
     * Checks that the certification request contains exactly the expected identifiers.
     */
    /* default */ void requireExactIdentifiers(ParsedCertificationRequest parsed, List<AcmeState.Identifier> expected){
        Set<AcmeState.Identifier> actual = new LinkedHashSet<>();
        for (SubjectAlternativeName name : parsed.subjectAlternativeNames()) {
            if (!(name instanceof SubjectAlternativeName.DnsName dns)) { throw new PkiException("ACME CSR contains a non-DNS identifier"); }
            boolean wildcard = dns.value().startsWith("*."); String value = wildcard ? dns.value().substring(2) : dns.value();
            if (!actual.add(new AcmeState.Identifier(AcmeState.IdentifierType.DNS, value, wildcard))) {
                throw new PkiException("ACME CSR contains duplicate identifiers");
            }
        }
        if (!actual.equals(Set.copyOf(expected))) { throw new PkiException("ACME CSR identifiers do not match the order"); }
    }

    /**
     * Returns the retained directory or rejects an unknown identifier.
     */
    /* default */ AcmeState.Directory requireDirectory(String id){ return owner.store.get(AcmeState.Directory.class, id).orElseThrow(() -> new IllegalArgumentException("ACME directory unavailable")); }

    /**
     * Returns the retained account or rejects an unknown identifier.
     */
    /* default */ AcmeState.Account requireAccount(String id){ return owner.store.get(AcmeState.Account.class, id).orElseThrow(() -> new IllegalArgumentException("ACME account unavailable")); }

    /**
     * Returns the retained order or rejects an unknown identifier.
     */
    /* default */ AcmeState.Order requireOrder(String id){ return owner.store.get(AcmeState.Order.class, id).orElseThrow(() -> new IllegalArgumentException("ACME order unavailable")); }

    /**
     * Returns the retained authorization or rejects an unknown identifier.
     */
    /* default */ AcmeState.Authorization requireAuthorization(String id){ return owner.store.get(AcmeState.Authorization.class, id).orElseThrow(() -> new IllegalArgumentException("ACME authorization unavailable")); }

    /**
     * Returns the retained challenge or rejects an unknown identifier.
     */
    /* default */ AcmeState.Challenge requireChallenge(String id){ return owner.store.get(AcmeState.Challenge.class, id).orElseThrow(() -> new IllegalArgumentException("ACME challenge unavailable")); }

    /**
     * Copies the directory with the supplied status and an unsealed commitment.
     */
    /* default */ AcmeState.Directory copyDirectory(AcmeState.Directory v, AcmeState.DirectoryStatus status){ return new AcmeState.Directory(v.directoryId(), v.alias(), v.revision(), v.realmId(), v.authorityId(), v.profile(), v.enrollmentProfileId(), v.issuerId(), v.issuancePathId(), v.issuancePathCommitment(), v.identifierTypes(), v.dnsNamespaces(), v.maximumValidity(), v.publicKeyAlgorithms(), v.x509BindingPolicies(), v.challengeTypes(), v.challengeProviderIds(), v.eabProviderId(), v.eabRequired(), v.confirmationPolicy(), v.confirmationPolicyCommitment(), status, v.policyCommitment(), v.createdAt(), AcmeService.ZERO); }

    /**
     * Copies the order with the supplied state changes and an unsealed commitment.
     */
    /* default */ AcmeState.Order copyOrder(AcmeState.Order v, AcmeState.OrderStatus status, Optional<PkiId> credential){
        return owner.operations.shared.copyOrder(v, status, credential, v.signingOperationId());
    }

    /**
     * Copies the order with the supplied state changes and an unsealed commitment.
     */
    /* default */ AcmeState.Order copyOrder(AcmeState.Order v, AcmeState.OrderStatus status, Optional<PkiId> credential,
            Optional<PkiId> signingOperation){
        return owner.operations.shared.copyOrder(v, status, credential, signingOperation, v.issuanceCommitment());
    }

    /**
     * Copies the order with the supplied state changes and an unsealed commitment.
     */
    /* default */ AcmeState.Order copyOrder(AcmeState.Order v, AcmeState.OrderStatus status, Optional<PkiId> credential,
            Optional<PkiId> signingOperation, Optional<String> issuanceCommitment){ return new AcmeState.Order(v.orderId(), v.accountId(), v.directoryId(), v.directoryRevision(), v.directoryPolicyCommitment(), v.authorityId(), v.profile(), v.issuerId(), v.issuancePathId(), v.issuancePathCommitment(), v.identifiers(), v.notBefore(), v.notAfter(), status, v.authorizationIds(), credential, issuanceCommitment, signingOperation, v.createdAt(), v.expiresAt(), AcmeService.ZERO); }

    /**
     * Creates a prefixed identifier containing 128 random bits in hexadecimal form.
     */
    /* default */ String id(String prefix){ byte[] value = new byte[16]; owner.random.nextBytes(value); return prefix + ":" + HexFormat.of().formatHex(value); }

    /**
     * Creates an unpadded Base64url token containing 256 random bits.
     */
    /* default */ String token(){ byte[] value = new byte[32]; owner.random.nextBytes(value); String result = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value); java.util.Arrays.fill(value, (byte) 0); return result; }

    /**
     * Submits an ACME transport audit event to the realm.
     */
    /* default */ void audit(String action, String actor, Map<String, String> details){
        owner.realm.auditTransport(action, actor, details);
    }

    /**
     * Requests an advisory reconciliation wake without propagating callback failures.
     */
    // Retains the established safe diagnostic or standalone monitor boundary.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    /* default */ void signalReconciliation(){
        try {
            owner.reconciliationWake.run();
        } catch (RuntimeException ignored) {
            // Periodic reconciliation remains authoritative after a failed advisory wake.
        }
    }

    /**
     * Returns the hexadecimal SHA-256 digest of the UTF-8 text.
     */
    /* default */ String digest(String value){ try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); } }

    /**
     * Returns the hexadecimal SHA-256 digest of the supplied bytes.
     */
    /* default */ String digestBytes(byte[] value){ try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); } }

    /**
     * Converts a hexadecimal key commitment to an unpadded Base64url thumbprint.
     */
    /* default */ String accountKeyAuthorizationThumbprint(String commitment){
        byte[] digest = HexFormat.of().parseHex(commitment);
        try {
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } finally {
            java.util.Arrays.fill(digest, (byte) 0);
        }
    }
}
