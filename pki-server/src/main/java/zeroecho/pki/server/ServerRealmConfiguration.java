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

import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;

import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;
import zeroecho.pki.spi.store.MetadataStoreId;

/**
 * Immutable transport-neutral configuration for one server realm.
 *
 * <p>The realm identity and server-control identity are explicit values and are
 * never derived from paths, listeners, display names, or Java types. Provider
 * configuration values may contain sensitive references and must not be logged
 * or rendered.</p>
 *
 * @param realmId canonical realm identity
 * @param displayName safe finite administrative display name
 * @param confirmationProofPolicy immutable credential-confirmation proof policy
 * @param pkiSessionConfiguration shared PKI session configuration
 * @param authorityExposure explicit process authority-exposure policy
 * @param authorizationCommitment SHA-256 commitment to authorization configuration
 * @param approvalCommitment SHA-256 commitment to the HIGH_RISK approval policy
 * @param extendedApprovalCommitment SHA-256 commitment to all non-HIGH_RISK approval policies
 * @param disclosureCommitment SHA-256 commitment to disclosure defaults
 * @param disclosureDefaults safe object-disclosure defaults
 * @param controlLogPath dedicated server-control metadata log
 * @param controlStoreId explicit durable server-control identity
 * @param approvalPolicies closed approval policies by operation category
 */
public record ServerRealmConfiguration(RealmId realmId, String displayName,
        CredentialConfirmationProofPolicy confirmationProofPolicy,
        PkiSessionConfiguration pkiSessionConfiguration, AuthorityExposurePolicy authorityExposure,
        String authorizationCommitment, String approvalCommitment, String extendedApprovalCommitment,
        String disclosureCommitment,
        DisclosureService.Defaults disclosureDefaults, Path controlLogPath, MetadataStoreId controlStoreId,
        Map<ApprovalCategory, ApprovalService.Policy> approvalPolicies) {

    /** Validates and snapshots the complete configuration before allocation. */
    public ServerRealmConfiguration {
        Objects.requireNonNull(realmId, "realmId");
        Permission.requireBounded(displayName, 256, "realm display name");
        Objects.requireNonNull(confirmationProofPolicy, "confirmationProofPolicy");
        Objects.requireNonNull(pkiSessionConfiguration, "pkiSessionConfiguration");
        Objects.requireNonNull(authorityExposure, "authorityExposure");
        requireDigest(authorizationCommitment, "authorization commitment");
        requireDigest(approvalCommitment, "approval commitment");
        requireDigest(extendedApprovalCommitment, "extended approval commitment");
        requireDigest(disclosureCommitment, "disclosure commitment");
        Objects.requireNonNull(disclosureDefaults, "disclosureDefaults");
        controlLogPath = Objects.requireNonNull(controlLogPath, "controlLogPath").toAbsolutePath().normalize();
        if (controlLogPath.getParent() == null) {
            throw new IllegalArgumentException("Server-control log requires a parent directory");
        }
        Objects.requireNonNull(controlStoreId, "controlStoreId");
        approvalPolicies = Map.copyOf(Objects.requireNonNull(approvalPolicies, "approvalPolicies"));
        ApprovalService.Policy highRisk = approvalPolicies.get(ApprovalCategory.HIGH_RISK);
        if (highRisk == null || !highRisk.commitment().equals(approvalCommitment)) {
            throw new IllegalArgumentException("High-risk approval policy commitment is inconsistent");
        }
        if (approvalPolicies.containsKey(ApprovalCategory.NONE)) {
            throw new IllegalArgumentException("Ordinary operations cannot have an implicit approval policy");
        }
        ApprovalService.Policy issuanceSingle = approvalPolicies.get(ApprovalCategory.ISSUANCE_SINGLE);
        if (issuanceSingle != null && issuanceSingle.threshold() != 1) {
            throw new IllegalArgumentException("Single-approval issuance policy must require exactly one approval");
        }
        ApprovalService.Policy issuanceThreshold = approvalPolicies.get(ApprovalCategory.ISSUANCE_THRESHOLD);
        if (issuanceThreshold != null && issuanceThreshold.threshold() < 2) {
            throw new IllegalArgumentException(
                    "Threshold-approval issuance policy must require at least two approvals");
        }
        if (!extendedApprovalCommitment(approvalPolicies).equals(extendedApprovalCommitment)) {
            throw new IllegalArgumentException("Extended approval policy commitment is inconsistent");
        }
    }

    /**
     * Computes the canonical tamper-evidence commitment over every approval policy other than
     * {@link ApprovalCategory#HIGH_RISK} (which the durable record commits separately).
     *
     * <p>The commitment is a SHA-256 digest over the category-name-sorted map of
     * {@code CATEGORY=policyCommitment} entries, so any future approval category is absorbed by the
     * same single field without a durable-record format change. An empty map yields the digest of the
     * empty string.</p>
     *
     * @param approvalPolicies closed approval policies by operation category
     * @return canonical extended approval commitment
     */
    public static String extendedApprovalCommitment(
            Map<ApprovalCategory, ApprovalService.Policy> approvalPolicies) {
        StringBuilder canonical = new StringBuilder();
        approvalPolicies.entrySet().stream()
                .filter(entry -> entry.getKey() != ApprovalCategory.HIGH_RISK
                        && entry.getKey() != ApprovalCategory.NONE)
                .sorted(Map.Entry.comparingByKey(Comparator.comparing(Enum::name)))
                .forEach(entry -> {
                    if (canonical.length() > 0) {
                        canonical.append(';');
                    }
                    canonical.append(entry.getKey().name()).append('=').append(entry.getValue().commitment());
                });
        return ApprovalService.digest(canonical.toString());
    }

    private static void requireDigest(String value, String name) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }
}
