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

package zeroecho.pki.server.enrollment;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import zeroecho.pki.server.AdministrativeAuthenticationMode;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.RealmId;

/**
 * Conservative, exclusion-only aliases derived from configured end-client
 * credential commitments. A matching certificate, supported equivalent SPKI or
 * issuer/serial coordinate excludes its principal even when other mapping
 * coordinates differ or that principal is disabled. Authentication continues to
 * require every configured coordinate and its existing uniqueness rules.
 *
 * <p>Hash-only certificate mappings cannot reveal that an unseen different
 * certificate contains the same key. This helper makes no such inference.
 * Canonical requester/decider key comparisons remain a separate necessary check.
 * Instances contain one immutable realm configuration and are thread-safe.</p>
 */
public final class EnrollmentIdentityAliases {
    private static final int MAXIMUM_PRINCIPAL_ALIASES = 20_000;
    private final RealmId realmId;
    private final List<PkiServerConfiguration.ClientCertificateMapping> mappings;

    /**
     * Selects only end-client mappings for the configured administrative topology.
     * Proxy transport mappings can never contribute end-client aliases.
     * @param realmId exact realm
     * @param authentication immutable authentication configuration
     */
    public EnrollmentIdentityAliases(RealmId realmId, PkiServerConfiguration.Authentication authentication) {
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        Objects.requireNonNull(authentication, "authentication");
        mappings = authentication.mode() == AdministrativeAuthenticationMode.DIRECT_MTLS
                ? authentication.directClientMappings() : authentication.forwardedClientMappings();
    }

    /**
     * Collects every known alias without principal-state or authorization lookups.
     * Time is O(M log A), retained memory O(A), for at most 10,000 configured
     * mappings M and distinct aliases A. No identity relationship grants access.
     * @param evidence verified requester evidence for this realm
     * @return immutable realm-bound exclusion snapshot, including disabled aliases
     * @throws IllegalArgumentException if the evidence belongs to another realm
     */
    public Snapshot knownAliases(CertificateIdentityEvidence evidence) {
        Objects.requireNonNull(evidence, "evidence");
        if (!realmId.equals(evidence.realmId())) {
            throw new IllegalArgumentException("Alias evidence realm differs");
        }
        SortedSet<String> aliases = new TreeSet<>();
        for (PkiServerConfiguration.ClientCertificateMapping mapping : mappings) {
            if (mapping.certificateSha256().filter(evidence.certificateSha256()::equals).isPresent()
                    || mapping.subjectPublicKeyInfoSha256().filter(evidence.legacySpkiSha256()::contains).isPresent()
                    || mapping.issuerSerialSha256().filter(evidence.issuerSerialSha256()::equals).isPresent()) {
                aliases.add(mapping.principalId());
            }
        }
        return new Snapshot(realmId, aliases);
    }

    /**
     * Finds exclusion-only aliases for an authenticated account key that has no
     * client certificate. Only the finite validated equivalent SPKI hashes are
     * compared; certificate-only mappings cannot reveal this relationship.
     * @param identity independently validated mathematical account key
     * @return every configured key alias in this realm, including disabled aliases
     */
    public Snapshot knownKeyAliases(zeroecho.pkix.PublicKeyIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        return knownKeyHashes(identity.equivalentSubjectPublicKeyInfoSha256());
    }

    /* default */ Snapshot knownKeyHashes(Set<String> hashes) {
        SortedSet<String> aliases = new TreeSet<>();
        for (PkiServerConfiguration.ClientCertificateMapping mapping : mappings) {
            if (mapping.subjectPublicKeyInfoSha256().filter(hashes::contains).isPresent()) {
                aliases.add(mapping.principalId());
            }
        }
        return new Snapshot(realmId, aliases);
    }

    /**
     * Immutable sorted aliases bound to one realm; at most 20,000 entries permits
     * union of one frozen and one current configuration snapshot.
     * @param realmId exact realm owning these principal names
     * @param principalIds exclusion-only principal names
     */
    public record Snapshot(RealmId realmId, Set<String> principalIds) {
        /** Validates and snapshots the bounded alias set in O(A log A) time and O(A) memory. */
        public Snapshot {
            Objects.requireNonNull(realmId, "realmId");
            Objects.requireNonNull(principalIds, "principalIds");
            if (principalIds.size() > MAXIMUM_PRINCIPAL_ALIASES) {
                throw new IllegalArgumentException("Alias snapshot exceeds its bound");
            }
            for (String principal : principalIds) {
                if (principal == null || !principal.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
                    throw new IllegalArgumentException("Alias principal is invalid");
                }
            }
            principalIds = Collections.unmodifiableSortedSet(new TreeSet<>(principalIds));
        }

        /**
         * Retains frozen exclusions and adds current mappings without removing
         * aliases whose mapping or enabled state changed after admission.
         * @param current current configuration aliases for the same realm
         * @return immutable union
         * @throws IllegalArgumentException if realms differ or the union exceeds its bound
         */
        public Snapshot union(Snapshot current) {
            Objects.requireNonNull(current, "current");
            if (!realmId.equals(current.realmId)) {
                throw new IllegalArgumentException("Alias snapshot realms differ");
            }
            SortedSet<String> union = new TreeSet<>(principalIds);
            union.addAll(current.principalIds);
            return new Snapshot(realmId, union);
        }

        /** @return redacted diagnostic description */
        @Override public String toString() { return "EnrollmentIdentityAliases.Snapshot[redacted]"; }
    }
}
