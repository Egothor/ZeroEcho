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

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, separately versioned enrollment resource and credential configuration.
 * No capability or resource budget is enabled implicitly. Certificate paths name
 * single DER certificates, and encrypted keyring paths must already exist.
 *
 * @param budgets explicit transaction admission limits
 * @param keyrings dedicated encrypted keyring owners
 * @param credentialSets immutable, authority-scoped current and retained credentials
 * @param activeCredentials unique selections for new protocol transactions
 * @param keygenArtifacts optional encrypted delivery artifact capability
 */
public record EnrollmentRuntimeConfiguration(Budgets budgets, List<Keyring> keyrings,
        List<CredentialSet> credentialSets, List<ActiveCredential> activeCredentials,
        Optional<KeygenArtifacts> keygenArtifacts) {
    /** Current companion configuration version; independent of server schema 8. */
    public static final int VERSION = 1;

    /** Validates bounded collections and every cross-reference. */
    public EnrollmentRuntimeConfiguration {
        Objects.requireNonNull(budgets, "budgets");
        keyrings = copy(keyrings, 32);
        credentialSets = copy(credentialSets, 256);
        activeCredentials = copy(activeCredentials, 256);
        keygenArtifacts = Objects.requireNonNull(keygenArtifacts, "keygenArtifacts");
        unique(keyrings.stream().map(Keyring::id).toList());
        unique(keyrings.stream().map(value -> value.path().toString()).toList());
        unique(credentialSets.stream().map(CredentialSet::credentialId).toList());
        unique(activeCredentials.stream().map(value -> value.protocol() + ":" + value.authorityId()).toList());
        Set<String> ringIds = Set.copyOf(keyrings.stream().map(Keyring::id).toList());
        for (CredentialSet set : credentialSets) {
            set.signer().ifPresent(value -> requireRing(ringIds, value.key()));
            set.pbm().ifPresent(value -> value.identities().forEach(identity -> requireRing(ringIds, identity.secret())));
        }
        for (ActiveCredential active : activeCredentials) {
            if (credentialSets.stream().noneMatch(set -> set.credentialId().equals(active.credentialId())
                    && set.protocol() == active.protocol() && set.authorityId().equals(active.authorityId()))) {
                throw new IllegalArgumentException("Enrollment active credential reference is invalid");
            }
        }
    }

    /** Protocols requiring explicitly provisioned message credentials. */
    public enum Protocol {
        /** EST server-generated private-key delivery signature. */ EST,
        /** SCEP RA encryption and response signature. */ SCEP,
        /** CMP signature or password-based message protection. */ CMP
    }

    /**
     * Explicit transaction budgets, including terminal replay records.
     * @param maximumTransactions retained transactions including tombstones, 1..1000000
     * @param maximumPending pending transactions, at most the retained count
     * @param maximumRetainedRequestBytes retained original bytes plus serialized metadata
     *        and reserved bounded decision/receipt/result growth
     * @param maximumRequestBytes one encoded request, 1..1048576 bytes
     * @param maximumConcurrentDispatches concurrent dispatches, 1..1024
     * @param pendingLifetime fixed admission lifetime, at most 30 days
     * @param retryAfter polling interval, at most the pending lifetime
     */
    public record Budgets(int maximumTransactions, int maximumPending, long maximumRetainedRequestBytes,
            int maximumRequestBytes, int maximumConcurrentDispatches, Duration pendingLifetime, Duration retryAfter) {
        /** Validates exact positive budgets and their relationships. */
        public Budgets {
            range(maximumTransactions, 1, 1_000_000);
            range(maximumPending, 1, maximumTransactions);
            range(maximumRequestBytes, 1, 1_048_576);
            range(maximumRetainedRequestBytes, maximumRequestBytes, 1L << 40);
            range(maximumConcurrentDispatches, 1, Math.min(1024, maximumPending));
            duration(pendingLifetime, Duration.ofDays(30));
            duration(retryAfter, pendingLifetime);
        }
    }

    /**
     * Dedicated, preprovisioned encrypted keyring.
     * @param id configuration-local canonical identity
     * @param path absolute normalized existing keyring file
     */
    public record Keyring(String id, Path path) {
        /** Validates the identity and normalizes the path without opening it. */
        public Keyring { EnrollmentRuntimeConfiguration.id(id); path = EnrollmentRuntimeConfiguration.path(path); }
    }

    /**
     * Reference to existing material in a configured encrypted keyring.
     * @param keyringId exact configured keyring identity
     * @param alias exact logical keyring alias
     */
    public record KeyReference(String keyringId, String alias) {
        /** Validates both canonical references. */
        public KeyReference { id(keyringId); id(alias); }
    }

    /**
     * Response signer with a leaf-to-anchor DER certificate chain.
     * The leaf must be delegated directly by the selected authority generation.
     * @param key private key reference
     * @param certificateChain leaf followed by the exact repository authority path
     */
    public record Signer(KeyReference key, List<Path> certificateChain) {
        /** Validates the reference and bounded nonempty chain. */
        public Signer {
            Objects.requireNonNull(key, "key");
            certificateChain = paths(certificateChain, 33, false);
        }
    }

    /**
     * One CMP PBM requester, isolated to this credential set and authority.
     * Owner aliases exclude known administrators from approving their own request;
     * they never grant an authentication or authorization privilege.
     * @param senderKid canonical lowercase hexadecimal identifier, 1..128 bytes
     * @param identityId canonical requester identity
     * @param secret encrypted keyring reference to 32..128 secret bytes
     * @param ownerAliases explicit nonempty administrative owner exclusions
     */
    public record PbmIdentity(String senderKid, String identityId, KeyReference secret, List<String> ownerAliases) {
        /** Validates bounded identity and exclusion fields. */
        public PbmIdentity {
            if (senderKid == null || !senderKid.matches("(?:[0-9a-f]{2}){1,128}")) {
                invalid();
            }
            id(identityId);
            Objects.requireNonNull(secret, "secret");
            ownerAliases = copy(ownerAliases, 128).stream().sorted().toList();
            if (ownerAliases.isEmpty()) {
                invalid();
            }
            ownerAliases.forEach(EnrollmentRuntimeConfiguration::id);
            unique(ownerAliases);
        }
        @Override public String toString() { return "PbmIdentity[redacted]"; }
    }

    /** Explicitly supported PBM digest families. */
    public enum PbmDigest {
        /** SHA-256. */ SHA256,
        /** SHA-384. */ SHA384,
        /** SHA-512. */ SHA512
    }

    /** Explicitly supported PBM MAC families. */
    public enum PbmMac {
        /** HMAC with SHA-256. */ HMAC_SHA256,
        /** HMAC with SHA-384. */ HMAC_SHA384,
        /** HMAC with SHA-512. */ HMAC_SHA512
    }

    /**
     * Explicit CMP PBM work, salt and algorithm limits. A message must satisfy
     * these limits before any iterative derivation is attempted.
     * @param minimumIterations positive iteration floor
     * @param maximumIterations iteration ceiling, at most 1000000
     * @param minimumSaltBytes salt floor, at least 16 bytes
     * @param maximumSaltBytes salt ceiling, at most 64 bytes
     * @param digests nonempty allowed digest families
     * @param macs nonempty allowed MAC families
     * @param identities nonempty unique sender and requester mappings
     */
    public record Pbm(int minimumIterations, int maximumIterations, int minimumSaltBytes, int maximumSaltBytes,
            Set<PbmDigest> digests, Set<PbmMac> macs, List<PbmIdentity> identities) {
        /** Validates resource limits and independent requester mappings. */
        public Pbm {
            range(maximumIterations, 1, 1_000_000);
            range(minimumIterations, 1, maximumIterations);
            range(maximumSaltBytes, 16, 64);
            range(minimumSaltBytes, 16, maximumSaltBytes);
            digests = Set.copyOf(digests);
            macs = Set.copyOf(macs);
            if (digests.isEmpty() || macs.isEmpty()) {
                invalid();
            }
            identities = copy(identities, 256);
            if (identities.isEmpty()) {
                invalid();
            }
            unique(identities.stream().map(PbmIdentity::senderKid).toList());
            unique(identities.stream().map(PbmIdentity::identityId).toList());
        }
        @Override public String toString() { return "Pbm[redacted]"; }
    }

    /**
     * Immutable authority-scoped protocol credentials. Changing any retained set
     * requires a new credential identity; active selection can then move to it.
     * @param credentialId stable immutable credential-set identity
     * @param protocol protocol family
     * @param authorityId logical issuing authority
     * @param issuerId exact retained issuer generation
     * @param chainPathId exact retained authority chain
     * @param signer optional response signer, mandatory for EST and SCEP
     * @param requestTrustAnchors explicit CMP request signature trust anchors
     * @param authorizedRaKeys canonical public-key commitments allowed RA privileges
     * @param pbm optional CMP password-based protection configuration
     */
    public record CredentialSet(String credentialId, Protocol protocol, String authorityId,
            String issuerId, String chainPathId, Optional<Signer> signer, List<Path> requestTrustAnchors,
            List<String> authorizedRaKeys, Optional<Pbm> pbm) {
        /** Validates the closed protocol capability combination. */
        public CredentialSet {
            id(credentialId); id(authorityId); id(issuerId); id(chainPathId);
            Objects.requireNonNull(protocol, "protocol");
            signer = Objects.requireNonNull(signer, "signer");
            pbm = Objects.requireNonNull(pbm, "pbm");
            requestTrustAnchors = paths(requestTrustAnchors, 32, true);
            authorizedRaKeys = copy(authorizedRaKeys, 256).stream().sorted().toList();
            unique(authorizedRaKeys);
            for (String value : authorizedRaKeys) {
                if (!value.matches("[0-9a-f]{64}")) {
                    invalid();
                }
            }
            if ((protocol == Protocol.EST || protocol == Protocol.SCEP) && (signer.isEmpty() || pbm.isPresent()
                    || !requestTrustAnchors.isEmpty() || !authorizedRaKeys.isEmpty())) {
                invalid();
            }
            if (protocol == Protocol.CMP && (signer.isPresent() != !requestTrustAnchors.isEmpty()
                    || signer.isEmpty() && pbm.isEmpty()
                    || signer.isEmpty() && !authorizedRaKeys.isEmpty())) {
                invalid();
            }
        }
        @Override public String toString() { return "CredentialSet[redacted]"; }
    }

    /**
     * Selection for newly admitted transactions; retained transactions keep their ID.
     * @param protocol protocol family
     * @param authorityId exact authority scope
     * @param credentialId configured immutable set identity
     */
    public record ActiveCredential(Protocol protocol, String authorityId, String credentialId) {
        /** Validates the selection identities. */
        public ActiveCredential { Objects.requireNonNull(protocol, "protocol"); id(authorityId); id(credentialId); }
    }

    /**
     * Optional client-encrypted server-keygen delivery storage. No plaintext key
     * persistence is authorized by this capability.
     * @param directory preprovisioned exclusive artifact directory
     * @param maximumArtifactBytes maximum ciphertext bytes per artifact
     * @param maximumRetainedBytes aggregate reserved ciphertext bytes
     * @param maximumArtifacts maximum retained artifact descriptors
     * @param maximumConcurrentGenerations maximum active generation jobs
     * @param deliveryRetention fixed delivery retention, at most 30 days
     */
    public record KeygenArtifacts(Path directory, long maximumArtifactBytes, long maximumRetainedBytes,
            int maximumArtifacts, int maximumConcurrentGenerations, Duration deliveryRetention) {
        /** Validates all explicit artifact budgets. */
        public KeygenArtifacts {
            directory = path(directory);
            range(maximumArtifactBytes, 1, 16_777_216);
            range(maximumRetainedBytes, maximumArtifactBytes, 1L << 40);
            range(maximumArtifacts, 1, 1_000_000);
            range(maximumConcurrentGenerations, 1, Math.min(maximumArtifacts, 1024));
            duration(deliveryRetention, Duration.ofDays(30));
        }
    }

    /**
     * Reads a bounded strict UTF-8 companion document.
     * @param path document path
     * @return immutable validated configuration
     * @throws IOException if reading fails
     * @throws IllegalArgumentException if the document is invalid
     */
    public static EnrollmentRuntimeConfiguration read(Path path) throws IOException {
        return EnrollmentRuntimeConfigurationCodec.read(path);
    }

    /**
     * Decodes a closed version-one JSON document, at most 1 MiB.
     * @param bytes exact UTF-8 document
     * @return immutable validated configuration
     * @throws IllegalArgumentException if the document is invalid
     */
    public static EnrollmentRuntimeConfiguration decode(byte[] bytes) {
        return EnrollmentRuntimeConfigurationCodec.decode(bytes);
    }

    @Override public String toString() { return "EnrollmentRuntimeConfiguration[redacted]"; }

    /* default */ static void id(String value) { EnrollmentEndpoint.requireProfileId(value); }
    private static void requireRing(Set<String> rings, KeyReference reference) {
        if (!rings.contains(reference.keyringId())) {
            invalid();
        }
    }
    private static Path path(Path value) {
        Path result = Objects.requireNonNull(value, "path").toAbsolutePath().normalize();
        if (result.getParent() == null || result.toString().length() > 4096) {
            invalid();
        }
        return result;
    }
    private static List<Path> paths(List<Path> values, int maximum, boolean allowEmpty) {
        List<Path> result = copy(values, maximum).stream().map(EnrollmentRuntimeConfiguration::path).toList();
        if (!allowEmpty && result.isEmpty()) {
            invalid();
        }
        unique(result);
        return result;
    }
    private static <T> List<T> copy(List<T> values, int maximum) {
        List<T> result = List.copyOf(values);
        if (result.size() > maximum) {
            invalid();
        }
        return result;
    }
    private static void unique(List<?> values) {
        if (new HashSet<>(values).size() != values.size()) {
            invalid();
        }
    }
    private static void range(long value, long minimum, long maximum) {
        if (value < minimum || value > maximum) {
            invalid();
        }
    }
    private static void duration(Duration value, Duration maximum) {
        Objects.requireNonNull(value, "duration");
        if (value.isZero() || value.isNegative() || value.getNano() != 0 || value.compareTo(maximum) > 0) {
            invalid();
        }
    }
    private static void invalid() { throw new IllegalArgumentException("Invalid enrollment runtime configuration"); }
}
