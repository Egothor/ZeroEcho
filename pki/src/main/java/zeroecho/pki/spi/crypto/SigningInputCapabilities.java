/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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

package zeroecho.pki.spi.crypto;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Base64;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;

/**
 * Immutable, thread-safe input contract for a configured signing provider.
 * Exact advertised prehash mappings always take precedence over raw input.
 * Construction takes O(A log A) time and O(A) space; selection takes expected
 * O(1) time. No selected mode needs to be persisted separately.
 */
public final class SigningInputCapabilities {
    private static final int MAX_PREHASH_ID_LENGTH = 512;
    // The supported SHA-2 digest/PSS tuples are flat. This syntax-only guard
    // prevents the general identity codec from recursively decoding nested
    // parameter expressions; requiredDigest remains the semantic authority.
    private static final Pattern PREHASH_PARAMETERS = Pattern.compile(
            "(?:digest=zeroecho\\.sha2-(?:256|384|512)\\.none"
            + "|hash=zeroecho\\.sha2-(?:256|384|512)\\.none,mask=zeroecho\\.mgf1\\.none,"
            + "maskhash=zeroecho\\.sha2-(?:256|384|512)\\.none,salt=(?:0|[1-9][0-9]{0,9}),trailer=1)");
    /** Version of the explicit raw/prehashed input protocol. */
    public static final int PROTOCOL_VERSION = 2;
    /** Maximum number of advertised algorithm identities. */
    public static final int MAXIMUM_ALGORITHMS = 1024;
    /** Current remote client's inclusive raw input ceiling. */
    public static final long REMOTE_RAW_LIMIT = 16L * 1024 * 1024;

    /** Meaning of the transmitted signing input. */
    public enum Mode {
        /** Original message bytes. */
        RAW_MESSAGE,
        /** Exact algorithm digest, without another message hashing step. */
        PREHASHED_DIGEST
    }

    private final long rawMessageMaximum;
    private final Map<String, AlgorithmIdentity> prehashedDigests;

    /**
     * Creates a finite capability contract. Empty messages are valid; the
     * inclusive raw maximum itself must be positive.
     *
     * @param rawMessageMaximum inclusive positive raw length maximum
     * @param prehashedDigests canonical signature identity to exact digest
     * @throws IllegalArgumentException for unsafe, noncanonical or excessive mappings
     */
    public SigningInputCapabilities(long rawMessageMaximum, Map<String, AlgorithmIdentity> prehashedDigests) {
        if (rawMessageMaximum <= 0) {
            throw new IllegalArgumentException("Raw signing limit must be positive");
        }
        Objects.requireNonNull(prehashedDigests, "prehashedDigests");
        if (prehashedDigests.size() > MAXIMUM_ALGORITHMS) {
            throw new IllegalArgumentException("Too many prehashed signing algorithms");
        }
        for (Map.Entry<String, AlgorithmIdentity> entry : prehashedDigests.entrySet()) {
            requireIdentityBound(entry.getKey());
            requireShallowPrehashParameters(entry.getKey());
            AlgorithmIdentity signature = AlgorithmIdentity.parse(entry.getKey(), List.of());
            if (!requiredDigest(signature).equals(entry.getValue())) {
                throw new IllegalArgumentException("Prehashed digest differs from exact signature identity");
            }
        }
        this.rawMessageMaximum = rawMessageMaximum;
        this.prehashedDigests = Map.copyOf(prehashedDigests);
    }

    /** {@return inclusive positive raw-message maximum} */
    public long rawMessageMaximum() { return rawMessageMaximum; }

    /** {@return immutable exact canonical signature-to-digest mappings} */
    public Map<String, AlgorithmIdentity> prehashedDigests() { return prehashedDigests; }

    /**
     * Selects prehash whenever advertised, otherwise checks the raw bound.
     *
     * @param algorithmId exact canonical signature identity
     * @param length original content length, including zero
     * @return deterministic input mode
     * @throws IllegalArgumentException for negative or unsupported input length
     */
    public Mode select(String algorithmId, long length) {
        Objects.requireNonNull(algorithmId, "algorithmId");
        if (length < 0) {
            throw new IllegalArgumentException("Signing input length must not be negative");
        }
        if (prehashedDigests.containsKey(algorithmId)) {
            return Mode.PREHASHED_DIGEST;
        }
        if (length > rawMessageMaximum) {
            throw new IllegalArgumentException("Signing input exceeds provider raw-message limit");
        }
        return Mode.RAW_MESSAGE;
    }

    /**
     * Composes backend configuration with the complete effective input contract.
     * Sorted, length-framed fields include protocol version and selection rule.
     *
     * @param backend immutable backend configuration commitment
     * @param algorithms exact advertised algorithm set
     * @return client-effective configuration commitment
     */
    public SigningProvider.ConfigurationCommitment commitment(SigningProvider.ConfigurationCommitment backend,
            Set<String> algorithms) {
        Objects.requireNonNull(backend, "backend");
        if (algorithms.size() > MAXIMUM_ALGORITHMS || !algorithms.containsAll(prehashedDigests.keySet())) {
            throw new IllegalArgumentException("Signing capability algorithm set is inconsistent");
        }
        MessageDigest digest = newDigest(BootstrapAlgorithmIdentities.SHA256);
        try (DataOutputStream output = new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(),
                digest))) {
            output.writeUTF("zeroecho.signing-input");
            output.writeInt(PROTOCOL_VERSION);
            output.writeUTF("exact-prehash-first-otherwise-bounded-raw");
            output.write(backend.bytes());
            output.writeLong(rawMessageMaximum);
            output.writeInt(algorithms.size());
            for (String algorithm : new TreeSet<>(algorithms)) {
                requireIdentityBound(algorithm);
                output.writeUTF(algorithm);
            }
            output.writeInt(prehashedDigests.size());
            for (Map.Entry<String, AlgorithmIdentity> entry : new TreeMap<>(prehashedDigests).entrySet()) {
                output.writeUTF(entry.getKey());
                output.writeUTF(entry.getValue().canonicalForm());
            }
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory input commitment failed", impossible);
        }
        return new SigningProvider.ConfigurationCommitment(digest.digest());
    }

    /**
     * Resolves only explicitly supported typed standard signature semantics.
     * Pure EdDSA, private families and unknown algorithms are not prehashable.
     *
     * @param signature exact typed signature identity
     * @return message digest implied by the exact identity
     * @throws IllegalArgumentException if equivalent prehash semantics are not supported
     */
    public static AlgorithmIdentity requiredDigest(AlgorithmIdentity signature) {
        Objects.requireNonNull(signature, "signature");
        AlgorithmIdentity digest;
        if (signature.kind() == AlgorithmIdentity.Kind.SIGNATURE
                && (signature.family().equals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.family())
                    || signature.family().equals(BootstrapAlgorithmIdentities.ECDSA_SHA256.family()))
                && signature.parameters() instanceof AlgorithmIdentity.DigestParameters parameters) {
            digest = parameters.digest();
        } else if (signature.kind() == AlgorithmIdentity.Kind.SIGNATURE
                && signature.family().equals(BootstrapAlgorithmIdentities.RSA_PSS_SHA256.family())
                && signature.parameters() instanceof AlgorithmIdentity.RsaPssParameters parameters
                && parameters.mask().equals(BootstrapAlgorithmIdentities.MGF1)) {
            digestLength(parameters.maskHash());
            digest = parameters.hash();
        } else {
            throw new IllegalArgumentException("Signature identity has no supported prehash semantics");
        }
        digestLength(digest);
        return digest;
    }

    /**
     * Resolves the output size of a supported prehash digest.
     * @param digest exact supported digest identity
     * @return digest length in bytes
     * @throws IllegalArgumentException for unsupported digest identities
     */
    public static int digestLength(AlgorithmIdentity digest) {
        if (BootstrapAlgorithmIdentities.SHA256.equals(digest)) { return 32; }
        if (BootstrapAlgorithmIdentities.SHA384.equals(digest)) { return 48; }
        if (BootstrapAlgorithmIdentities.SHA512.equals(digest)) { return 64; }
        throw new IllegalArgumentException("Unsupported prehash digest identity");
    }

    /**
     * Creates an independent JDK engine for a supported prehash digest.
     * @param digest exact supported digest identity
     * @return new independently owned JDK digest engine
     */
    public static MessageDigest newDigest(AlgorithmIdentity digest) {
        String name = switch (digestLength(digest)) {
            case 32 -> "SHA-256";
            case 48 -> "SHA-384";
            case 64 -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported digest");
        };
        try {
            return MessageDigest.getInstance(name);
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("Required SHA-2 digest unavailable", unavailable);
        }
    }

    private static void requireIdentityBound(String value) {
        if (value == null || value.isBlank() || value.length() > 8192) {
            throw new IllegalArgumentException("Algorithm identity exceeds its finite bound");
        }
    }

    private static void requireShallowPrehashParameters(String identity) {
        // Every supported tuple, including Integer.MAX_VALUE salt length,
        // fits within 512 ASCII characters in the canonical identity envelope.
        if (identity.length() > MAX_PREHASH_ID_LENGTH) {
            throw new IllegalArgumentException("Prehash signature identity exceeds its structural bound");
        }
        int separator = identity.lastIndexOf(':');
        if (separator < 0) {
            throw new IllegalArgumentException("Malformed prehash signature identity");
        }
        byte[] encoded = Base64.getUrlDecoder().decode(identity.substring(separator + 1));
        String parameters = new String(encoded, StandardCharsets.US_ASCII);
        if (!PREHASH_PARAMETERS.matcher(parameters).matches()) {
            throw new IllegalArgumentException("Unsupported nested prehash signature parameters");
        }
    }
}
