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
package zeroecho.pki.api.orch;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Versioned ZeroEcho signing-submission identifier.
 *
 * <p>
 * The format is
 * {@code zsign:v1:<namespace>:<epoch-millisecond>:<128-bit-random>}. Creation
 * time remains store-authoritative: stores must validate the embedded time
 * against their own clock and persist it with the intent.
 * </p>
 *
 * @param id        identifier value
 * @param namespace provider/store namespace
 * @param createdAt embedded creation time with millisecond precision
 */
public record SigningSubmissionId(PkiId id, String namespace, Instant createdAt) {

    private static final String PREFIX = "zsign:v1:";
    private static final int RANDOM_BYTES = 16;

    /** Validates and preserves the exact submission identity components. */
    public SigningSubmissionId {
        Objects.requireNonNull(id, "id");
        requireNamespace(namespace);
        Objects.requireNonNull(createdAt, "createdAt");
    }

    /**
     * Creates a new identifier using a cryptographically strong random source.
     *
     * @param namespace provider/store namespace
     * @param now       trusted caller creation time
     * @param random    secure random source
     * @return new identifier
     */
    public static SigningSubmissionId create(String namespace, Instant now, SecureRandom random) {
        requireNamespace(namespace);
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(random, "random");
        Instant created = Instant.ofEpochMilli(now.toEpochMilli());
        byte[] nonce = new byte[RANDOM_BYTES];
        random.nextBytes(nonce);
        String value = PREFIX + namespace + ":" + created.toEpochMilli() + ":" + HexFormat.of().formatHex(nonce);
        return new SigningSubmissionId(new PkiId(value), namespace, created);
    }

    /**
     * Parses and validates the version, namespace, timestamp, and random length.
     *
     * @param id identifier to parse
     * @return parsed identifier
     * @throws IllegalArgumentException if the identifier is malformed
     */
    public static SigningSubmissionId parse(PkiId id) {
        Objects.requireNonNull(id, "id");
        String[] parts = id.value().split(":", -1);
        if (parts.length != 5 || !"zsign".equals(parts[0]) || !"v1".equals(parts[1])) {
            throw new IllegalArgumentException("Unsupported signing submission id");
        }
        requireNamespace(parts[2]);
        long epochMilli;
        try {
            epochMilli = Long.parseLong(parts[3]);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid signing submission timestamp", ex);
        }
        if (parts[4].length() != RANDOM_BYTES * 2) {
            throw new IllegalArgumentException("Invalid signing submission random length");
        }
        try {
            HexFormat.of().parseHex(parts[4]);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid signing submission random value", ex);
        }
        return new SigningSubmissionId(id, parts[2], Instant.ofEpochMilli(epochMilli));
    }

    /**
     * Validates namespace and lifetime against store-authoritative time.
     *
     * @param requiredNamespace expected namespace
     * @param now               store-authoritative time
     * @param horizon           maximum accepted age
     * @param permittedSkew     allowed future clock skew
     * @throws IllegalArgumentException if namespace or lifetime is invalid
     */
    public void validate(String requiredNamespace, Instant now, Duration horizon, Duration permittedSkew) {
        requireNamespace(requiredNamespace);
        Objects.requireNonNull(now, "now");
        requirePositive(horizon, "horizon");
        Objects.requireNonNull(permittedSkew, "permittedSkew");
        if (permittedSkew.isNegative()) {
            throw new IllegalArgumentException("permittedSkew must not be negative");
        }
        if (!namespace.equals(requiredNamespace)) {
            throw new IllegalArgumentException("Signing submission namespace mismatch");
        }
        if (createdAt.isAfter(now.plus(permittedSkew))) {
            throw new IllegalArgumentException("Signing submission timestamp is in the future");
        }
        if (!createdAt.plus(horizon).isAfter(now)) {
            throw new IllegalArgumentException("Signing submission id has expired");
        }
    }

    private static void requireNamespace(String namespace) {
        if (namespace == null || namespace.isBlank() || namespace.length() > 128) {
            throw new IllegalArgumentException("namespace must contain 1 to 64 characters");
        }
        for (int index = 0; index < namespace.length(); index++) {
            char value = namespace.charAt(index);
            boolean valid = value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '.' || value == '_'
                    || value == '-';
            if (!valid) {
                throw new IllegalArgumentException("namespace contains an unsupported character");
            }
        }
    }

    private static void requirePositive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
