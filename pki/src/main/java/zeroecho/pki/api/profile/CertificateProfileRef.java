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
package zeroecho.pki.api.profile;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Exact immutable identity of one imported certificate-profile version.
 */
public final class CertificateProfileRef {
    /** SHA-256 digest length in bytes. */
    public static final int HASH_BYTES = 32;

    private final String profileId;
    private final long profileVersion;
    private final byte[] canonicalSha256;

    /**
     * Creates an exact profile reference.
     *
     * @param profileId       logical profile identifier
     * @param profileVersion  positive profile version
     * @param canonicalSha256 SHA-256 of the canonical JSON document
     */
    public CertificateProfileRef(String profileId, long profileVersion, byte[] canonicalSha256) {
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be null/blank");
        }
        if (profileVersion <= 0) {
            throw new IllegalArgumentException("profileVersion must be positive");
        }
        Objects.requireNonNull(canonicalSha256, "canonicalSha256");
        if (canonicalSha256.length != HASH_BYTES) {
            throw new IllegalArgumentException("canonicalSha256 must contain 32 bytes");
        }
        this.profileId = profileId;
        this.profileVersion = profileVersion;
        this.canonicalSha256 = canonicalSha256.clone();
    }

    /** @return logical profile identifier */
    public String profileId() {
        return profileId;
    }

    /** @return positive profile version */
    public long profileVersion() {
        return profileVersion;
    }

    /** @return defensive copy of the canonical SHA-256 digest */
    public byte[] canonicalSha256() {
        return canonicalSha256.clone();
    }

    /**
     * Returns a short non-authoritative fingerprint suitable for audit metadata.
     *
     * @return first eight hash bytes encoded as lowercase hexadecimal
     */
    public String shortFingerprint() {
        return HexFormat.of().formatHex(canonicalSha256, 0, 8);
    }

    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof CertificateProfileRef ref && profileVersion == ref.profileVersion
                && profileId.equals(ref.profileId) && MessageDigest.isEqual(canonicalSha256, ref.canonicalSha256);
    }

    @Override
    public int hashCode() {
        int result = profileId.hashCode();
        result = 31 * result + Long.hashCode(profileVersion);
        result = 31 * result + Arrays.hashCode(canonicalSha256);
        return result;
    }

    @Override
    public String toString() {
        return "CertificateProfileRef[profileId=" + profileId + ", profileVersion=" + profileVersion + ", fingerprint="
                + shortFingerprint() + "]";
    }
}
