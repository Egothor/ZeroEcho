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
package zeroecho.pki.spi.ct;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable Merkle-chained entry in the CT audit journal.
 *
 * <p>Each entry records the SHA-256 fingerprint of one issued certificate and
 * chains to the previous entry via its {@code previousHash} and {@code entryHash}
 * fields. The chain is tamper-evident: any modification to an entry changes its
 * {@code entryHash}, which invalidates all subsequent entries.</p>
 *
 * <p>Use {@link #create(long, Instant, byte[], BigInteger, String, byte[])} to
 * construct entries with automatically computed hashes. The canonical constructor
 * is available for deserialization from durable storage.</p>
 *
 * <h2>Hash computation</h2>
 * <ul>
 *   <li>{@code leafHash = SHA-256(sequenceNumber || epochSeconds || certFingerprint)}</li>
 *   <li>{@code entryHash = SHA-256(previousHash || leafHash)}</li>
 * </ul>
 * <p>All multi-byte integers are big-endian.</p>
 *
 * @param sequenceNumber  monotonically increasing sequence position, 1-based
 * @param timestamp       signing completion time
 * @param certFingerprint SHA-256 of the DER-encoded issued certificate (32 bytes)
 * @param serialNumber    X.509 serial number of the issued certificate
 * @param authorityId     issuing CA authority identifier
 * @param previousHash    {@code entryHash} of the previous entry; all-zeros for the first entry (32 bytes)
 * @param leafHash        SHA-256 of (sequenceNumber || epochSeconds || certFingerprint) (32 bytes)
 * @param entryHash       SHA-256 of (previousHash || leafHash) (32 bytes)
 * @since 1.0
 */
public record CtJournalEntry(
        long sequenceNumber,
        Instant timestamp,
        byte[] certFingerprint,
        BigInteger serialNumber,
        String authorityId,
        byte[] previousHash,
        byte[] leafHash,
        byte[] entryHash) {

    /** Required length in bytes for all hash fields. */
    public static final int HASH_BYTES = 32;

    /** Maximum UTF-8 byte length of the authority identifier. */
    public static final int MAX_AUTHORITY_ID_BYTES = 128;

    /**
     * Validates fields and defensively copies all byte arrays.
     *
     * @throws NullPointerException     if any field is {@code null}
     * @throws IllegalArgumentException if {@code sequenceNumber} is not positive,
     *                                  if any hash array does not have exactly 32 bytes,
     *                                  if {@code certFingerprint} does not have exactly 32 bytes,
     *                                  or if {@code authorityId} is blank
     */
    public CtJournalEntry {
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(certFingerprint, "certFingerprint");
        Objects.requireNonNull(serialNumber, "serialNumber");
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(previousHash, "previousHash");
        Objects.requireNonNull(leafHash, "leafHash");
        Objects.requireNonNull(entryHash, "entryHash");
        if (sequenceNumber <= 0) {
            throw new IllegalArgumentException("sequenceNumber must be positive");
        }
        if (certFingerprint.length != HASH_BYTES) {
            throw new IllegalArgumentException("certFingerprint must be exactly 32 bytes");
        }
        if (previousHash.length != HASH_BYTES) {
            throw new IllegalArgumentException("previousHash must be exactly 32 bytes");
        }
        if (leafHash.length != HASH_BYTES) {
            throw new IllegalArgumentException("leafHash must be exactly 32 bytes");
        }
        if (entryHash.length != HASH_BYTES) {
            throw new IllegalArgumentException("entryHash must be exactly 32 bytes");
        }
        if (authorityId.isBlank()) {
            throw new IllegalArgumentException("authorityId must not be blank");
        }
        if (authorityId.getBytes(StandardCharsets.UTF_8).length > MAX_AUTHORITY_ID_BYTES) {
            throw new IllegalArgumentException("authorityId UTF-8 encoding exceeds 128 bytes");
        }
        // Defensive copies to preserve immutability.
        certFingerprint = certFingerprint.clone();
        previousHash = previousHash.clone();
        leafHash = leafHash.clone();
        entryHash = entryHash.clone();
    }

    /**
     * Creates a new journal entry with automatically computed {@code leafHash} and {@code entryHash}.
     *
     * @param sequenceNumber  monotonically increasing position, must be positive
     * @param timestamp       signing completion time; must not be {@code null}
     * @param certFingerprint SHA-256 of the DER-encoded certificate (exactly 32 bytes)
     * @param serialNumber    certificate serial number; must not be {@code null}
     * @param authorityId     issuing authority identifier; must not be blank
     * @param previousHash    {@code entryHash} of the previous entry; all-zeros for entry #1 (exactly 32 bytes)
     * @return new immutable journal entry with computed hashes
     * @throws NullPointerException     if any parameter is {@code null}
     * @throws IllegalArgumentException if parameters fail their constraints
     */
    public static CtJournalEntry create(
            final long sequenceNumber,
            final Instant timestamp,
            final byte[] certFingerprint,
            final BigInteger serialNumber,
            final String authorityId,
            final byte[] previousHash) {
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(certFingerprint, "certFingerprint");
        Objects.requireNonNull(serialNumber, "serialNumber");
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(previousHash, "previousHash");

        final byte[] leaf = computeLeafHash(sequenceNumber, timestamp, certFingerprint);
        final byte[] entry = computeEntryHash(previousHash, leaf);
        return new CtJournalEntry(sequenceNumber, timestamp, certFingerprint,
                serialNumber, authorityId, previousHash, leaf, entry);
    }

    /**
     * Returns an independent copy of the {@code certFingerprint} bytes.
     *
     * @return 32-byte copy of the certificate SHA-256 fingerprint
     */
    public byte[] certFingerprintCopy() {
        return certFingerprint.clone();
    }

    /**
     * Returns an independent copy of the {@code previousHash} bytes.
     *
     * @return 32-byte copy of the previous entry hash
     */
    public byte[] previousHashCopy() {
        return previousHash.clone();
    }

    /**
     * Returns an independent copy of the {@code leafHash} bytes.
     *
     * @return 32-byte copy of the leaf hash
     */
    public byte[] leafHashCopy() {
        return leafHash.clone();
    }

    /**
     * Returns an independent copy of the {@code entryHash} bytes.
     *
     * @return 32-byte copy of the entry chain hash
     */
    public byte[] entryHashCopy() {
        return entryHash.clone();
    }

    // leafHash = SHA-256(sequenceNumber_BE8 || epochSeconds_BE8 || certFingerprint)
    private static byte[] computeLeafHash(final long sequenceNumber, final Instant timestamp,
            final byte[] certFingerprint) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final ByteBuffer buf = ByteBuffer.allocate(8 + 8 + HASH_BYTES);
            buf.putLong(sequenceNumber);
            buf.putLong(timestamp.getEpochSecond());
            buf.put(certFingerprint, 0, HASH_BYTES);
            digest.update(buf.array());
            return digest.digest();
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }

    // entryHash = SHA-256(previousHash || leafHash)
    private static byte[] computeEntryHash(final byte[] previousHash, final byte[] leafHash) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(previousHash);
            digest.update(leafHash);
            return digest.digest();
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CtJournalEntry other)) {
            return false;
        }
        return sequenceNumber == other.sequenceNumber
                && Objects.equals(timestamp, other.timestamp)
                && Arrays.equals(certFingerprint, other.certFingerprint)
                && Objects.equals(serialNumber, other.serialNumber)
                && Objects.equals(authorityId, other.authorityId)
                && Arrays.equals(previousHash, other.previousHash)
                && Arrays.equals(leafHash, other.leafHash)
                && Arrays.equals(entryHash, other.entryHash);
    }

    @Override
    public int hashCode() {
        int result = Long.hashCode(sequenceNumber);
        result = 31 * result + Objects.hashCode(timestamp);
        result = 31 * result + Arrays.hashCode(certFingerprint);
        result = 31 * result + Objects.hashCode(serialNumber);
        result = 31 * result + Objects.hashCode(authorityId);
        result = 31 * result + Arrays.hashCode(previousHash);
        result = 31 * result + Arrays.hashCode(leafHash);
        result = 31 * result + Arrays.hashCode(entryHash);
        return result;
    }

    @Override
    public String toString() {
        return "CtJournalEntry[seq=" + sequenceNumber + ",authorityId=" + authorityId + "]";
    }
}
