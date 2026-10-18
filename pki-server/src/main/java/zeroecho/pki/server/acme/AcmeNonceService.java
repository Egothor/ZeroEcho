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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Bounded process-local one-time ACME replay-nonce authority.
 *
 * <p>Only SHA-256 commitments are retained. Restart intentionally invalidates all
 * outstanding nonces. Expiry buckets are removed eagerly on every issue and
 * consume operation, so retained state cannot grow beyond the configured bound.</p>
 */
@SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel", "PMD.ControlStatementBraces",
        "PMD.UselessParentheses" })
public final class AcmeNonceService {
    private static final int NONCE_BYTES = 32;
    private final String listenerId;
    private final Duration lifetime;
    private final int maximumOutstanding;
    private final Clock clock;
    private final SecureRandom random;
    private final Map<String, Instant> byCommitment = new HashMap<>();
    private final NavigableMap<Instant, java.util.Set<String>> byExpiry = new TreeMap<>();

    /**
     * Creates a bounded nonce service for one exact ACME listener.
     *
     * @param listenerId stable listener identity included in nonce commitments
     * @param lifetime positive nonce lifetime, no greater than one hour
     * @param maximumOutstanding maximum retained nonces, from 16 through 1,000,000
     * @param clock authoritative time source
     * @param random cryptographically secure entropy source
     * @throws IllegalArgumentException if the listener identity, lifetime, or capacity is invalid
     * @throws NullPointerException if {@code clock} or {@code random} is {@code null}
     */
    public AcmeNonceService(String listenerId, Duration lifetime, int maximumOutstanding,
            Clock clock, SecureRandom random) {
        if (listenerId == null || !listenerId.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException("ACME listener identity is invalid");
        }
        if (lifetime == null || lifetime.isZero() || lifetime.isNegative()
                || lifetime.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("ACME nonce lifetime is invalid");
        }
        if (maximumOutstanding < 16 || maximumOutstanding > 1_000_000) {
            throw new IllegalArgumentException("ACME nonce capacity is invalid");
        }
        this.listenerId = listenerId;
        this.lifetime = lifetime;
        this.maximumOutstanding = maximumOutstanding;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * Issues one canonical unpadded Base64url nonce with 256 bits of entropy.
     *
     * @param nonceScope canonical listener alias scope to bind into the commitment
     * @return the newly issued one-time nonce
     * @throws IllegalArgumentException if {@code nonceScope} is not a canonical DNS label
     * @throws IllegalStateException if nonce capacity is exhausted
     */
    public synchronized String issue(String nonceScope) {
        requireNonceScope(nonceScope);
        expire(clock.instant());
        if (byCommitment.size() >= maximumOutstanding) {
            throw new IllegalStateException("ACME nonce capacity is exhausted");
        }
        byte[] raw = new byte[NONCE_BYTES];
        String nonce;
        String commitment;
        do {
            random.nextBytes(raw);
            nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            commitment = commitment(nonce, nonceScope);
        } while (byCommitment.containsKey(commitment));
        java.util.Arrays.fill(raw, (byte) 0);
        Instant expiry = clock.instant().plus(lifetime);
        byCommitment.put(commitment, expiry);
        byExpiry.computeIfAbsent(expiry, ignored -> new java.util.HashSet<>()).add(commitment);
        return nonce;
    }

    /**
     * Consumes one nonce exactly once for the bound listener and canonical alias scope.
     *
     * @param nonce canonical unpadded Base64url nonce, or malformed input to reject
     * @param nonceScope listener alias scope expected by the request
     * @return {@code true} only for a live nonce bound to the supplied scope
     */
    public synchronized boolean consume(String nonce, String nonceScope) {
        Instant now = clock.instant();
        expire(now);
        if (nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}")
                || nonceScope == null || nonceScope.isBlank()) return false;
        String key = commitment(nonce, nonceScope);
        Instant expiry = byCommitment.remove(key);
        if (expiry == null) return false;
        java.util.Set<String> bucket = byExpiry.get(expiry);
        if (bucket != null && (bucket.remove(key) && bucket.isEmpty())) byExpiry.remove(expiry);
        return expiry.isAfter(now);
    }

    /**
     * Returns the current bounded outstanding nonce count for diagnostics.
     *
     * @return the count after expired entries have been removed
     */
    public synchronized int outstanding() { expire(clock.instant()); return byCommitment.size(); }

    private void expire(Instant now) {
        while (!byExpiry.isEmpty() && !byExpiry.firstKey().isAfter(now)) {
            byExpiry.pollFirstEntry().getValue().forEach(byCommitment::remove);
        }
    }

    private String commitment(String nonce, String nonceScope) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(listenerId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(nonceScope.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(nonce.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void requireNonceScope(String nonceScope) {
        if (nonceScope == null || !nonceScope.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
            throw new IllegalArgumentException("ACME nonce scope is invalid");
        }
    }
}
