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

package zeroecho.pki.impl.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pkix.Pkix;

/**
 * Immutable internal identity of an X.509 CRL issuer: canonical X.500 name and
 * exact canonical DER SubjectPublicKeyInfo. Name equivalence is exactly
 * {@link X500Principal#equals(Object)}, including its canonical string rules.
 * The digest is an index locator; structural equality always compares both
 * constituents. This value grants no ownership or authorization.
 *
 * <p>Local framing, validation and storage use O(N + K) time and auxiliary
 * memory for bounded name bytes N and SPKI bytes K, in addition to JDK name
 * canonicalization (including ordering multi-valued RDNs). The value owns its
 * arrays and is thread-safe.</p>
 */
public final class CrlScope {
    /** Maximum encoded issuer name and canonical UTF-8 name size. */
    public static final int MAXIMUM_NAME_BYTES = 65_536;
    /** Maximum canonical SPKI size, matching certificate preparation. */
    public static final int MAXIMUM_SPKI_BYTES = 1_048_576;

    private final String canonicalIssuerName;
    private final byte[] subjectPublicKeyInfoDer;
    private final String digest;

    private CrlScope(String canonicalIssuerName, byte[] key) {
        this.canonicalIssuerName = canonicalIssuerName;
        this.subjectPublicKeyInfoDer = key;
        MessageDigest hash = sha256();
        field(hash, "zeroecho:pki:crl-scope:v1".getBytes(StandardCharsets.US_ASCII));
        field(hash, nameBytes(canonicalIssuerName));
        field(hash, key);
        this.digest = HexFormat.of().formatHex(hash.digest());
    }

    /**
     * Derives an identity from a canonical DER X.500 Name and canonical SPKI.
     *
     * @param issuerNameDer complete DER Name, at most {@link #MAXIMUM_NAME_BYTES}
     * @param subjectPublicKeyInfoDer complete DER SPKI, at most {@link #MAXIMUM_SPKI_BYTES}
     * @return immutable canonical identity
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if an input is malformed or exceeds its bound
     */
    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    public static CrlScope of(byte[] issuerNameDer, byte[] subjectPublicKeyInfoDer) {
        byte[] name = boundedCopy(issuerNameDer, MAXIMUM_NAME_BYTES);
        try {
            new StreamingDerReader().validate(name, MAXIMUM_NAME_BYTES);
            String canonical = new X500Principal(name).getName(X500Principal.CANONICAL);
            return new CrlScope(canonical, validatedKey(subjectPublicKeyInfoDer));
        } catch (IOException | IllegalArgumentException invalid) {
            throw malformed();
        }
    }

    /**
     * Restores canonical constituents and verifies their stored digest. No
     * normalization of persisted noncanonical input or compatibility decoding occurs.
     *
     * @param canonicalIssuerName exact JDK canonical X.500 string
     * @param subjectPublicKeyInfoDer canonical DER SPKI
     * @param expectedDigest lowercase 64-digit SHA-256 locator
     * @return validated immutable identity
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if a constituent is invalid or the digest differs
     */
    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    public static CrlScope restore(String canonicalIssuerName, byte[] subjectPublicKeyInfoDer,
            String expectedDigest) {
        nameBytes(canonicalIssuerName);
        Objects.requireNonNull(expectedDigest, "expectedDigest");
        X500Principal principal;
        try {
            principal = new X500Principal(canonicalIssuerName);
            new StreamingDerReader().validate(principal.getEncoded(), MAXIMUM_NAME_BYTES);
        } catch (IOException | IllegalArgumentException invalid) {
            throw malformed();
        }
        if (!canonicalIssuerName.equals(principal.getName(X500Principal.CANONICAL))) { throw malformed(); }
        CrlScope scope = new CrlScope(canonicalIssuerName, validatedKey(subjectPublicKeyInfoDer));
        if (!scope.digest.equals(expectedDigest)) { throw malformed(); }
        return scope;
    }

    /** {@return canonical X.500 name under JDK principal equality} */
    public String canonicalIssuerName() { return canonicalIssuerName; }

    /** {@return defensive copy of the canonical DER SPKI} */
    public byte[] subjectPublicKeyInfoDer() { return subjectPublicKeyInfoDer.clone(); }

    /** {@return lowercase SHA-256 index locator, never an ownership proof} */
    public String digest() { return digest; }

    @Override
    public boolean equals(Object other) {
        return other instanceof CrlScope scope && canonicalIssuerName.equals(scope.canonicalIssuerName)
                && Arrays.equals(subjectPublicKeyInfoDer, scope.subjectPublicKeyInfoDer);
    }

    @Override
    public int hashCode() { return digest.hashCode(); }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private static byte[] validatedKey(byte[] encoded) {
        byte[] exact = boundedCopy(encoded, MAXIMUM_SPKI_BYTES);
        boolean canonical;
        try {
            new StreamingDerReader().validateSubjectPublicKeyInfo(exact, MAXIMUM_SPKI_BYTES);
            byte[] bits = Pkix.subjectPublicKeyBytes(exact);
            canonical = bits.length != 0 && Arrays.equals(exact,
                    Pkix.buildSubjectPublicKeyInfo(Pkix.subjectPublicKeyAlgorithm(exact), bits));
        } catch (IOException | IllegalArgumentException invalid) {
            throw malformed();
        }
        if (!canonical) { throw malformed(); }
        return exact;
    }

    private static byte[] boundedCopy(byte[] value, int maximum) {
        Objects.requireNonNull(value, "encoded");
        if (value.length == 0 || value.length > maximum) {
            throw malformed();
        }
        return value.clone();
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private static byte[] nameBytes(String name) {
        Objects.requireNonNull(name, "canonicalIssuerName");
        if (name.length() > MAXIMUM_NAME_BYTES) {
            throw malformed();
        }
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(name));
            if (encoded.remaining() > MAXIMUM_NAME_BYTES) {
                throw malformed();
            }
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        } catch (CharacterCodingException invalid) {
            throw malformed();
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable", unavailable);
        }
    }

    private static void field(MessageDigest hash, byte[] value) {
        hash.update((byte) (value.length >>> 24));
        hash.update((byte) (value.length >>> 16));
        hash.update((byte) (value.length >>> 8));
        hash.update((byte) value.length);
        hash.update(value);
    }

    private static IllegalArgumentException malformed() {
        return new IllegalArgumentException("Invalid canonical CRL scope");
    }
}
