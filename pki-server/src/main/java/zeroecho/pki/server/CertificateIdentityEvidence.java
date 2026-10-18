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

package zeroecho.pki.server;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.PublicKeyIdentity;

/**
 * Immutable realm-bound certificate and mathematical key commitments used only
 * for enrollment separation. Construction does not establish certificate trust,
 * authentication or authority. Production callers create this value only after
 * validating the actual direct or forwarded end-client credential.
 *
 * @param realmId authentication realm
 * @param certificateSha256 exact certificate DER commitment
 * @param canonicalKeySha256 mathematical key commitment, distinct from mapping hashes
 * @param legacySpkiSha256 finite supported equivalent SPKI commitments plus actual provider encoding
 * @param issuerSerialSha256 existing issuer-DER/positive-serial mapping commitment
 */
public record CertificateIdentityEvidence(RealmId realmId, String certificateSha256, String canonicalKeySha256,
        Set<String> legacySpkiSha256, String issuerSerialSha256) {
    /** Validates fixed-size commitments and snapshots at most three SPKI hashes. */
    public CertificateIdentityEvidence {
        Objects.requireNonNull(realmId, "realmId");
        requireDigest(certificateSha256);
        requireDigest(canonicalKeySha256);
        requireDigest(issuerSerialSha256);
        Objects.requireNonNull(legacySpkiSha256, "legacySpkiSha256");
        if (legacySpkiSha256.isEmpty() || legacySpkiSha256.size() > 3) {
            throw new IllegalArgumentException("Identity mapping commitments are invalid");
        }
        legacySpkiSha256.forEach(CertificateIdentityEvidence::requireDigest);
        legacySpkiSha256 = Collections.unmodifiableSortedSet(new TreeSet<>(legacySpkiSha256));
    }

    /**
     * Computes evidence from an already validated end-client certificate. It does
     * not validate trust, time, usage or principal mapping. Unsupported identity
     * encodings are rejected without a fallback to hashing arbitrary SPKI bytes.
     * Existing configured mapping hash semantics remain unchanged.
     * @param realmId exact authenticated realm
     * @param certificate validated end-client leaf, never a proxy transport leaf
     * @return immutable, redacted credential evidence
     * @throws CertificateEncodingException if certificate encoding is unavailable
     * @throws IllegalArgumentException if the key representation or serial is unsupported
     */
    public static CertificateIdentityEvidence fromCertificate(RealmId realmId, X509Certificate certificate)
            throws CertificateEncodingException {
        Objects.requireNonNull(certificate, "certificate");
        PublicKeyIdentity identity = PublicKeyIdentity.fromSubjectPublicKeyInfo(Pkix.subjectPublicKeyInfo(certificate));
        BigInteger serial = certificate.getSerialNumber();
        if (serial.signum() <= 0) {
            throw new IllegalArgumentException("Certificate identity is invalid");
        }
        MessageDigest issuerSerial = sha256();
        issuerSerial.update(certificate.getIssuerX500Principal().getEncoded());
        issuerSerial.update((byte) 0);
        issuerSerial.update(serial.toByteArray());
        SortedSet<String> legacy = new TreeSet<>(identity.equivalentSubjectPublicKeyInfoSha256());
        legacy.add(HexFormat.of().formatHex(sha256().digest(certificate.getPublicKey().getEncoded())));
        return new CertificateIdentityEvidence(realmId, HexFormat.of().formatHex(sha256().digest(certificate.getEncoded())),
                identity.canonicalSha256(), legacy, HexFormat.of().formatHex(issuerSerial.digest()));
    }

    /**
     * Compares exact certificates or mathematical keys within the same realm.
     * @param other verified credential evidence
     * @return whether both represent one known requester credential relationship
     */
    public boolean sameCredential(CertificateIdentityEvidence other) {
        Objects.requireNonNull(other, "other");
        return realmId.equals(other.realmId) && (certificateSha256.equals(other.certificateSha256)
                || canonicalKeySha256.equals(other.canonicalKeySha256));
    }

    /** @return redacted diagnostic description without credential commitments */
    @Override public String toString() { return "CertificateIdentityEvidence[redacted]"; }

    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Identity commitment is invalid");
        }
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
}
