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
package zeroecho.pkix.ocsp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import zeroecho.pkix.AlgorithmIdentifier;

/**
 * An OCSP {@code CertID} (RFC 6960): identifies a certificate by the hash of its
 * issuer's name and key together with the certificate serial number.
 *
 * @param hashAlgorithm the digest algorithm used for the name and key hashes
 * @param issuerNameHash the digest of the issuer distinguished name
 * @param issuerKeyHash the digest of the issuer public key
 * @param serialNumber the certificate serial number
 */
public record CertId(AlgorithmIdentifier hashAlgorithm, byte[] issuerNameHash, byte[] issuerKeyHash,
        BigInteger serialNumber) {

    /** Canonicalizing constructor. */
    public CertId {
        Objects.requireNonNull(hashAlgorithm, "hashAlgorithm");
        Objects.requireNonNull(issuerNameHash, "issuerNameHash");
        Objects.requireNonNull(issuerKeyHash, "issuerKeyHash");
        Objects.requireNonNull(serialNumber, "serialNumber");
        issuerNameHash = issuerNameHash.clone();
        issuerKeyHash = issuerKeyHash.clone();
    }

    /**
     * Returns the issuer-name digest without exposing the record's internal array.
     *
     * @return a defensive copy of the issuer-name digest
     */
    @Override
    public byte[] issuerNameHash() {
        return issuerNameHash.clone();
    }

    /**
     * Returns the issuer-key digest without exposing the record's internal array.
     *
     * @return a defensive copy of the issuer-key digest
     */
    @Override
    public byte[] issuerKeyHash() {
        return issuerKeyHash.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CertId that && hashAlgorithm.equals(that.hashAlgorithm)
                && serialNumber.equals(that.serialNumber)
                && Arrays.equals(issuerNameHash, that.issuerNameHash)
                && Arrays.equals(issuerKeyHash, that.issuerKeyHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hashAlgorithm, Arrays.hashCode(issuerNameHash), Arrays.hashCode(issuerKeyHash),
                serialNumber);
    }

    @Override
    public String toString() {
        return "CertId[serialNumber=" + serialNumber + ", hashAlgorithm=" + hashAlgorithm.oid() + ']';
    }
}
