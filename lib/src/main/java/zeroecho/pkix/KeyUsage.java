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
package zeroecho.pkix;

/**
 * The X.509 {@code KeyUsage} bits (RFC 5280, 4.2.1.3), in the standard bit order.
 *
 * <p>
 * This enum is the typed, JCA-friendly counterpart of the boolean-array key-usage
 * representation returned by {@link java.security.cert.X509Certificate#getKeyUsage()}:
 * the ordinal of each constant equals its DER bit position.
 * </p>
 */
public enum KeyUsage {
    /** digitalSignature (bit 0). */
    DIGITAL_SIGNATURE,
    /** nonRepudiation / contentCommitment (bit 1). */
    NON_REPUDIATION,
    /** keyEncipherment (bit 2). */
    KEY_ENCIPHERMENT,
    /** dataEncipherment (bit 3). */
    DATA_ENCIPHERMENT,
    /** keyAgreement (bit 4). */
    KEY_AGREEMENT,
    /** keyCertSign (bit 5). */
    KEY_CERT_SIGN,
    /** cRLSign (bit 6). */
    CRL_SIGN,
    /** encipherOnly (bit 7). */
    ENCIPHER_ONLY,
    /** decipherOnly (bit 8). */
    DECIPHER_ONLY;

    /**
     * Returns the DER bit position of this usage (equal to the ordinal).
     *
     * @return the standard bit position
     */
    public int bit() {
        return ordinal();
    }
}
