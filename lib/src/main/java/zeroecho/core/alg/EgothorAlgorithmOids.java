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
package zeroecho.core.alg;

/**
 * OID constants for the Egothor organisation's private algorithm arc.
 *
 * <p>Root: {@code 1.3.6.1.4.1.31424} (Egothor IANA Private Enterprise Number 31424).
 *
 * <p>Sub-arc layout:
 * <pre>
 * 1.3.6.1.4.1.31424.1          ZeroEcho platform cryptography
 * 1.3.6.1.4.1.31424.1.1        SPHINCS+ (ZeroEcho default parameter set)
 * 1.3.6.1.4.1.31424.1.1.1      SPHINCS+ SubjectPublicKeyInfo
 * 1.3.6.1.4.1.31424.1.1.2      SPHINCS+ CSR signature
 * 1.3.6.1.4.1.31424.1.1.3      SPHINCS+ certificate signature
 * 1.3.6.1.4.1.31424.1.1.4      SPHINCS+ CRL signature
 * 1.3.6.1.4.1.31424.1.1.5      SPHINCS+ OCSP request signature
 * </pre>
 *
 * <p>Certificates carrying Egothor OIDs are interoperable within the ZeroEcho
 * ecosystem. They are not interoperable with parties that do not recognise these
 * OIDs. IETF-standardised successors (e.g. FIPS 205 SLH-DSA OIDs for
 * SPHINCS+-derived algorithms) should be preferred where available.
 *
 * @since 1.0
 */
public final class EgothorAlgorithmOids { // NOPMD DataClass - Canonical public OID constants preserve API identity.

    /** Egothor organisation root OID (IANA PEN 31424). */
    public static final String OID_ROOT = "1.3.6.1.4.1.31424";

    /** ZeroEcho platform cryptography arc. */
    public static final String OID_ZEROECHO = OID_ROOT + ".1";

    /** SPHINCS+ algorithm arc (ZeroEcho default parameter set). */
    public static final String OID_SPHINCS_PLUS = OID_ZEROECHO + ".1";

    /** SPHINCS+ SubjectPublicKeyInfo OID. */
    public static final String OID_SPHINCS_PLUS_SPKI = OID_SPHINCS_PLUS + ".1";

    /** SPHINCS+ CSR signature algorithm OID. */
    public static final String OID_SPHINCS_PLUS_CSR_SIGNATURE = OID_SPHINCS_PLUS + ".2"; // NOPMD LongVariable - Exported canonical algorithm identity name preserves source compatibility.

    /** SPHINCS+ certificate signature algorithm OID. */
    public static final String OID_SPHINCS_PLUS_CERTIFICATE_SIGNATURE = OID_SPHINCS_PLUS + ".3"; // NOPMD LongVariable - Exported canonical algorithm identity name preserves source compatibility.

    /** SPHINCS+ CRL signature algorithm OID. */
    public static final String OID_SPHINCS_PLUS_CRL_SIGNATURE = OID_SPHINCS_PLUS + ".4"; // NOPMD LongVariable - Exported canonical algorithm identity name preserves source compatibility.

    /** SPHINCS+ OCSP request signature algorithm OID. */
    public static final String OID_SPHINCS_PLUS_OCSP_REQUEST_SIGNATURE = OID_SPHINCS_PLUS + ".5"; // NOPMD LongVariable - Exported canonical algorithm identity name preserves source compatibility.

    private EgothorAlgorithmOids() {
    }
}
