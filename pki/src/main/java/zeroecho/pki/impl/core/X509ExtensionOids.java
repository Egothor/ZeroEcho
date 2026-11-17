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

package zeroecho.pki.impl.core;

/**
 * Standard X.509 extension identifiers used by issuer and continuation validation.
 *
 * <p>Each accessor returns a canonical dotted-decimal object identifier.
 */
public final class X509ExtensionOids {
    private static final String EXTENSION_ROOT = "2.5.29";
    /**
     * Returns the subject key identifier extension identifier.
     *
     * @return the object identifier {@code 2.5.29.14}
     */
    public static String subjectKeyIdentifier() { return EXTENSION_ROOT + ".14"; }
    /**
     * Returns the alternative subject public-key information extension identifier.
     *
     * @return the object identifier {@code 2.5.29.72}
     */
    public static String subjectAltPublicKeyInfo() { return EXTENSION_ROOT + ".72"; }
    /**
     * Returns the alternative signature algorithm extension identifier.
     *
     * @return the object identifier {@code 2.5.29.73}
     */
    public static String altSignatureAlgorithm() { return EXTENSION_ROOT + ".73"; }
    /**
     * Returns the alternative signature value extension identifier.
     *
     * @return the object identifier {@code 2.5.29.74}
     */
    public static String altSignatureValue() { return EXTENSION_ROOT + ".74"; }
    private X509ExtensionOids() { }
}
