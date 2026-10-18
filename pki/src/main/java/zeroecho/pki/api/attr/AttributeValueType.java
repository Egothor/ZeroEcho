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
package zeroecho.pki.api.attr;

/**
 * Declares the logical value type of an attribute.
 *
 * <p>
 * Framework backends map these logical types into framework-specific constructs
 * (e.g., X.509 extensions, claims, or other credential fields).
 * </p>
 */
public enum AttributeValueType {

    /**
     * UTF-8 string value.
     */
    STRING,

    /**
     * Boolean value.
     */
    BOOLEAN,

    /**
     * Integer/long value.
     */
    INTEGER,

    /**
     * Timestamp value.
     */
    INSTANT,

    /**
     * Raw byte string.
     */
    BYTES,

    /**
     * Object identifier string.
     */
    OID,

    /**
     * Distinguished Name representation (string form with normalization rules
     * defined by profile/policy).
     */
    DN,

    /**
     * GeneralName-like identity (DNS/IP/URI/email/etc.) represented in a canonical
     * structured form.
     */
    GENERAL_NAME,

    /**
     * Public key information representation (e.g., SPKI).
     */
    KEY_INFO,

    /**
     * Structured composite value.
     */
    STRUCT
}
