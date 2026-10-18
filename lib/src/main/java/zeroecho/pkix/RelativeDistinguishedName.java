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

import java.util.Objects;

/**
 * A single-valued relative distinguished name: an attribute-type OID, its value,
 * and the ASN.1 string type used to encode that value.
 *
 * <p>
 * Used with {@link Pkix#distinguishedName(java.util.List)} to build a byte-exact
 * {@link javax.security.auth.x500.X500Principal} from typed components, so callers
 * that apply their own naming policy control the exact DER encoding.
 * </p>
 *
 * @param attributeTypeOid the attribute-type OID (e.g. {@code 2.5.4.3} for CN)
 * @param value the attribute value
 * @param stringType the ASN.1 string type used to encode the value
 */
public record RelativeDistinguishedName(String attributeTypeOid, String value, DirectoryStringType stringType) {

    /** Canonicalizing constructor. */
    public RelativeDistinguishedName {
        Objects.requireNonNull(attributeTypeOid, "attributeTypeOid");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(stringType, "stringType");
        if (attributeTypeOid.isBlank()) {
            throw new IllegalArgumentException("attributeTypeOid must not be blank");
        }
    }
}
