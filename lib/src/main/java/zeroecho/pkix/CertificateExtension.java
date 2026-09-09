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
package zeroecho.pkix;

import java.util.Arrays;
import java.util.Objects;

/**
 * A generic X.509 v3 extension (RFC 5280, 4.1): an OID, a criticality flag, and
 * the exact DER of the {@code extnValue} OCTET STRING contents.
 *
 * <p>
 * High-level typed extensions (key usage, extended key usage, basic constraints,
 * subject alternative names, key identifiers) are expressed through the
 * builder's dedicated methods; this generic form carries any other extension and
 * is what a parsed request exposes for extensions the API does not model
 * explicitly.
 * </p>
 *
 * @param oid dotted-decimal extension OID
 * @param critical whether the extension is marked critical
 * @param derValue exact DER of the extension value (the contents of the
 *        {@code extnValue} OCTET STRING, not the OCTET STRING wrapper)
 */
public record CertificateExtension(String oid, boolean critical, byte[] derValue) {

    /** Canonicalizing constructor. */
    public CertificateExtension {
        Objects.requireNonNull(oid, "oid");
        Objects.requireNonNull(derValue, "derValue");
        if (oid.isBlank()) {
            throw new IllegalArgumentException("oid must not be blank");
        }
        derValue = derValue.clone();
    }

    /**
     * Returns the encoded extension value without exposing the record's internal array.
     *
     * @return a defensive copy of the extension value DER
     */
    @Override
    public byte[] derValue() {
        return derValue.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CertificateExtension that && critical == that.critical
                && oid.equals(that.oid) && Arrays.equals(derValue, that.derValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(oid, critical, Arrays.hashCode(derValue));
    }

    @Override
    public String toString() {
        return "CertificateExtension[oid=" + oid + ", critical=" + critical + ']';
    }
}
