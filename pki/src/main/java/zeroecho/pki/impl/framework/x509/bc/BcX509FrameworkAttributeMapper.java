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
package zeroecho.pki.impl.framework.x509.bc;

import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.spi.framework.FrameworkAttributeMapper;

/**
 * Minimal framework attribute mapper for the internal Bouncy Castle backed
 * X.509 adapter.
 *
 * <p>
 * This mapper forms the attribute-normalization boundary between higher PKI
 * layers and the X.509 framework implementation. It accepts framework-facing
 * {@link AttributeSet} values and returns the normalized attribute set that
 * should be consumed by downstream X.509 adapter components.
 * </p>
 *
 * <p>
 * The current implementation is intentionally minimal and acts as an identity
 * mapper. It validates only that the supplied attribute set reference is not
 * {@code null} and then returns it unchanged.
 * </p>
 *
 * <p>
 * In a more feature-complete X.509 implementation, this component would be the
 * natural place to apply framework-specific normalization rules such as:
 * </p>
 * <ul>
 * <li>OID validation and canonicalization,</li>
 * <li>distinguished-name normalization,</li>
 * <li>attribute catalogue enforcement,</li>
 * <li>validation of expected attribute value types for X.509-specific override
 * identifiers.</li>
 * </ul>
 *
 * <h2>Architectural role</h2>
 * <p>
 * This class does not perform certificate issuance, CSR parsing, or status-
 * object generation. Its responsibility is limited to normalizing framework-
 * specific attribute input before that input is consumed by other X.509 adapter
 * components.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Framework attributes may contain operationally sensitive metadata or
 * adapter-specific wiring values.</li>
 * <li>This implementation does not redact, filter, or validate attribute
 * content.</li>
 * <li>Callers must not assume that the returned attribute set is safe for
 * unrestricted logging or external exposure.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless and thread-safe.
 * </p>
 */
public final class BcX509FrameworkAttributeMapper implements FrameworkAttributeMapper {

    /**
     * Normalizes the supplied framework attribute set.
     *
     * <p>
     * The current implementation performs only null checking and returns the input
     * instance unchanged. No copying, canonicalization, validation, or enrichment
     * is performed.
     * </p>
     *
     * @param input framework-facing attribute set to normalize; must not be
     *              {@code null}
     * @return the supplied attribute set unchanged
     * @throws IllegalArgumentException if {@code input} is {@code null}
     */
    @Override
    public AttributeSet normalize(AttributeSet input) {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }
        // In a full implementation, this would validate OIDs, normalise DNs,
        // and enforce attribute catalogue definitions.
        return input;
    }
}
