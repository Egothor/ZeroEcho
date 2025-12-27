/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.api.audit;

import java.util.Optional;

import zeroecho.pki.api.attr.AttributeCatalogue;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;

/**
 * Policy enforcement point for attribute access with mandatory auditing.
 *
 * <p>
 * All attribute read/write/export/derive operations should be performed through
 * this service to ensure: (1) consistent ACL evaluation and (2) consistent
 * audit event emission.
 * </p>
 */
public interface AttributeGovernanceService {

    /**
     * Reads an attribute value after applying access control.
     *
     * @param catalogue attribute catalogue used to resolve definitions
     * @param set       attribute set being accessed
     * @param id        attribute id
     * @param context   access context
     * @return value if present and access is allowed; empty otherwise
     * @throws IllegalArgumentException if inputs are null
     */
    Optional<AttributeValue> read(AttributeCatalogue catalogue, AttributeSet set, AttributeId id,
            AccessContext context);

    /**
     * Writes an attribute value after applying access control.
     *
     * @param catalogue attribute catalogue used to resolve definitions
     * @param set       attribute set being modified
     * @param id        attribute id
     * @param value     value to write
     * @param context   access context
     * @return new attribute set instance containing the updated value
     * @throws IllegalArgumentException if inputs are null
     */
    AttributeSet write(AttributeCatalogue catalogue, AttributeSet set, AttributeId id, AttributeValue value,
            AccessContext context);

    /**
     * Exports an attribute value after applying access control.
     *
     * <p>
     * Export may imply redaction. The exact redaction rules are
     * implementation-defined and should take attribute sensitivity and export
     * target into account.
     * </p>
     *
     * @param catalogue attribute catalogue used to resolve definitions
     * @param set       attribute set being exported from
     * @param id        attribute id
     * @param context   access context
     * @return exported value if present and allowed; empty otherwise
     * @throws IllegalArgumentException if inputs are null
     */
    Optional<AttributeValue> export(AttributeCatalogue catalogue, AttributeSet set, AttributeId id,
            AccessContext context);

    /**
     * Derives an attribute value from other inputs after applying access control.
     *
     * <p>
     * Derivation may be used to compute attributes such as fingerprints or
     * normalized identity fields.
     * </p>
     *
     * @param catalogue attribute catalogue used to resolve definitions
     * @param set       attribute set being modified
     * @param id        attribute id
     * @param context   access context
     * @return new attribute set instance containing the derived value
     *         (implementation-defined)
     * @throws IllegalArgumentException if inputs are null
     */
    AttributeSet derive(AttributeCatalogue catalogue, AttributeSet set, AttributeId id, AccessContext context);
}
