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
package zeroecho.pki.api.status;

import java.time.Instant;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Generated status object used for revocation distribution.
 *
 * <p>
 * For X.509 this represents CRLs or delta CRLs. For other frameworks it can
 * represent analogous revocation lists. OCSP representation is
 * implementation-defined but still transported using this container for
 * uniformity.
 * </p>
 *
 * @param statusObjectId stable identifier of the status object
 * @param formatId       framework format id
 * @param issuerCaId     issuer CA entity id
 * @param type           status object type
 * @param thisUpdate     time of issuance/publication baseline
 * @param nextUpdate     optional next update timestamp
 * @param encoded        encoded payload
 * @param attributes     universal attributes describing the object (must not
 *                       contain secrets)
 */
public record StatusObject(PkiId statusObjectId, FormatId formatId, PkiId issuerCaId, StatusObjectType type,
        Instant thisUpdate, Optional<Instant> nextUpdate, EncodedObject encoded, AttributeSet attributes) {

    /**
     * Creates a status object.
     *
     * @throws IllegalArgumentException if mandatory inputs are null or optional
     *                                  container is null
     */
    public StatusObject {
        if (statusObjectId == null) {
            throw new IllegalArgumentException("statusObjectId must not be null");
        }
        if (formatId == null) {
            throw new IllegalArgumentException("formatId must not be null");
        }
        if (issuerCaId == null) {
            throw new IllegalArgumentException("issuerCaId must not be null");
        }
        if (type == null) {
            throw new IllegalArgumentException("type must not be null");
        }
        if (thisUpdate == null) {
            throw new IllegalArgumentException("thisUpdate must not be null");
        }
        if (nextUpdate == null) {
            throw new IllegalArgumentException("nextUpdate must not be null");
        }
        if (encoded == null) {
            throw new IllegalArgumentException("encoded must not be null");
        }
        if (attributes == null) {
            throw new IllegalArgumentException("attributes must not be null");
        }
    }
}
