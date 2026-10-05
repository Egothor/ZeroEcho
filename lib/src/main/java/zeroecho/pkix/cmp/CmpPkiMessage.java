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
package zeroecho.pkix.cmp;

import java.math.BigInteger;

/**
 * Parsed representation of a CMP PKIMessage (RFC 4210 / RFC 9480).
 *
 * <p>Captures the fields most relevant to server-side processing. The raw
 * DER bytes are also preserved so the server can re-verify protection if
 * needed without re-encoding.</p>
 *
 * @param bodyType        CMP PKIBody type integer:
 *                        ir=0, ip=1, cr=2, cp=3, kur=7, kup=8,
 *                        rr=11, rp=12, genm=21, genp=22
 * @param senderNonce     senderNonce bytes from PKIHeader (nullable)
 * @param transactionId   transactionId bytes from PKIHeader (nullable)
 * @param certTemplateDer DER-encoded CertTemplate (for ir/cr/kur), nullable
 * @param issuerDer       DER-encoded issuer Name (for kur/rr), nullable
 * @param serialNumber    certificate serial number (for kur/rr), nullable
 * @param genMsgOid       first InfoType OID string from genm body (nullable)
 * @param hasProtection   true if the PKIMessage contained a protection value
 * @since 1.0
 */
public record CmpPkiMessage(
        int bodyType,
        byte[] senderNonce,
        byte[] transactionId,
        byte[] certTemplateDer,
        byte[] issuerDer,
        BigInteger serialNumber,
        String genMsgOid,
        boolean hasProtection) {
}
