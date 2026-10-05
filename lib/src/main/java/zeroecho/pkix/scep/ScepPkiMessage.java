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
package zeroecho.pkix.scep;

import java.security.cert.X509Certificate;

/**
 * Parsed representation of a SCEP PKIOperation message.
 *
 * <p>All SCEP protocol messages (PKCSReq, GetCertInitial, GetCert, GetCRL) are
 * transported as CMS SignedData. This record captures the authenticated attributes
 * and inner content extracted by {@link ScepCodec#parsePkiOperationDer}.</p>
 *
 * @param messageType    SCEP message type integer (e.g., 19=PKCSReq, 20=GetCertInitial)
 * @param transactionId  SCEP transaction identifier string
 * @param senderNonce    senderNonce octet string (16 bytes, nullable if absent)
 * @param innerContent   decrypted inner content bytes (PKCS#10 CSR DER for PKCSReq,
 *                       IssuerAndSubject DER for GetCertInitial, IssuerAndSerialNumber
 *                       DER for GetCert/GetCRL; raw encap content for others)
 * @param requesterCert  the signing certificate carried in the outer CMS SignedData
 *                       (the requester's self-signed certificate)
 * @since 1.0
 */
public record ScepPkiMessage(
        int messageType,
        String transactionId,
        byte[] senderNonce,
        byte[] innerContent,
        X509Certificate requesterCert) {
}
