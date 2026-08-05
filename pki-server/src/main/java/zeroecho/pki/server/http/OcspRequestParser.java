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
package zeroecho.pki.server.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;

import zeroecho.pki.application.OcspResponseService;

/** Narrow canonical DER and unpadded Base64url OCSP request decoder. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.ExceptionAsFlowControl", "PMD.PreserveStackTrace",
        "PMD.AvoidCatchingGenericException", "PMD.CyclomaticComplexity" })
final class OcspRequestParser {
    /* default */ record Parsed(List<OcspResponseService.CertId> requests, Optional<byte[]> nonce) {
        Parsed { requests = List.copyOf(requests); nonce = nonce.map(byte[]::clone); }
        @Override public Optional<byte[]> nonce() { return nonce.map(byte[]::clone); }
    }

    private OcspRequestParser() { }

    /* default */ static byte[] decodeGet(String encoded, int maximumBytes) {
        if (encoded.isEmpty() || encoded.length() > Math.addExact(maximumBytes * 2, 8)
                || !encoded.matches("[A-Za-z0-9_-]+") || encoded.indexOf('=') >= 0) throw malformed();
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encoded);
            if (decoded.length > maximumBytes || !Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(decoded).equals(encoded)) throw malformed();
            return decoded;
        } catch (IllegalArgumentException failure) { throw malformed(); }
    }

    /* default */ static Parsed parse(byte[] der, int maximumEntries,
            Set<OcspResponseService.CertIdHash> acceptedHashes, int maximumNonceBytes) {
        try {
            OCSPReq request = new OCSPReq(der);
            if (!Arrays.equals(der, request.getEncoded()) || request.isSigned()) throw malformed();
            Req[] entries = request.getRequestList();
            if (entries.length == 0 || entries.length > maximumEntries) throw malformed();
            List<OcspResponseService.CertId> result = new ArrayList<>(entries.length);
            for (Req entry : entries) {
                CertificateID id = entry.getCertID();
                org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm = id.toASN1Primitive().getHashAlgorithm();
                OcspResponseService.CertIdHash hash;
                if (OIWObjectIdentifiers.idSHA1.equals(id.getHashAlgOID())
                        && DERNull.INSTANCE.equals(algorithm.getParameters())) {
                    hash = OcspResponseService.CertIdHash.SHA1;
                } else if (NISTObjectIdentifiers.id_sha256.equals(id.getHashAlgOID())
                        && algorithm.getParameters() == null) {
                    hash = OcspResponseService.CertIdHash.SHA256;
                }
                else throw malformed();
                if (!acceptedHashes.contains(hash)) throw malformed();
                result.add(new OcspResponseService.CertId(hash, id.getIssuerNameHash(),
                        id.getIssuerKeyHash(), id.getSerialNumber()));
            }
            List<?> extensionIds = request.getExtensionOIDs();
            if (extensionIds.size() > 1 || extensionIds.stream().anyMatch(
                    oid -> !OCSPObjectIdentifiers.id_pkix_ocsp_nonce.equals(oid))) throw malformed();
            Optional<byte[]> nonce = Optional.empty();
            if (!extensionIds.isEmpty()) {
                org.bouncycastle.asn1.x509.Extension extension = request.getExtension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                if (extension == null || extension.isCritical()) throw malformed();
                byte[] value = ASN1OctetString.getInstance(extension.getParsedValue()).getOctets();
                if (value.length == 0 || value.length > maximumNonceBytes) throw malformed();
                nonce = Optional.of(value);
            }
            return new Parsed(result, nonce);
        } catch (IOException | RuntimeException failure) { throw malformed(); }
    }

    private static IllegalArgumentException malformed() {
        return new IllegalArgumentException("OCSP request is malformed");
    }
}
