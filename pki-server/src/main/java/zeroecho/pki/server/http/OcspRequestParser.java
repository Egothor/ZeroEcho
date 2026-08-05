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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;

import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.server.OcspRequesterService;

/** Narrow canonical DER and unpadded Base64url OCSP request decoder. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.ExceptionAsFlowControl", "PMD.PreserveStackTrace",
        "PMD.AvoidCatchingGenericException", "PMD.CyclomaticComplexity", "PMD.AvoidLiteralsInIfCondition" })
final class OcspRequestParser {
    /* default */ record Parsed(List<OcspResponseService.CertId> requests, Optional<byte[]> nonce,
            Optional<OcspRequesterService.SignedRequest> signedRequest) {
        Parsed {
            requests = List.copyOf(requests);
            nonce = nonce.map(byte[]::clone);
            signedRequest = Objects.requireNonNull(signedRequest, "signedRequest");
        }
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
        return parse(der, maximumEntries, acceptedHashes, maximumNonceBytes, 0, 0);
    }

    /* default */ static Parsed parse(byte[] der, int maximumEntries,
            Set<OcspResponseService.CertIdHash> acceptedHashes, int maximumNonceBytes,
            int maximumSignerCertificates, int maximumSignerChainBytes) {
        try {
            OCSPReq request = new OCSPReq(der);
            if (!Arrays.equals(der, request.getEncoded())) throw malformed();
            byte[] exactTbsRequest = firstSequenceElement(der);
            Req[] entries = request.getRequestList();
            if (entries.length == 0 || entries.length > maximumEntries) throw malformed();
            List<OcspResponseService.CertId> result = new ArrayList<>(entries.length);
            for (Req entry : entries) {
                if (entry.getSingleRequestExtensions() != null) throw malformed();
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
            Optional<OcspRequesterService.SignedRequest> signed = signedRequest(request, der, exactTbsRequest,
                    maximumSignerCertificates, maximumSignerChainBytes);
            if (signed.isEmpty() && request.getRequestorName() != null) throw malformed();
            return new Parsed(result, nonce, signed);
        } catch (IOException | RuntimeException failure) { throw malformed(); }
    }

    private static Optional<OcspRequesterService.SignedRequest> signedRequest(OCSPReq request, byte[] requestDer,
            byte[] exactTbsRequest, int maximumSignerCertificates, int maximumSignerChainBytes) throws IOException {
        if (!request.isSigned()) return Optional.empty();
        if (maximumSignerCertificates <= 0 || maximumSignerChainBytes <= 0) throw malformed();
        GeneralName requestor = request.getRequestorName();
        if (requestor == null || requestor.getTagNo() != GeneralName.directoryName) throw malformed();
        byte[] nameDer = requestor.getName().toASN1Primitive().getEncoded("DER");
        OCSPRequest structure = OCSPRequest.getInstance(ASN1Primitive.fromByteArray(requestDer));
        Signature signature = structure.getOptionalSignature();
        if (signature == null || signature.getSignature().getPadBits() != 0
                || signature.getSignature().getOctets().length == 0) throw malformed();
        byte[] algorithmDer = signature.getSignatureAlgorithm().getEncoded("DER");
        org.bouncycastle.cert.X509CertificateHolder[] holders = request.getCerts();
        if (holders.length == 0 || holders.length > maximumSignerCertificates) throw malformed();
        int total = 0;
        List<byte[]> certificates = new ArrayList<>(holders.length);
        Set<String> unique = new java.util.HashSet<>();
        for (org.bouncycastle.cert.X509CertificateHolder holder : holders) {
            byte[] certificate = holder.getEncoded();
            if (!Arrays.equals(certificate, ASN1Primitive.fromByteArray(certificate).getEncoded("DER"))) {
                throw malformed();
            }
            total = Math.addExact(total, certificate.length);
            if (total > maximumSignerChainBytes || !unique.add(Base64.getEncoder().encodeToString(certificate))) {
                throw malformed();
            }
            certificates.add(certificate);
        }
        return Optional.of(new OcspRequesterService.SignedRequest(exactTbsRequest, nameDer, algorithmDer,
                signature.getSignature().getOctets(), certificates));
    }

    private static byte[] firstSequenceElement(byte[] der) {
        if (der.length < 4 || Byte.toUnsignedInt(der[0]) != 0x30) throw malformed();
        Length outer = length(der, 1);
        int outerEnd = Math.addExact(outer.offset(), outer.length());
        if (outerEnd != der.length || outer.offset() >= outerEnd || Byte.toUnsignedInt(der[outer.offset()]) != 0x30) {
            throw malformed();
        }
        Length child = length(der, outer.offset() + 1);
        int childEnd = Math.addExact(child.offset(), child.length());
        if (childEnd > outerEnd) throw malformed();
        return Arrays.copyOfRange(der, outer.offset(), childEnd);
    }

    private static Length length(byte[] der, int offset) {
        if (offset >= der.length) throw malformed();
        int first = Byte.toUnsignedInt(der[offset]);
        if (first < 128) return new Length(offset + 1, first);
        int count = first & 0x7f;
        if (count == 0 || count > 4 || offset + count >= der.length || der[offset + 1] == 0) throw malformed();
        int value = 0;
        for (int index = 0; index < count; index++) value = Math.addExact(Math.multiplyExact(value, 256),
                Byte.toUnsignedInt(der[offset + index + 1]));
        if (value < 128) throw malformed();
        return new Length(offset + count + 1, value);
    }

    private record Length(int offset, int length) { }

    private static IllegalArgumentException malformed() {
        return new IllegalArgumentException("OCSP request is malformed");
    }
}
