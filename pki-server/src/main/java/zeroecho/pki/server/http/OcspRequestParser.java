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
package zeroecho.pki.server.http;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.OcspRequest;

import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.server.OcspRequesterService;

/** Narrow canonical DER and unpadded Base64url OCSP request decoder. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.ExceptionAsFlowControl", "PMD.PreserveStackTrace",
        "PMD.AvoidCatchingGenericException", "PMD.CyclomaticComplexity", "PMD.AvoidLiteralsInIfCondition" })
final class OcspRequestParser {
    private static final String OID_SHA1 = "1.3.14.3.2.26";
    private static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    private static final String OID_NONCE = "1.3.6.1.5.5.7.48.1.2";

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
            byte[] exactTbsRequest = firstSequenceElement(der);
            OcspRequest request = Pkix.parseOcspRequest(der);
            TbsRequestView view = TbsRequestView.parse(exactTbsRequest);
            if (view.singleRequestExtensions()) throw malformed();

            List<CertId> requested = request.requestedCertificates();
            if (requested.isEmpty() || requested.size() > maximumEntries) throw malformed();
            List<OcspResponseService.CertId> result = new ArrayList<>(requested.size());
            for (CertId id : requested) {
                OcspResponseService.CertIdHash hash = certIdHash(id.hashAlgorithm());
                if (!acceptedHashes.contains(hash)) throw malformed();
                result.add(new OcspResponseService.CertId(hash, id.issuerNameHash(), id.issuerKeyHash(),
                        id.serialNumber()));
            }

            List<CertificateExtension> extensions = view.requestExtensions();
            if (extensions.size() > 1) throw malformed();
            Optional<byte[]> nonce = Optional.empty();
            if (!extensions.isEmpty()) {
                CertificateExtension extension = extensions.getFirst();
                if (!OID_NONCE.equals(extension.oid()) || extension.critical()) throw malformed();
                byte[] value = request.nonce().orElseThrow(OcspRequestParser::malformed);
                if (value.length == 0 || value.length > maximumNonceBytes) throw malformed();
                nonce = Optional.of(value);
            }

            Optional<OcspRequesterService.SignedRequest> signed = signedRequest(request, view, exactTbsRequest,
                    maximumSignerCertificates, maximumSignerChainBytes);
            if (signed.isEmpty() && view.requestorNamePresent()) throw malformed();
            return new Parsed(result, nonce, signed);
        } catch (RuntimeException failure) { throw malformed(); }
    }

    private static OcspResponseService.CertIdHash certIdHash(AlgorithmIdentifier algorithm) {
        if (OID_SHA1.equals(algorithm.oid())
                && algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.DER_NULL) {
            return OcspResponseService.CertIdHash.SHA1;
        }
        if (OID_SHA256.equals(algorithm.oid())
                && algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.ABSENT) {
            return OcspResponseService.CertIdHash.SHA256;
        }
        throw malformed();
    }

    private static Optional<OcspRequesterService.SignedRequest> signedRequest(OcspRequest request,
            TbsRequestView view, byte[] exactTbsRequest, int maximumSignerCertificates,
            int maximumSignerChainBytes) {
        if (!request.isSigned()) return Optional.empty();
        if (maximumSignerCertificates <= 0 || maximumSignerChainBytes <= 0) throw malformed();
        byte[] nameDer = view.requestorNameDirectory().orElseThrow(OcspRequestParser::malformed);
        byte[] signature = request.signature().orElseThrow(OcspRequestParser::malformed);
        if (signature.length == 0) throw malformed();
        byte[] algorithmDer = Pkix.encodeAlgorithmIdentifier(
                request.signatureAlgorithm().orElseThrow(OcspRequestParser::malformed));
        List<X509Certificate> signers = request.signerCertificates();
        if (signers.isEmpty() || signers.size() > maximumSignerCertificates) throw malformed();
        int total = 0;
        List<byte[]> certificates = new ArrayList<>(signers.size());
        Set<String> unique = new HashSet<>();
        for (X509Certificate signer : signers) {
            byte[] certificate;
            try {
                certificate = signer.getEncoded();
            } catch (CertificateEncodingException failure) {
                throw malformed();
            }
            total = Math.addExact(total, certificate.length);
            if (total > maximumSignerChainBytes || !unique.add(Base64.getEncoder().encodeToString(certificate))) {
                throw malformed();
            }
            certificates.add(certificate);
        }
        return Optional.of(new OcspRequesterService.SignedRequest(exactTbsRequest, nameDer, algorithmDer,
                signature, certificates));
    }

    /**
     * A minimal structural view of the exact {@code tbsRequest} DER, used to enforce
     * strictness the high-level {@link OcspRequest} does not expose: the presence and
     * form of {@code requestorName}, whether any per-request {@code singleRequestExtensions}
     * are present, and the request-level extensions (for canonical nonce validation).
     */
    private record TbsRequestView(boolean requestorNamePresent, Optional<byte[]> requestorNameDirectory,
            boolean singleRequestExtensions, List<CertificateExtension> requestExtensions) {

        private static TbsRequestView parse(byte[] tbs) {
            Tlv outer = readTlv(tbs, 0, tbs.length);
            if (outer.tag() != 0x30 || outer.end() != tbs.length) throw malformed();
            boolean requestorNamePresent = false;
            Optional<byte[]> requestorNameDirectory = Optional.empty();
            boolean singleRequestExtensions = false;
            List<CertificateExtension> requestExtensions = List.of();
            int position = outer.contentStart();
            while (position < outer.end()) {
                Tlv field = readTlv(tbs, position, outer.end());
                switch (field.tag()) {
                    case 0xA0 -> { }
                    case 0xA1 -> {
                        requestorNamePresent = true;
                        Tlv generalName = readTlv(tbs, field.contentStart(), field.end());
                        if (generalName.tag() == 0xA4) {
                            Tlv name = readTlv(tbs, generalName.contentStart(), generalName.end());
                            if (name.tag() != 0x30) throw malformed();
                            requestorNameDirectory = Optional.of(
                                    Arrays.copyOfRange(tbs, generalName.contentStart(), name.end()));
                        }
                    }
                    case 0x30 -> singleRequestExtensions = scanRequestList(tbs, field);
                    case 0xA2 -> {
                        Tlv sequence = readTlv(tbs, field.contentStart(), field.end());
                        if (sequence.tag() != 0x30) throw malformed();
                        requestExtensions = Pkix.parseExtensions(
                                Arrays.copyOfRange(tbs, field.contentStart(), sequence.end()));
                    }
                    default -> throw malformed();
                }
                position = field.end();
            }
            return new TbsRequestView(requestorNamePresent, requestorNameDirectory, singleRequestExtensions,
                    requestExtensions);
        }

        private static boolean scanRequestList(byte[] tbs, Tlv requestList) {
            boolean singleRequestExtensions = false;
            int position = requestList.contentStart();
            while (position < requestList.end()) {
                Tlv entry = readTlv(tbs, position, requestList.end());
                if (entry.tag() != 0x30) throw malformed();
                Tlv certId = readTlv(tbs, entry.contentStart(), entry.end());
                if (certId.tag() != 0x30) throw malformed();
                if (certId.end() < entry.end() && readTlv(tbs, certId.end(), entry.end()).tag() == 0xA0) {
                    singleRequestExtensions = true;
                }
                position = entry.end();
            }
            return singleRequestExtensions;
        }
    }

    private record Tlv(int tag, int contentStart, int contentLength, int end) { }

    private static Tlv readTlv(byte[] der, int offset, int limit) {
        if (offset >= limit) throw malformed();
        int tag = Byte.toUnsignedInt(der[offset]);
        Length content = length(der, offset + 1);
        int end = Math.addExact(content.offset(), content.length());
        if (end > limit) throw malformed();
        return new Tlv(tag, content.offset(), content.length(), end);
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
