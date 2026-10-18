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
package zeroecho.pkix.bc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.sign.ContentVerifier;

/** BouncyCastle-backed parsed {@link zeroecho.pkix.ocsp.OcspRequest}. */
// Immutable provider adapter exposes the parsed OCSP request contract without additional domain behavior.
@SuppressWarnings("PMD.DataClass")
final class BcOcspRequest implements zeroecho.pkix.ocsp.OcspRequest {

    private final List<CertId> requested = new ArrayList<>();
    private final Optional<byte[]> nonce;
    private final boolean signed;
    private final Optional<AlgorithmIdentifier> signatureAlgorithm;
    private final Optional<byte[]> toBeSigned;
    private final Optional<byte[]> signature;
    private final List<X509Certificate> signerCertificates = new ArrayList<>();

    /* default */ BcOcspRequest(byte[] der) {
        OCSPRequest request = OCSPRequest.getInstance(der);
        TBSRequest tbs = request.getTbsRequest();
        for (ASN1Encodable element : tbs.getRequestList()) {
            CertID certId = Request.getInstance(element).getReqCert();
            requested.add(new CertId(BcAlgorithmIdentifiers.fromBc(certId.getHashAlgorithm()),
                    certId.getIssuerNameHash().getOctets(), certId.getIssuerKeyHash().getOctets(),
                    certId.getSerialNumber().getValue()));
        }
        this.nonce = extractNonce(tbs.getRequestExtensions());
        Signature optionalSignature = request.getOptionalSignature();
        if (optionalSignature == null) {
            this.signed = false;
            this.signatureAlgorithm = Optional.empty();
            this.toBeSigned = Optional.empty();
            this.signature = Optional.empty();
        } else {
            this.signed = true;
            this.signatureAlgorithm = Optional.of(
                    BcAlgorithmIdentifiers.fromBc(optionalSignature.getSignatureAlgorithm()));
            this.toBeSigned = Optional.of(encode(tbs));
            this.signature = Optional.of(optionalSignature.getSignature().getOctets());
            extractCertificates(optionalSignature);
        }
    }

    private static Optional<byte[]> extractNonce(Extensions extensions) {
        if (extensions == null) {
            return Optional.empty();
        }
        Extension nonce = extensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonce == null) {
            return Optional.empty();
        }
        return Optional.of(ASN1OctetString.getInstance(nonce.getParsedValue()).getOctets());
    }

    private void extractCertificates(Signature optionalSignature) {
        if (optionalSignature.getCerts() == null) {
            return;
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (ASN1Encodable element : optionalSignature.getCerts()) {
                Certificate certificate = Certificate.getInstance(element);
                signerCertificates.add((X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(certificate.getEncoded(ASN1Encoding.DER))));
            }
        } catch (CertificateException | IOException failure) {
            throw new IllegalArgumentException("Invalid signer certificate in OCSP request", failure);
        }
    }

    private static byte[] encode(TBSRequest tbs) {
        try {
            return tbs.getEncoded(ASN1Encoding.DER);
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode OCSP tbsRequest", failure);
        }
    }

    @Override
    public List<CertId> requestedCertificates() {
        return List.copyOf(requested);
    }

    @Override
    public Optional<byte[]> nonce() {
        return nonce.map(byte[]::clone);
    }

    @Override
    public boolean isSigned() {
        return signed;
    }

    @Override
    public Optional<AlgorithmIdentifier> signatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public Optional<byte[]> toBeSigned() {
        return toBeSigned.map(byte[]::clone);
    }

    @Override
    public Optional<byte[]> signature() {
        return signature.map(byte[]::clone);
    }

    @Override
    public List<X509Certificate> signerCertificates() {
        return List.copyOf(signerCertificates);
    }

    @Override
    public boolean verifySignature(PublicKey signerKey) {
        if (!signed) {
            return false;
        }
        ContentVerifier verifier = new JcaContentVerifier(signerKey, signatureAlgorithm.orElseThrow());
        try (OutputStream stream = verifier.contentStream()) {
            stream.write(toBeSigned.orElseThrow());
        } catch (IOException failure) {
            return false;
        }
        return verifier.verify(signature.orElseThrow());
    }
}
