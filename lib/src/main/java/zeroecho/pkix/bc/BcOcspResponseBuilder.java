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
package zeroecho.pkix.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;

import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.crl.CrlReason;
import zeroecho.pkix.ocsp.OcspResponseBuilder;
import zeroecho.pkix.ocsp.ResponderId;
import zeroecho.pkix.sign.ContentSigner;

/** BouncyCastle-backed {@link OcspResponseBuilder}. */
final class BcOcspResponseBuilder implements OcspResponseBuilder {

    private ResponderId responderId;
    private Instant producedAt;
    private byte[] nonce;
    private final List<SingleResponse> responses = new ArrayList<>();

    private record SingleResponse(CertId certId, CertStatus status, Instant thisUpdate, Instant nextUpdate) {
    }

    @Override
    public OcspResponseBuilder responderId(ResponderId responderId) {
        this.responderId = responderId;
        return this;
    }

    @Override
    public OcspResponseBuilder producedAt(Instant producedAt) {
        this.producedAt = producedAt;
        return this;
    }

    @Override
    public OcspResponseBuilder addResponse(CertId certId, CertStatus status, Instant thisUpdate,
            Instant nextUpdate) {
        responses.add(new SingleResponse(certId, status, thisUpdate, nextUpdate));
        return this;
    }

    @Override
    public OcspResponseBuilder nonce(byte[] nonce) {
        this.nonce = nonce == null ? null : nonce.clone();
        return this;
    }

    @Override
    public byte[] buildTbs() {
        try {
            return responseData().getEncoded(ASN1Encoding.DER);
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot assemble OCSP response data", failure);
        }
    }

    @Override
    public byte[] build(ContentSigner signer, List<X509Certificate> chain) {
        Objects.requireNonNull(responderId, "responderId");
        Objects.requireNonNull(producedAt, "producedAt");
        Objects.requireNonNull(signer, "signer");
        try {
            ResponseData data = responseData();
            ASN1Sequence certificates = BcOcspEncoding.certificates(chain);
            byte[] signature;
            try {
                try (OutputStream output = signer.contentStream()) {
                    output.write(data.getEncoded(ASN1Encoding.DER));
                }
                signature = Objects.requireNonNull(signer.signature(), "signature");
            } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Preserve the builder failure contract across the provider signer boundary.
                throw new IllegalStateException("Cannot sign OCSP response data", failure);
            }
            return BcOcspEncoding.assemble(data, BcAlgorithmIdentifiers.toBc(signer.algorithm()), signature, certificates);
        } catch (IOException | CertificateEncodingException failure) {
            throw new IllegalStateException("Cannot assemble OCSP response", failure);
        }
    }

    private ResponseData responseData() throws IOException {
        Objects.requireNonNull(responderId, "responderId");
        Objects.requireNonNull(producedAt, "producedAt");
        ASN1EncodableVector entries = new ASN1EncodableVector(responses.size());
        for (SingleResponse response : responses) {
            entries.add(new org.bouncycastle.asn1.ocsp.SingleResponse(toCertificateId(response.certId()), // NOPMD AvoidInstantiatingObjectsInLoops - Each wire response/certificate/extension requires its own distinct immutable encoding object.
                    toStatus(response.status()), new DERGeneralizedTime(Date.from(response.thisUpdate())), // NOPMD AvoidInstantiatingObjectsInLoops - Each wire response/certificate/extension requires its own distinct immutable encoding object.
                    response.nextUpdate() == null ? null : new DERGeneralizedTime(Date.from(response.nextUpdate())), // NOPMD AvoidInstantiatingObjectsInLoops - Each wire response/certificate/extension requires its own distinct immutable encoding object.
                    (Extensions) null));
        }
        Extensions extensions = null;
        if (nonce != null) {
            ExtensionsGenerator generator = new ExtensionsGenerator();
            generator.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
            extensions = generator.generate();
        }
        return new ResponseData(toRespId(responderId), new ASN1GeneralizedTime(Date.from(producedAt)),
                new DERSequence(entries), extensions);
    }

    private static ResponderID toRespId(ResponderId responderId) {
        return switch (responderId) {
            case ResponderId.ByName byName -> new ResponderID(BcExtensions.toX500Name(byName.name()));
            case ResponderId.ByKey byKey -> new ResponderID(new DEROctetString(byKey.keyHash()));
        };
    }

    private static org.bouncycastle.asn1.ocsp.CertID toCertificateId(CertId certId) {
        return new org.bouncycastle.asn1.ocsp.CertID(BcAlgorithmIdentifiers.toBc(certId.hashAlgorithm()),
                new DEROctetString(certId.issuerNameHash()), new DEROctetString(certId.issuerKeyHash()),
                new ASN1Integer(certId.serialNumber()));
    }

    private static org.bouncycastle.asn1.ocsp.CertStatus toStatus(CertStatus status) {
        return switch (status) {
            case CertStatus.Good ignored -> new org.bouncycastle.asn1.ocsp.CertStatus();
            case CertStatus.Unknown ignored -> new org.bouncycastle.asn1.ocsp.CertStatus(2, DERNull.INSTANCE);
            // Preserve the signed builder's existing unspecified-reason encoding.
            case CertStatus.Revoked revoked -> new org.bouncycastle.asn1.ocsp.CertStatus(new RevokedInfo(
                    new ASN1GeneralizedTime(Date.from(revoked.revocationTime())),
                    CRLReason.lookup(revoked.reason().map(CrlReason::code).orElse(0))));
        };
    }
}
