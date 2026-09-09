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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;

import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.CertStatus;
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
    public byte[] build(ContentSigner signer, List<X509Certificate> chain) {
        Objects.requireNonNull(responderId, "responderId");
        Objects.requireNonNull(producedAt, "producedAt");
        Objects.requireNonNull(signer, "signer");
        try {
            BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(toRespId(responderId));
            for (SingleResponse response : responses) {
                builder.addResponse(toCertificateId(response.certId()), toStatus(response.status()),
                        Date.from(response.thisUpdate()),
                        response.nextUpdate() == null ? null : Date.from(response.nextUpdate()), (Extensions) null);
            }
            if (nonce != null) {
                ExtensionsGenerator generator = new ExtensionsGenerator();
                generator.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                        new DEROctetString(nonce));
                builder.setResponseExtensions(generator.generate());
            }
            BasicOCSPResp basic = builder.build(new BcContentSignerAdapter(signer), toHolders(chain),
                    Date.from(producedAt));
            return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
        } catch (OCSPException | IOException | CertificateEncodingException failure) {
            throw new IllegalStateException("Cannot assemble OCSP response", failure);
        }
    }

    private static RespID toRespId(ResponderId responderId) {
        return switch (responderId) {
            case ResponderId.ByName byName -> new RespID(BcExtensions.toX500Name(byName.name()));
            case ResponderId.ByKey byKey ->
                    new RespID(new ResponderID(new DEROctetString(byKey.keyHash())));
        };
    }

    private static CertificateID toCertificateId(CertId certId) {
        org.bouncycastle.asn1.ocsp.CertID asn1 = new org.bouncycastle.asn1.ocsp.CertID(
                BcAlgorithmIdentifiers.toBc(certId.hashAlgorithm()),
                new DEROctetString(certId.issuerNameHash()), new DEROctetString(certId.issuerKeyHash()),
                new ASN1Integer(certId.serialNumber()));
        return new CertificateID(asn1);
    }

    private static CertificateStatus toStatus(CertStatus status) {
        return switch (status) {
            case CertStatus.Good ignored -> CertificateStatus.GOOD;
            case CertStatus.Unknown ignored -> new UnknownStatus();
            case CertStatus.Revoked revoked -> revoked.reason()
                    .map(reason -> new RevokedStatus(Date.from(revoked.revocationTime()), reason.code()))
                    .orElseGet(() -> new RevokedStatus(Date.from(revoked.revocationTime()), 0));
        };
    }

    private static X509CertificateHolder[] toHolders(List<X509Certificate> chain)
            throws IOException, CertificateEncodingException {
        List<X509CertificateHolder> holders = new ArrayList<>();
        for (X509Certificate certificate : chain) {
            holders.add(new X509CertificateHolder(certificate.getEncoded()));
        }
        return holders.toArray(new X509CertificateHolder[0]);
    }
}
