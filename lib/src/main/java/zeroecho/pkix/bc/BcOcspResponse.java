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

import java.io.IOException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import zeroecho.pkix.crl.CrlReason;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.ocsp.OcspResponse;
import zeroecho.pkix.ocsp.ResponderId;

/** BouncyCastle-backed parsed {@link OcspResponse}. */
final class BcOcspResponse implements OcspResponse {

    private final boolean successful;
    private final BasicOCSPResp basic;
    private final Instant producedAt;
    private final ResponderId responderId;
    private final List<SingleResponse> responses = new ArrayList<>();

    /* default */ BcOcspResponse(byte[] der) {
        try {
            OCSPResp outer = new OCSPResp(der);
            this.successful = outer.getStatus() == OCSPRespBuilder.SUCCESSFUL;
            if (!successful) {
                this.basic = null;
                this.producedAt = null;
                this.responderId = null;
                return;
            }
            this.basic = (BasicOCSPResp) outer.getResponseObject();
            this.producedAt = basic.getProducedAt().toInstant();
            this.responderId = responderId(basic.getResponderId().toASN1Primitive());
            for (SingleResp single : basic.getResponses()) {
                responses.add(new SingleResponse(certId(single), status(single.getCertStatus()),
                        single.getThisUpdate().toInstant(),
                        Optional.ofNullable(single.getNextUpdate()).map(java.util.Date::toInstant)));
            }
        } catch (OCSPException | IOException failure) {
            throw new IllegalArgumentException("Invalid OCSP response", failure);
        }
    }

    private static ResponderId responderId(ResponderID asn1) {
        if (asn1.getName() != null) {
            return ResponderId.byName(principal(asn1.getName()));
        }
        return ResponderId.byKey(asn1.getKeyHash());
    }

    private static X500Principal principal(X500Name name) {
        try {
            return new X500Principal(name.getEncoded());
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode responder name", failure);
        }
    }

    private static CertId certId(SingleResp single) {
        org.bouncycastle.asn1.ocsp.CertID asn1 = single.getCertID().toASN1Primitive();
        return new CertId(BcAlgorithmIdentifiers.fromBc(asn1.getHashAlgorithm()),
                asn1.getIssuerNameHash().getOctets(), asn1.getIssuerKeyHash().getOctets(),
                asn1.getSerialNumber().getValue());
    }

    private static CertStatus status(CertificateStatus status) {
        if (status == CertificateStatus.GOOD) {
            return CertStatus.good();
        }
        if (status instanceof RevokedStatus revoked) {
            Instant time = revoked.getRevocationTime().toInstant();
            if (revoked.hasRevocationReason()) {
                return CertStatus.revoked(time, reason(revoked.getRevocationReason()));
            }
            return new CertStatus.Revoked(time, Optional.empty());
        }
        return CertStatus.unknown();
    }

    private static CrlReason reason(int code) {
        for (CrlReason reason : CrlReason.values()) {
            if (reason.code() == code) {
                return reason;
            }
        }
        return CrlReason.UNSPECIFIED;
    }

    @Override
    public boolean isSuccessful() {
        return successful;
    }

    @Override
    public Instant producedAt() {
        return producedAt;
    }

    @Override
    public ResponderId responderId() {
        return responderId;
    }

    @Override
    public List<SingleResponse> responses() {
        return List.copyOf(responses);
    }

    @Override
    public boolean verifySignature(PublicKey responderKey) {
        if (!successful || basic == null) {
            return false;
        }
        try {
            return basic.isSignatureValid(new JcaContentVerifierProviderBuilder().build(responderKey));
        } catch (OCSPException | OperatorCreationException failure) {
            return false;
        }
    }

    @Override
    public Optional<byte[]> nonce() {
        if (basic == null) {
            return Optional.empty();
        }
        org.bouncycastle.asn1.x509.Extension extension = basic.getExtension(
                org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (extension == null) {
            return Optional.empty();
        }
        return Optional.of(org.bouncycastle.asn1.ASN1OctetString.getInstance(
                extension.getParsedValue()).getOctets());
    }

    @Override
    public List<java.security.cert.X509Certificate> certificates() {
        if (basic == null) {
            return List.of();
        }
        try {
            java.security.cert.CertificateFactory factory =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            List<java.security.cert.X509Certificate> result = new ArrayList<>();
            for (org.bouncycastle.cert.X509CertificateHolder holder : basic.getCerts()) {
                result.add((java.security.cert.X509Certificate) factory.generateCertificate(
                        new java.io.ByteArrayInputStream(holder.getEncoded())));
            }
            return List.copyOf(result);
        } catch (java.security.cert.CertificateException | IOException failure) {
            throw new IllegalArgumentException("Cannot decode responder certificates", failure);
        }
    }

    @Override
    public zeroecho.pkix.AlgorithmIdentifier signatureAlgorithm() {
        if (basic == null) {
            throw new IllegalStateException("Unsuccessful OCSP response has no signature algorithm");
        }
        return BcAlgorithmIdentifiers.fromBc(basic.getSignatureAlgorithmID());
    }
}
