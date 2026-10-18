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
package zeroecho.pki.impl.core.continuation;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pkix.Pkix;
import zeroecho.pkix.ocsp.OcspResponse;
import zeroecho.pkix.ocsp.ResponderId;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.spi.store.PkiStore;

/** Publishes one frozen status continuation with exact restart validation. */
final class StatusContinuationPublisher {
    private static final String GENERATE_STATUS = "GENERATE_STATUS";
    private final PkiStore store;
    private final DomainContinuationPublisher support;
    private final DomainContentAccess contentAccess;

    /* default */ StatusContinuationPublisher(PkiStore store, DomainContinuationPublisher support) {
        this.store = Objects.requireNonNull(store, "store");
        this.support = Objects.requireNonNull(support, "support");
        this.contentAccess = new DomainContentAccess(store);
    }

    /* default */ void publish(DomainCommandEncoding.Decoded command, EncodedObject result) {
        if (!GENERATE_STATUS.equals(command.operation())) {
            throw new DomainContinuationPublisher.PostconditionFailure("STATUS_OPERATION_INVALID");
        }
        StatusObjectType type = StatusObjectType.valueOf(command.field(1));
        command.requireFields(type == StatusObjectType.OCSP ? 10 : 9);
        PkiId issuerCaId = new PkiId(command.field(0));
        FormatId format = new FormatId(command.field(2));
        Instant thisUpdate = Instant.parse(command.field(3));
        Instant nextUpdate = Instant.parse(command.field(4));
        AttributeSet attributes = DomainAttributeEncoding.decode(command.field(8));
        byte[] issuerDer = statusIssuer(attributes);
        validateStatus(result, issuerDer, thisUpdate, nextUpdate, type);
        byte[] der = result.bytes();
        String prefix = type == StatusObjectType.CRL || type == StatusObjectType.DELTA_CRL ? "crl:" : "status:";
        PkiId statusId = new PkiId(prefix + DomainContinuationPublisher.sha256(der));
        Optional<StatusObject> existing = store.getStatusObject(statusId);
        if (existing.isPresent()) {
            StatusObject exact = status(statusId, existing.orElseThrow().content(), format,
                    issuerCaId, type, thisUpdate, nextUpdate, attributes);
            requireStatus(existing.orElseThrow(), exact, der);
            Arrays.fill(der, (byte) 0);
            return;
        }
        publishNew(statusId, format, issuerCaId, type, thisUpdate, nextUpdate, attributes, der);
    }

    private void publishNew(PkiId statusId, FormatId format, PkiId issuerCaId, StatusObjectType type,
            Instant thisUpdate, Instant nextUpdate, AttributeSet attributes, byte[] der) {
        DurableContentReference content = support.persist(der);
        boolean published = false;
        try {
            store.putStatusObject(status(statusId, content, format, issuerCaId,
                    type, thisUpdate, nextUpdate, attributes));
            published = true;
            DomainContinuationPublisher.afterDurablePublication(
                    DomainContinuationPublisher.PublicationFaultPoint.AFTER_STATUS);
        } finally {
            Arrays.fill(der, (byte) 0);
            support.releaseUnlessPublished(content, published);
        }
    }

    private static StatusObject status(PkiId statusId, DurableContentReference content, FormatId format,
            PkiId issuerCaId, StatusObjectType type, Instant thisUpdate, Instant nextUpdate,
            AttributeSet attributes) {
        return new StatusObject(statusId, format, issuerCaId, type, thisUpdate,
                Optional.of(nextUpdate), content, attributes);
    }

    private static byte[] statusIssuer(AttributeSet attributes) {
        return attributes.get(BcX509Attributes.ISSUER_CERT_DER)
                .filter(AttributeValue.BytesValue.class::isInstance)
                .map(AttributeValue.BytesValue.class::cast)
                .map(AttributeValue.BytesValue::value)
                .map(byte[]::clone)
                .orElseThrow(() -> new DomainContinuationPublisher.PostconditionFailure(
                        "STATUS_ISSUER_UNAVAILABLE"));
    }

    private static void validateStatus(EncodedObject result, byte[] issuerDer,
            Instant thisUpdate, Instant nextUpdate, StatusObjectType type) {
        try {
            if (type == StatusObjectType.OCSP) {
                validateOcsp(result, issuerDer, thisUpdate, nextUpdate);
            } else {
                validateCrl(result, issuerDer, thisUpdate, nextUpdate);
            }
        } finally {
            Arrays.fill(issuerDer, (byte) 0);
        }
    }

    private static void validateCrl(EncodedObject result, byte[] issuerDer,
            Instant thisUpdate, Instant nextUpdate) {
        try {
            X509CRL crl = Pkix.parseCrl(result.bytes());
            X509Certificate issuer = Pkix.parseCertificate(issuerDer);
            if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                    || !crl.getThisUpdate().toInstant().equals(thisUpdate)
                    || crl.getNextUpdate() == null
                    || !crl.getNextUpdate().toInstant().equals(nextUpdate)) {
                throw new DomainContinuationPublisher.PostconditionFailure("STATUS_OBJECT_DIFFERS");
            }
            crl.verify(issuer.getPublicKey());
        } catch (java.security.GeneralSecurityException | IllegalArgumentException malformed) {
            throw new DomainContinuationPublisher.PostconditionFailure("STATUS_OBJECT_INVALID", malformed);
        }
    }

    private static void validateOcsp(EncodedObject result, byte[] issuerDer,
            Instant thisUpdate, Instant nextUpdate) {
        try {
            OcspResponse response = Pkix.parseOcspResponse(result.bytes());
            X509Certificate issuer = Pkix.parseCertificate(issuerDer);
            java.util.List<OcspResponse.SingleResponse> responses = response.responses();
            if (!response.isSuccessful()
                    || !response.producedAt().equals(thisUpdate)
                    || !response.responderId().equals(ResponderId.byName(issuer.getSubjectX500Principal()))
                    || responses.size() != 1
                    || !responses.get(0).thisUpdate().equals(thisUpdate)
                    || responses.get(0).nextUpdate().isEmpty()
                    || !responses.get(0).nextUpdate().orElseThrow().equals(nextUpdate)
                    || !response.verifySignature(issuer.getPublicKey())) {
                throw new DomainContinuationPublisher.PostconditionFailure("STATUS_OBJECT_DIFFERS");
            }
        } catch (IllegalArgumentException malformed) {
            throw new DomainContinuationPublisher.PostconditionFailure("STATUS_OBJECT_INVALID", malformed);
        }
    }

    private void requireStatus(StatusObject actual, StatusObject expected, byte[] der) {
        if (!actual.statusObjectId().equals(expected.statusObjectId())
                || !actual.formatId().equals(expected.formatId())
                || !actual.issuerCaId().equals(expected.issuerCaId())
                || actual.type() != expected.type()
                || !actual.thisUpdate().equals(expected.thisUpdate())
                || !actual.nextUpdate().equals(expected.nextUpdate())
                || !DomainAttributeEncoding.encode(actual.attributes())
                        .equals(DomainAttributeEncoding.encode(expected.attributes()))) {
            throw new DomainContinuationPublisher.PostconditionFailure("PUBLISHED_STATUS_DIFFERS");
        }
        contentAccess.requireExact(actual.content(), der, "PUBLISHED_STATUS_CONTENT_DIFFERS");
    }
}
