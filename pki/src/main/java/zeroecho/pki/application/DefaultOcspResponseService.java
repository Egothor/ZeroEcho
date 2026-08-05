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
package zeroecho.pki.application;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.framework.x509.bc.PkiBusContentSigner;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationView;

/** Store-backed, signing-bus-confined OCSP response application service. */
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.CyclomaticComplexity",
        "PMD.PreserveStackTrace", "PMD.ExceptionAsFlowControl", "PMD.SignatureDeclareThrowsException",
        "PMD.NPathComplexity", "PMD.ControlStatementBraces", "PMD.UseVarargs" })
final class DefaultOcspResponseService implements OcspResponseService {
    private final PkiStore store;
    private final PkiSigningBus bus;
    private final Duration signingTtl;
    private final Runnable requireOpen;

    /* default */ DefaultOcspResponseService(PkiStore store, PkiSigningBus bus, Duration signingTtl,
            Runnable requireOpen) {
        this.store = Objects.requireNonNull(store, "store");
        this.bus = Objects.requireNonNull(bus, "bus");
        this.signingTtl = Objects.requireNonNull(signingTtl, "signingTtl");
        this.requireOpen = Objects.requireNonNull(requireOpen, "requireOpen");
    }

    @Override public Response respond(Command command) {
        requireOpen.run();
        Objects.requireNonNull(command, "command");
        try {
            X509CertificateHolder issuer = certificate(command.issuerCredentialId());
            X509CertificateHolder responder = certificate(command.responderCredentialId());
            validateAuthority(command, issuer, responder);
            List<Resolved> resolved;
            long revision;
            String commitment;
            try (RevocationView view = store.openRevocationView()) {
                revision = view.revision();
                commitment = view.commitment();
                resolved = resolve(command, issuer, view);
            }
            int good = Math.toIntExact(resolved.stream().filter(value -> value.status() == CertificateStatus.GOOD)
                    .count());
            int revoked = Math.toIntExact(resolved.stream().filter(value -> value.status() instanceof RevokedStatus)
                    .count());
            int unknown = Math.subtractExact(resolved.size(), Math.addExact(good, revoked));
            return new Response(sign(command, responder, resolved), revision, commitment, good, revoked, unknown);
        } catch (Exception failure) {
            throw new PkiException("OCSP response generation failed: code=OCSP_RESPONSE_FAILED");
        }
    }

    @Override public void validateSigningBinding(zeroecho.pki.api.PkiId responderCredentialId,
            zeroecho.pki.api.KeyRef signingKeyRef, String signatureAlgorithm,
            Optional<String> signatureBindingId) {
        requireOpen.run();
        Objects.requireNonNull(responderCredentialId, "responderCredentialId");
        Objects.requireNonNull(signingKeyRef, "signingKeyRef");
        Objects.requireNonNull(signatureBindingId, "signatureBindingId");
        byte[] challenge = "ZeroEcho OCSP signing binding v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        try {
            X509CertificateHolder responder = certificate(responderCredentialId);
            AlgorithmIdentity identity = bus.authority().resolveIdentity(signatureAlgorithm);
            PkiBusContentSigner signer = signatureBindingId.isPresent()
                    ? new PkiBusContentSigner(bus, signingKeyRef, identity, signatureBindingId.orElseThrow(), signingTtl)
                    : new PkiBusContentSigner(bus, signingKeyRef, identity, signingTtl);
            try (java.io.OutputStream output = signer.getOutputStream()) { output.write(challenge); }
            org.bouncycastle.operator.ContentVerifier verifier =
                    new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(responder)
                            .get(signer.getAlgorithmIdentifier());
            try (java.io.OutputStream output = verifier.getOutputStream()) { output.write(challenge); }
            if (!verifier.verify(signer.getSignature())) {
                throw new IOException("OCSP signing binding differs");
            }
        } catch (Exception failure) {
            throw new PkiException("OCSP signing binding validation failed: code=OCSP_SIGNING_BINDING_FAILED");
        }
    }

    private List<Resolved> resolve(Command command, X509CertificateHolder issuer, RevocationView view)
            throws Exception {
        List<Resolved> result = new ArrayList<>(command.requests().size());
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        for (CertId request : command.requests()) {
            DigestCalculator digest = digests.get(CertificateID.HASH_SHA1);
            if (request.hash() == CertIdHash.SHA256) {
                digest = digests.get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256));
            }
            CertificateID id = new CertificateID(digest, issuer, request.serial());
            if (!MessageDigest.isEqual(id.getIssuerNameHash(), request.issuerNameHash())
                    || !MessageDigest.isEqual(id.getIssuerKeyHash(), request.issuerKeyHash())) {
                result.add(new Resolved(id, new UnknownStatus()));
                continue;
            }
            Credential credential = store.getCredentialByIssuerAndSerial(command.issuerId(), request.serial())
                    .orElse(null);
            if (credential == null) {
                result.add(new Resolved(id, new UnknownStatus()));
                continue;
            }
            CertificateStatus status = view.get(credential.credentialId())
                    .map(record -> status(record.transition().state(), record.transition().time(),
                            record.transition().permanentReason().orElse(RevocationReason.UNSPECIFIED)))
                    .orElse(CertificateStatus.GOOD);
            result.add(new Resolved(id, status));
        }
        return List.copyOf(result);
    }

    private byte[] sign(Command command, X509CertificateHolder responder, List<Resolved> resolved)
            throws Exception {
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        BasicOCSPRespBuilder builder = command.responderId() == ResponderId.BY_NAME
                ? new BasicOCSPRespBuilder(new RespID(responder.getSubject()))
                : new BasicOCSPRespBuilder(new RespID(responder.getSubjectPublicKeyInfo(),
                        digests.get(CertificateID.HASH_SHA1)));
        for (Resolved item : resolved) {
            builder.addResponse(item.id(), item.status(), Date.from(command.thisUpdate()),
                    Date.from(command.nextUpdate()), null);
        }
        if (command.nonce().isPresent()) {
            builder.setResponseExtensions(new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                    false, new DEROctetString(new DEROctetString(command.nonce().orElseThrow()).getEncoded()))));
        }
        AlgorithmIdentity identity = bus.authority().resolveIdentity(command.signatureAlgorithm());
        PkiBusContentSigner signer = command.signatureBindingId().isPresent()
                ? new PkiBusContentSigner(bus, command.signingKeyRef(), identity,
                        command.signatureBindingId().orElseThrow(), signingTtl)
                : new PkiBusContentSigner(bus, command.signingKeyRef(), identity, signingTtl);
        X509CertificateHolder[] chain = new X509CertificateHolder[command.responseChain().size()];
        for (int index = 0; index < chain.length; index++) chain[index] = certificate(command.responseChain().get(index));
        BasicOCSPResp basic = builder.build(signer, chain, Date.from(command.producedAt()));
        OCSPResp outer = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic);
        byte[] encoded = outer.getEncoded();
        OCSPResp decodedOuter = new OCSPResp(encoded);
        BasicOCSPResp decoded = (BasicOCSPResp) decodedOuter.getResponseObject();
        if (!Arrays.equals(encoded, decodedOuter.getEncoded())
                || decodedOuter.getStatus() != OCSPRespBuilder.SUCCESSFUL
                || decoded == null || !decoded.getProducedAt().equals(Date.from(command.producedAt()))
                || !decoded.getResponderId().equals(basic.getResponderId())
                || !decoded.getSignatureAlgorithmID().equals(signer.getAlgorithmIdentifier())
                || !decoded.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                        .build(responder))
                || !matchesResponses(decoded.getResponses(), resolved, command)
                || !matchesCertificates(decoded.getCerts(), chain)
                || !matchesNonce(decoded, command.nonce())) {
            throw new IOException("Generated OCSP response validation failed");
        }
        return encoded;
    }

    private static boolean matchesResponses(SingleResp[] decoded, List<Resolved> expected, Command command) {
        if (decoded.length != expected.size()) return false;
        for (int index = 0; index < decoded.length; index++) {
            SingleResp actual = decoded[index]; Resolved wanted = expected.get(index);
            if (!actual.getCertID().equals(wanted.id())
                    || !actual.getThisUpdate().equals(Date.from(command.thisUpdate()))
                    || !actual.getNextUpdate().equals(Date.from(command.nextUpdate()))
                    || !sameStatus(actual.getCertStatus(), wanted.status())) return false;
        }
        return true;
    }

    private static boolean sameStatus(CertificateStatus actual, CertificateStatus expected) {
        if (actual == CertificateStatus.GOOD || expected == CertificateStatus.GOOD) {
            return actual == CertificateStatus.GOOD && expected == CertificateStatus.GOOD;
        }
        if (actual instanceof UnknownStatus && expected instanceof UnknownStatus) return true;
        if (actual instanceof RevokedStatus left && expected instanceof RevokedStatus right) {
            return left.getRevocationTime().equals(right.getRevocationTime())
                    && left.hasRevocationReason() == right.hasRevocationReason()
                    && (!left.hasRevocationReason() || left.getRevocationReason() == right.getRevocationReason());
        }
        return false;
    }

    private static boolean matchesCertificates(X509CertificateHolder[] decoded, X509CertificateHolder[] expected)
            throws IOException {
        if (decoded.length != expected.length) return false;
        for (int index = 0; index < decoded.length; index++) {
            if (!Arrays.equals(decoded[index].getEncoded(), expected[index].getEncoded())) return false;
        }
        return true;
    }

    private static boolean matchesNonce(BasicOCSPResp decoded, Optional<byte[]> expected) {
        Extension extension = decoded.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (expected.isEmpty()) return extension == null;
        if (extension == null || extension.isCritical()) return false;
        byte[] actual = org.bouncycastle.asn1.ASN1OctetString.getInstance(extension.getParsedValue()).getOctets();
        return MessageDigest.isEqual(actual, expected.orElseThrow());
    }

    private void validateAuthority(Command command, X509CertificateHolder issuer,
            X509CertificateHolder responder) {
        zeroecho.pki.api.ca.IssuerGeneration generation = store.getIssuerGeneration(command.issuerId())
                .orElseThrow(() -> new IllegalArgumentException("OCSP issuer is unavailable"));
        if (!generation.authorityId().equals(command.authorityId())
                || !generation.credentialId().equals(command.issuerCredentialId())
                || !command.signingKeyRef().equals(generation.signingKeyRef())
                        && command.responderCredentialId().equals(command.issuerCredentialId())) {
            throw new IllegalArgumentException("OCSP responder authority mismatch");
        }
        if (issuer.getSerialNumber().signum() <= 0 || responder.getSerialNumber().signum() <= 0) {
            throw new IllegalArgumentException("OCSP responder certificate is invalid");
        }
        if (!responder.isValidOn(Date.from(command.producedAt()))
                || command.nextUpdate().isAfter(responder.getNotAfter().toInstant())) {
            throw new IllegalArgumentException("OCSP response exceeds responder signing validity");
        }
    }

    private X509CertificateHolder certificate(zeroecho.pki.api.PkiId credentialId) throws IOException {
        try (PkiRepositoryContent content = new DefaultPkiRepository(store, requireOpen)
                .openCredential(credentialId); InputStream input = content.openStream()) {
            byte[] encoded = input.readNBytes(1_048_577);
            if (encoded.length > 1_048_576 || input.read() != -1) {
                throw new IOException("OCSP certificate exceeds its finite bound");
            }
            return new X509CertificateHolder(encoded);
        }
    }

    private static CertificateStatus status(RevocationState state, java.time.Instant time,
            RevocationReason reason) {
        return switch (state) {
            case CLEAR -> CertificateStatus.GOOD;
            case HELD -> new RevokedStatus(Date.from(time), CRLReason.certificateHold);
            case PERMANENTLY_REVOKED -> new RevokedStatus(Date.from(time), reason(reason));
        };
    }

    private static int reason(RevocationReason reason) {
        return switch (reason) {
            case KEY_COMPROMISE -> CRLReason.keyCompromise;
            case CA_COMPROMISE -> CRLReason.cACompromise;
            case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
            case SUPERSEDED -> CRLReason.superseded;
            case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
            case CERTIFICATE_HOLD -> CRLReason.certificateHold;
            case REMOVE_FROM_CRL -> CRLReason.removeFromCRL;
            case PRIVILEGE_WITHDRAWN -> CRLReason.privilegeWithdrawn;
            case AA_COMPROMISE -> CRLReason.aACompromise;
            case UNSPECIFIED -> CRLReason.unspecified;
        };
    }

    private record Resolved(CertificateID id, CertificateStatus status) { }
}
