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
package zeroecho.pki.application;

import org.bouncycastle.asn1.ASN1Integer;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence;
import zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier;
import zeroecho.pki.application.DefaultOcspResponseService.Resolved;
import zeroecho.pki.application.OcspResponseService.CertId;
import zeroecho.pki.application.OcspResponseService.CertIdHash;
import zeroecho.pki.application.OcspResponseService.Command;
import zeroecho.pki.application.OcspResponseService.ResponderId;
import zeroecho.pki.application.OcspResponseService.SdkCommand;
import zeroecho.pki.application.OcspResponseService.SdkResponderBinding;
import zeroecho.pki.application.OcspResponseService.SdkSigningRole;
import zeroecho.pki.application.OcspResponseService.SigningPendingException;
import zeroecho.pki.application.OcspSigningAlgorithms.SdkResolvedRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationView;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.ocsp.OcspRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Coordinates opt-in SDK capture, bounded raw signing and final evidence verification.
 */
@SuppressWarnings({
    "PMD.CyclomaticComplexity",
    "PMD.PreserveStackTrace",
    "PMD.ExceptionAsFlowControl"
})
final class DefaultSdkOcspResponder {
    private static final int MAX_PRIMARY_PROOF = 104;
    private static final int ALTERNATIVE_PROOF_BYTES = 4_627;

    private static final String SHA1_OID = "1.3.14.3.2.26";
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";
    private final DefaultOcspResponseService nativeService;
    private final PkiStore store;
    private final SigningProvider provider;
    private final X509AuthoritySnapshot authority;
    private final Runnable requireOpen;
    private final java.time.Clock clock;

    /* default */ DefaultSdkOcspResponder(
            DefaultOcspResponseService nativeService,
            PkiStore store,
            SigningProvider provider,
            X509AuthoritySnapshot authority,
            Runnable requireOpen,
            java.time.Clock clock) {
        this.nativeService = nativeService;
        this.store = store;
        this.provider = provider;
        this.authority = authority;
        this.requireOpen = requireOpen;
        this.clock = clock;
    }

    /* default */ void validateSdkResponderMetadata(
            PkiId authorityId,
            PkiId issuerId,
            PkiId responderCredentialId,
            PkiId chainPathId,
            SdkSigningRole primary,
            SdkSigningRole alternative,
            ResponderId responderId,
            CancellationSignal cancellation) {
        captureSdkMaterial(
                authorityId,
                issuerId,
                responderCredentialId,
                chainPathId,
                primary,
                alternative,
                responderId,
                cancellation);
    }

    /**
     * Carries the origin coordinates without authorizing or validating them.
     */
    /* default */ record Origin(String trustedRealm, String canonicalOrigin) {}

    /* default */ static Origin origin(String trustedRealm, String canonicalOrigin) {
        return new Origin(trustedRealm, canonicalOrigin);
    }

    /* default */ SdkResponderBinding captureSdkResponderBinding(
            Origin origin,
            PkiId authorityId,
            PkiId issuerId,
            PkiId responderCredentialId,
            PkiId chainPathId,
            SdkSigningRole primary,
            SdkSigningRole alternative,
            ResponderId responderId,
            CancellationSignal cancellation) {
        SdkCapturedMaterial material =
                captureSdkMaterial(
                        authorityId,
                        issuerId,
                        responderCredentialId,
                        chainPathId,
                        primary,
                        alternative,
                        responderId,
                        cancellation);
        return new SdkResponderBinding(
                origin.trustedRealm(),
                origin.canonicalOrigin(),
                authorityId,
                issuerId,
                material.issuerCredentialId(),
                chainPathId,
                material.pathCommitment(),
                material.bindingCommitment(),
                responderCredentialId,
                material.chain(),
                primary,
                alternative,
                material.baselines(),
                responderId);
    }

    /* default */ SdkOcspEvidence respondSdk(SdkCommand query, CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(query, "query");
        Objects.requireNonNull(cancellation, "cancellation");
        try {
            SdkWork work = prepareSdkWork(query, cancellation);
            SdkResponderBinding selected = work.selected();
            java.time.Instant captured = work.captured();
            List<X509Certificate> chain = work.chain();
            X509Certificate responder = work.responder();
            SdkResolvedRole primary = work.primary();
            SdkResolvedRole alternative = work.alternative();
            HybridSdkValue roles = work.roles();
            byte[] tbs = work.tbs();
            byte[] placeholder = sdkPrimaryPlaceholder();
            byte[] maximumNative =
                    Pkix.assembleOcspResponse(
                            tbs, HybridSdkFrame.primaryAlgorithm(), placeholder, chain);
            SdkOcspProjection.Projection projected =
                    SdkOcspProjection.parse(query.originalRequestDer(), maximumNative);
            HybridSdkFrame maximumFrame =
                    sdkFrame(query, chain, roles, projected, maximumNative, captured);
            HybridSdkFrame maximumAlternative = new HybridSdkFrame(5, maximumFrame.fields());
            sdkEnvelopeBytes(
                    maximumNative.length,
                    maximumFrame.encode().length,
                    maximumAlternative.encode().length,
                    MAX_PRIMARY_PROOF,
                    ALTERNATIVE_PROOF_BYTES,
                    chain);
            provider.inputCapabilities()
                    .select(primary.algorithm().identity().canonicalForm(), tbs.length);
            provider.inputCapabilities()
                    .select(
                            primary.algorithm().identity().canonicalForm(),
                            maximumFrame.encode().length);
            provider.inputCapabilities()
                    .select(
                            alternative.algorithm().identity().canonicalForm(),
                            maximumAlternative.encode().length);
            cancellation.throwIfCancelled();
            byte[] nativeSignature =
                    nativeService.rawSign(
                            selected.authorityId(),
                            selected.primary().keyRef(),
                            primary.algorithm().identity(),
                            tbs,
                            Encoding.DER,
                            cancellation);
            if (nativeSignature.length > MAX_PRIMARY_PROOF) {
                throw new IOException("SDK native signature exceeded captured bound");
            }
            byte[] nativeResponse =
                    Pkix.assembleOcspResponse(
                            tbs, HybridSdkFrame.primaryAlgorithm(), nativeSignature, chain);
            if (nativeResponse.length > maximumNative.length) {
                throw new IOException("SDK native response exceeded captured bound");
            }
            SdkOcspProjection.Projection actual =
                    SdkOcspProjection.parse(query.originalRequestDer(), nativeResponse);
            if (!Pkix.parseOcspResponse(nativeResponse).verifySignature(responder.getPublicKey())) {
                throw new IOException("SDK native response signature invalid");
            }
            java.time.Instant issued = sdkNow();
            if (issued.isBefore(captured)) {
                throw new IOException("SDK clock moved backwards");
            }
            HybridSdkFrame f4 = sdkFrame(query, chain, roles, actual, nativeResponse, issued);
            HybridSdkFrame f5 = new HybridSdkFrame(5, f4.fields());
            byte[] first =
                    nativeService.rawSign(
                            selected.authorityId(),
                            selected.primary().keyRef(),
                            primary.algorithm().identity(),
                            f4.encode(),
                            Encoding.BINARY,
                            cancellation);
            if (first.length > MAX_PRIMARY_PROOF) {
                throw new IOException("SDK primary evidence signature exceeded captured bound");
            }
            byte[] second =
                    nativeService.rawSign(
                            selected.authorityId(),
                            selected.alternative().keyRef(),
                            alternative.algorithm().identity(),
                            f5.encode(),
                            Encoding.BINARY,
                            cancellation);
            if (second.length != ALTERNATIVE_PROOF_BYTES) {
                throw new IOException("SDK alternative evidence signature exceeded captured bound");
            }
            List<byte[]> encodedChain = new ArrayList<>();
            for (X509Certificate cert : chain) {
                encodedChain.add(cert.getEncoded());
            }
            SdkOcspEvidence result =
                    new SdkOcspEvidence(nativeResponse, encodedChain, f4, f5, first, second);
            java.time.Instant evaluated = sdkNow();
            if (evaluated.isBefore(issued)) {
                throw new IOException("SDK clock moved backwards");
            }
            cancellation.throwIfCancelled();
            SdkOcspEvidenceVerifier.verify(result, sdkTrust(query, chain, roles, evaluated));
            return result;
        } catch (SigningExecutionException | SigningPendingException signingFailure) {
            throw signingFailure;
        } catch (Exception failure) {
            DefaultOcspResponseService.rethrowSigningBoundaryFailure(failure);
            throw new PkiException("SDK OCSP evidence generation failed: code=SDK_OCSP_FAILED");
        }
    }

    private SdkCapturedMaterial captureSdkMaterial(
            PkiId authorityId,
            PkiId issuerId,
            PkiId responderCredentialId,
            PkiId chainPathId,
            SdkSigningRole primary,
            SdkSigningRole alternative,
            ResponderId responderId,
            CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(cancellation, "cancellation");
        Objects.requireNonNull(responderId, "responderId");
        Objects.requireNonNull(primary, "primary");
        Objects.requireNonNull(alternative, "alternative");
        try {
            cancellation.throwIfCancelled();
            IssuerGeneration generation = store.getIssuerGeneration(issuerId).orElseThrow();
            IssuerCryptographicBinding binding =
                    store.getIssuerCryptographicBinding(issuerId).orElseThrow();
            IssuerChainPath path = store.getIssuerChainPath(chainPathId).orElseThrow();
            if (!generation.authorityId().equals(authorityId)
                    || !binding.authorityId().equals(authorityId)
                    || !binding.credentialId().equals(generation.credentialId())
                    || !path.authorityId().equals(authorityId)
                    || !path.issuerId().equals(issuerId)
                    || path.orderedCredentialIds().size() > 31
                    || !path.orderedCredentialIds().getFirst().equals(generation.credentialId())) {
                throw new IllegalArgumentException("SDK issuer path differs");
            }
            Credential responder = store.getCredential(responderCredentialId).orElseThrow();
            if (!(responder.profileBinding()
                            instanceof zeroecho.pki.api.credential.EndEntityProfileBinding)
                    || !responder.issuerRef().caId().equals(authorityId)
                    || !responder.issuerRef().issuerId().equals(issuerId)
                    || !responder.issuerRef().chainPathId().equals(chainPathId)) {
                throw new IllegalArgumentException("SDK delegated responder differs");
            }
            List<IssuerCryptographicBinding.HybridSignatureBaseline> baselines = new ArrayList<>();
            List<byte[]> issuerPath = new ArrayList<>();
            PkiId nextGeneration = issuerId;
            for (PkiId credentialId : path.orderedCredentialIds()) {
                cancellation.throwIfCancelled();
                IssuerGeneration exactGeneration =
                        store.getIssuerGeneration(nextGeneration).orElseThrow();
                IssuerCryptographicBinding exactBinding =
                        store.getIssuerCryptographicBinding(nextGeneration).orElseThrow();
                Credential credential = store.getCredential(credentialId).orElseThrow();
                if (!exactGeneration.credentialId().equals(credentialId)
                        || !exactBinding.credentialId().equals(credentialId)) {
                    throw new IllegalArgumentException("SDK historical generation differs");
                }
                baselines.add(exactBinding.certificateHybridBaseline());
                issuerPath.add(nativeService.certificate(credentialId).getEncoded());
                nextGeneration = credential.issuerRef().issuerId();
            }
            X509Certificate certificate = nativeService.certificate(responderCredentialId);
            SdkResolvedRole first =
                    new OcspSigningAlgorithms(authority, provider)
                            .sdkRole(primary, Pkix.subjectPublicKeyInfo(certificate), false);
            SdkResolvedRole second =
                    new OcspSigningAlgorithms(authority, provider)
                            .sdkRole(
                                    alternative,
                                    zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(
                                            certificate,
                                            zeroecho.pki.impl.hybrid.AltSignatureExtensions
                                                    .OID_SUBJECT_ALT_PUBLIC_KEY_INFO),
                                    true);
            requireDedicatedSdkRoles(
                    primary, alternative, first.spki(), second.spki(), cancellation);
            HybridSdkValue roles =
                    HybridSdkValue.object(
                            Map.of("primary", first.value(), "alternative", second.value()));
            SdkOcspEvidenceVerifier.validateResponder(
                    issuerPath, baselines, certificate.getEncoded(), roles, sdkNow());
            cancellation.throwIfCancelled();
            List<PkiId> chain = new ArrayList<>();
            chain.add(responderCredentialId);
            chain.addAll(path.orderedCredentialIds());
            return new SdkCapturedMaterial(
                    generation.credentialId(),
                    path.pathCommitment(),
                    binding.commitment(),
                    List.copyOf(chain),
                    List.copyOf(baselines));
        } catch (Exception invalid) {
            throw new PkiException(
                    "SDK OCSP binding validation failed: code=SDK_OCSP_BINDING_INVALID");
        }
    }

    private record SdkWork(
            SdkResponderBinding selected,
            java.time.Instant captured,
            List<X509Certificate> chain,
            X509Certificate responder,
            SdkResolvedRole primary,
            SdkResolvedRole alternative,
            HybridSdkValue roles,
            byte[] tbs) {}

    private SdkWork prepareSdkWork(SdkCommand query, CancellationSignal cancellation)
            throws IOException, java.security.cert.CertificateEncodingException {
        cancellation.throwIfCancelled();
        OcspResponseService.SdkResponderBinding selected = query.responder();
        java.time.Instant captured = sdkNow();
        Map<PkiId, X509Certificate> certificates = new HashMap<>();
        X509Certificate issuer =
                nativeService.certificate(selected.issuerCredentialId(), certificates);
        X509Certificate responder =
                nativeService.certificate(selected.responderCredentialId(), certificates);
        List<X509Certificate> chain = new ArrayList<>();
        for (PkiId id : selected.responseChain()) {
            cancellation.throwIfCancelled();
            chain.add(nativeService.certificate(id, certificates));
        }
        requireSdkStoreBinding(selected);
        SdkResolvedRole primary =
                new OcspSigningAlgorithms(authority, provider)
                        .sdkRole(selected.primary(), Pkix.subjectPublicKeyInfo(responder), false);
        byte[] alternativeSpki =
                zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(
                        responder,
                        zeroecho.pki.impl.hybrid.AltSignatureExtensions
                                .OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
        SdkResolvedRole alternative =
                new OcspSigningAlgorithms(authority, provider)
                        .sdkRole(selected.alternative(), alternativeSpki, true);
        requireDedicatedSdkRoles(
                selected.primary(),
                selected.alternative(),
                primary.spki(),
                alternative.spki(),
                cancellation);
        HybridSdkValue roles =
                HybridSdkValue.object(
                        Map.of("primary", primary.value(), "alternative", alternative.value()));
        SdkOcspEvidenceVerifier.TrustedContext trusted = sdkTrust(query, chain, roles, captured);
        SdkOcspEvidenceVerifier.validateResponder(trusted);
        OcspRequest request = Pkix.parseOcspRequest(query.originalRequestDer());
        if (request.requestedCertificates().isEmpty()
                || request.requestedCertificates().size() > 819
                || request.nonce()
                        .filter(value -> value.length == 0 || value.length > 4_096)
                        .isPresent()) {
            throw new IllegalArgumentException("SDK OCSP request bounds invalid");
        }
        List<OcspResponseService.CertId> requests =
                request.requestedCertificates().stream()
                        .map(
                                id ->
                                        new CertId(
                                                switch (id.hashAlgorithm().oid()) {
                                                    case SHA1_OID -> CertIdHash.SHA1;
                                                    case SHA256_OID -> CertIdHash.SHA256;
                                                    default ->
                                                            throw new IllegalArgumentException(
                                                                    "SDK OCSP digest unsupported");
                                                },
                                                id.issuerNameHash(),
                                                id.issuerKeyHash(),
                                                id.serialNumber()))
                        .toList();
        java.time.Instant next = captured.plus(query.nextUpdateAfter());
        if (next.isAfter(responder.getNotAfter().toInstant())) {
            next = responder.getNotAfter().toInstant();
        }
        OcspResponseService.Command command =
                new Command(
                        selected.authorityId(),
                        selected.issuerId(),
                        selected.issuerCredentialId(),
                        selected.responderCredentialId(),
                        selected.primary().keyRef(),
                        selected.responseChain(),
                        selected.primary().signatureAlgorithm(),
                        selected.primary().signatureBindingId(),
                        selected.responderId(),
                        captured,
                        captured,
                        next,
                        request.nonce(),
                        requests);
        nativeService.validateAuthority(command, issuer, responder);
        SdkStatusSnapshot snapshot;
        try (RevocationView view = store.openRevocationView()) {
            snapshot =
                    new SdkStatusSnapshot(
                            nativeService.resolve(command, issuer, view, cancellation),
                            view.revision(),
                            view.commitment());
        }
        byte[] tbs =
                DefaultOcspResponseService.responseTbs(command, responder, snapshot.resolved());
        return new SdkWork(selected, captured, chain, responder, primary, alternative, roles, tbs);
    }

    private java.time.Instant sdkNow() {
        return clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    }

    private void requireSdkStoreBinding(SdkResponderBinding selected) {
        IssuerGeneration generation = store.getIssuerGeneration(selected.issuerId()).orElseThrow();
        IssuerCryptographicBinding binding =
                store.getIssuerCryptographicBinding(selected.issuerId()).orElseThrow();
        IssuerChainPath path = store.getIssuerChainPath(selected.chainPathId()).orElseThrow();
        if (!generation.authorityId().equals(selected.authorityId())
                || !generation.credentialId().equals(selected.issuerCredentialId())
                || !binding.commitment().equals(selected.issuerBindingCommitment())
                || !path.authorityId().equals(selected.authorityId())
                || !path.issuerId().equals(selected.issuerId())
                || !path.pathCommitment().equals(selected.pathCommitment())
                || !path.orderedCredentialIds()
                        .equals(
                                selected.responseChain()
                                        .subList(1, selected.responseChain().size()))) {
            throw new IllegalArgumentException("SDK OCSP immutable issuer context differs");
        }
        PkiId generationId = selected.issuerId();
        for (int index = 1; index < selected.responseChain().size(); index++) {
            IssuerGeneration exactGeneration =
                    store.getIssuerGeneration(generationId).orElseThrow();
            IssuerCryptographicBinding exactBinding =
                    store.getIssuerCryptographicBinding(generationId).orElseThrow();
            Credential credential =
                    store.getCredential(selected.responseChain().get(index)).orElseThrow();
            if (!exactGeneration.credentialId().equals(credential.credentialId())
                    || !exactBinding.credentialId().equals(credential.credentialId())
                    || exactBinding.certificateHybridBaseline()
                            != selected.issuerCertificateBaselines().get(index - 1)) {
                throw new IllegalArgumentException("SDK OCSP historical baseline differs");
            }
            generationId = credential.issuerRef().issuerId();
        }
        Credential responder = store.getCredential(selected.responderCredentialId()).orElseThrow();
        if (!(responder.profileBinding()
                        instanceof zeroecho.pki.api.credential.EndEntityProfileBinding)
                || !responder.issuerRef().caId().equals(selected.authorityId())
                || !responder.issuerRef().issuerId().equals(selected.issuerId())
                || !responder.issuerRef().chainPathId().equals(selected.chainPathId())) {
            throw new IllegalArgumentException("SDK OCSP delegation coordinates differ");
        }
    }

    private void requireDedicatedSdkRoles(
            SdkSigningRole primaryRole,
            SdkSigningRole alternativeRole,
            byte[] primary,
            byte[] alternative,
            CancellationSignal cancellation)
            throws IOException {
        String first = sdkDigest(primary);
        String second = sdkDigest(alternative);
        if (first.equals(second)) {
            throw new IllegalArgumentException("SDK responder roles coincide");
        }
        Optional<PkiId> after = Optional.empty();
        while (true) {
            List<CaRecord> authorities = store.listCasPage(after, 256);
            if (authorities.isEmpty()) {
                return;
            }
            for (CaRecord ca : authorities) {
                Optional<String> issuerAfter = Optional.empty();
                while (true) {
                    List<IssuerGeneration> generations =
                            store.listIssuerGenerationsPage(
                                    ca.caId(), issuerAfter, 256, value -> true, cancellation);
                    if (generations.isEmpty()) {
                        break;
                    }
                    for (IssuerGeneration generation : generations) {
                        cancellation.throwIfCancelled();
                        IssuerCryptographicBinding binding =
                                store.getIssuerCryptographicBinding(generation.issuerId())
                                        .orElseThrow();
                        List<IssuerKeyBinding> roles =
                                binding.alternative()
                                        .map(value -> List.of(binding.primary(), value))
                                        .orElseGet(() -> List.of(binding.primary()));
                        for (IssuerKeyBinding role : roles) {
                            if (role.keyRef().equals(primaryRole.keyRef())
                                    || role.keyRef().equals(alternativeRole.keyRef())
                                    || role.subjectSpkiSha256().equals(first)
                                    || role.subjectSpkiSha256().equals(second)) {
                                throw new IllegalArgumentException("SDK responder reuses CA role");
                            }
                        }
                    }
                    issuerAfter = Optional.of(generations.getLast().issuerId().value());
                }
            }
            after = Optional.of(authorities.getLast().caId());
        }
    }

    private static String sdkDigest(byte[] bytes) {
        try {
            return java.util.HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static SdkOcspEvidenceVerifier.TrustedContext sdkTrust(
            SdkCommand command,
            List<X509Certificate> chain,
            HybridSdkValue roles,
            java.time.Instant now)
            throws java.security.cert.CertificateEncodingException {
        OcspResponseService.SdkResponderBinding selected = command.responder();
        List<byte[]> issuerPath = new ArrayList<>();
        for (int index = 1; index < chain.size(); index++) {
            issuerPath.add(chain.get(index).getEncoded());
        }
        return new SdkOcspEvidenceVerifier.TrustedContext(
                selected.realmId(),
                selected.canonicalOrigin(),
                selected.authorityId(),
                selected.issuerId(),
                selected.chainPathId(),
                selected.pathCommitment(),
                selected.issuerBindingCommitment(),
                command.originalRequestDer(),
                command.clientNonce(),
                issuerPath,
                selected.issuerCertificateBaselines(),
                chain.getFirst().getEncoded(),
                roles,
                now);
    }

    private static HybridSdkFrame sdkFrame(
            SdkCommand query,
            List<X509Certificate> chain,
            HybridSdkValue roles,
            SdkOcspProjection.Projection projection,
            byte[] nativeResponse,
            java.time.Instant issued)
            throws java.security.cert.CertificateEncodingException {
        OcspResponseService.SdkResponderBinding selected = query.responder();
        java.time.Instant expires = issued.plusSeconds(120);
        if (expires.isAfter(projection.nextUpdate())) {
            expires = projection.nextUpdate();
        }
        if (expires.isAfter(chain.getFirst().getNotAfter().toInstant())) {
            expires = chain.getFirst().getNotAfter().toInstant();
        }
        Map<Integer, byte[]> values = new TreeMap<>();
        List<HybridSdkValue> encoded = new ArrayList<>();
        for (X509Certificate certificate : chain) {
            encoded.add(HybridSdkValue.bytes(certificate.getEncoded()));
        }
        values.put(1, sdkText("zeroecho-hybrid-sdk-v1"));
        values.put(2, sdkText(selected.realmId()));
        values.put(3, sdkText(selected.canonicalOrigin()));
        values.put(4, query.clientNonce());
        values.put(5, HybridSdkFrame.hash(query.originalRequestDer()));
        values.put(6, HybridSdkFrame.hash(nativeResponse));
        values.put(7, HybridSdkFrame.hash(chain.getFirst().getEncoded()));
        values.put(8, HybridSdkFrame.hash(HybridSdkValue.list(encoded).encode()));
        values.put(9, sdkText(selected.authorityId().value()));
        values.put(10, sdkText(selected.issuerId().value()));
        values.put(11, sdkText(selected.chainPathId().value()));
        values.put(12, sdkText(selected.pathCommitment()));
        values.put(13, sdkText(selected.issuerBindingCommitment()));
        values.put(14, roles.encode());
        values.put(15, sdkTime(projection.producedAt()));
        values.put(16, sdkTime(projection.thisUpdate()));
        values.put(17, sdkTime(projection.nextUpdate()));
        values.put(18, sdkTime(issued));
        values.put(19, sdkTime(expires));
        values.put(20, projection.nonce().encode());
        values.put(21, projection.statuses().encode());
        return new HybridSdkFrame(4, values);
    }

    private static byte[] sdkText(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sdkTime(java.time.Instant value) {
        return java.nio.ByteBuffer.allocate(8).putLong(value.getEpochSecond()).array();
    }

    private static byte[] sdkPrimaryPlaceholder() throws IOException {
        ASN1Integer integer = new ASN1Integer(java.math.BigInteger.ONE.shiftLeft(383));
        return new org.bouncycastle.asn1.DERSequence(
                        new org.bouncycastle.asn1.ASN1Encodable[] {integer, integer})
                .getEncoded("DER");
    }

    private static int sdkEnvelopeBytes(
            int nativeBytes,
            int firstFrame,
            int secondFrame,
            int firstSignature,
            int secondSignature,
            List<X509Certificate> chain)
            throws java.security.cert.CertificateEncodingException {
        String empty =
                "{\"version\":1,\"profile\":\"zeroecho-hybrid-sdk-v1\",\"primaryResponseDer\":\"\",\"responderChain\":[],\"primaryFrame\":\"\",\"alternativeFrame\":\"\",\"primarySignature\":\"\",\"alternativeSignature\":\"\"}";
        long bytes = empty.getBytes(StandardCharsets.UTF_8).length;
        for (int component :
                new int[] {nativeBytes, firstFrame, secondFrame, firstSignature, secondSignature}) {
            bytes = Math.addExact(bytes, sdkBase64Bytes(component));
        }
        for (X509Certificate certificate : chain) {
            bytes = Math.addExact(bytes, sdkBase64Bytes(certificate.getEncoded().length));
        }
        bytes =
                Math.addExact(
                        bytes, Math.addExact(2L * chain.size(), Math.max(0, chain.size() - 1)));
        return Math.toIntExact(bytes);
    }

    private static long sdkBase64Bytes(int bytes) {
        return Math.addExact(Math.multiplyExact(4L, bytes), 2) / 3;
    }

    private record SdkCapturedMaterial(
            PkiId issuerCredentialId,
            String pathCommitment,
            String bindingCommitment,
            List<PkiId> chain,
            List<IssuerCryptographicBinding.HybridSignatureBaseline> baselines) {}

    private record SdkStatusSnapshot(List<Resolved> resolved, long revision, String commitment) {
        private SdkStatusSnapshot {
            resolved = List.copyOf(resolved);
            if (revision < 0 || commitment == null || !commitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("SDK OCSP snapshot invalid");
            }
        }
    }
}
