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

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.OptionalLong;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pkix.Pkix;
import zeroecho.pkix.crl.CrlReason;
import zeroecho.pkix.sign.ContentVerifier;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.ocsp.OcspResponse;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.core.io.OneShotContent;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningService;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningOperation;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationView;

/**
 * Store-backed OCSP response service borrowing the session's bounded raw signer.
 * Invocation-local snapshots close before staging or waiting; no persistent OCSP
 * workflow or resource owner is introduced. Transient work is linear in requests
 * and encoded bytes, plus indexed issuer/serial and revocation lookups.
 */
@SuppressWarnings({ "PMD.CyclomaticComplexity",
        "PMD.PreserveStackTrace", "PMD.ExceptionAsFlowControl", "PMD.SignatureDeclareThrowsException",
        "PMD.ControlStatementBraces" })
final class DefaultOcspResponseService implements OcspResponseService {
    private static final String SHA1_OID = "1.3.14.3.2.26";
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";

    private final PkiStore store;
    private static final AccessContext ACCESS = new AccessContext(new Principal("SYSTEM", "pki"),
            new Purpose("X509_SIGN"), Optional.empty(), Optional.empty());
    private final SigningService signing;
    private final SigningProvider provider;
    private final X509AuthoritySnapshot authority;
    private final Runnable requireOpen;
    private final java.time.Clock clock;

    /* default */ DefaultOcspResponseService(PkiStore store, SigningService signing, SigningProvider provider,
            X509AuthoritySnapshot authority, Runnable requireOpen) {
        this(store, signing, provider, authority, requireOpen, java.time.Clock.systemUTC());
    }

    /* default */ DefaultOcspResponseService(PkiStore store, SigningService signing, SigningProvider provider,
            X509AuthoritySnapshot authority, Runnable requireOpen, java.time.Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.store = Objects.requireNonNull(store, "store");
        this.signing = Objects.requireNonNull(signing, "signing");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.authority = Objects.requireNonNull(authority, "authority");
        this.requireOpen = Objects.requireNonNull(requireOpen, "requireOpen");
    }

    @Override public Response respond(Command command) {
        return respond(command, CancellationSignal.NONE);
    }

    @Override public Response respond(Command command, CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(cancellation, "cancellation");
        try {
            cancellation.throwIfCancelled();
            Map<PkiId, X509Certificate> certificates = new HashMap<>();
            X509Certificate issuer = certificate(command.issuerCredentialId(), certificates);
            X509Certificate responder = certificate(command.responderCredentialId(), certificates);
            validateAuthority(command, issuer, responder);
            List<X509Certificate> chain = new ArrayList<>(command.responseChain().size());
            for (PkiId credentialId : command.responseChain()) {
                cancellation.throwIfCancelled();
                chain.add(certificate(credentialId, certificates));
            }
            SigningAlgorithm algorithm = algorithm(responder, command.signatureAlgorithm(), command.signatureBindingId());
            List<Resolved> resolved;
            long revision;
            String commitment;
            try (RevocationView view = store.openRevocationView()) {
                revision = view.revision();
                commitment = view.commitment();
                resolved = resolve(command, issuer, view, cancellation);
            }
            int good = Math.toIntExact(resolved.stream().filter(value -> value.status() instanceof CertStatus.Good)
                    .count());
            int revoked = Math.toIntExact(resolved.stream()
                    .filter(value -> value.status() instanceof CertStatus.Revoked).count());
            int unknown = Math.subtractExact(resolved.size(), Math.addExact(good, revoked));
            return new Response(sign(command, responder, chain, algorithm, resolved, cancellation), revision, commitment,
                    good, revoked, unknown);
        } catch (SigningExecutionException | SigningPendingException signingFailure) {
            throw signingFailure;
        } catch (Exception failure) {
            rethrowSigningBoundaryFailure(failure);
            throw new PkiException("OCSP response generation failed: code=OCSP_RESPONSE_FAILED");
        }
    }

    @Override public void validateSdkResponderMetadata(PkiId authorityId, PkiId issuerId, PkiId responderCredentialId,
            PkiId chainPathId, SdkSigningRole primary, SdkSigningRole alternative, ResponderId responderId, CancellationSignal cancellation) {
        captureSdkMaterial(authorityId, issuerId, responderCredentialId, chainPathId, primary, alternative, responderId, cancellation);
    }

    @Override public SdkResponderBinding captureSdkResponderBinding(String trustedRealm, String canonicalOrigin, PkiId authorityId,
            PkiId issuerId, PkiId responderCredentialId, PkiId chainPathId, SdkSigningRole primary, SdkSigningRole alternative,
            ResponderId responderId, CancellationSignal cancellation) {
        var material = captureSdkMaterial(authorityId, issuerId, responderCredentialId, chainPathId, primary, alternative, responderId, cancellation);
        return new SdkResponderBinding(trustedRealm, canonicalOrigin, authorityId, issuerId, material.issuerCredentialId(), chainPathId,
                material.pathCommitment(), material.bindingCommitment(), responderCredentialId, material.chain(), primary, alternative, material.baselines(), responderId);
    }

    private SdkCapturedMaterial captureSdkMaterial(PkiId authorityId, PkiId issuerId, PkiId responderCredentialId,
            PkiId chainPathId, SdkSigningRole primary, SdkSigningRole alternative, ResponderId responderId, CancellationSignal cancellation) {
        requireOpen.run(); Objects.requireNonNull(cancellation, "cancellation"); Objects.requireNonNull(responderId, "responderId");
        Objects.requireNonNull(primary, "primary"); Objects.requireNonNull(alternative, "alternative");
        try {
            cancellation.throwIfCancelled();
            var generation = store.getIssuerGeneration(issuerId).orElseThrow();
            var binding = store.getIssuerCryptographicBinding(issuerId).orElseThrow();
            var path = store.getIssuerChainPath(chainPathId).orElseThrow();
            if (!generation.authorityId().equals(authorityId) || !binding.authorityId().equals(authorityId)
                    || !binding.credentialId().equals(generation.credentialId()) || !path.authorityId().equals(authorityId)
                    || !path.issuerId().equals(issuerId) || path.orderedCredentialIds().size() > 31
                    || !path.orderedCredentialIds().getFirst().equals(generation.credentialId())) throw new IllegalArgumentException("SDK issuer path differs");
            var responder = store.getCredential(responderCredentialId).orElseThrow();
            if (!(responder.profileBinding() instanceof zeroecho.pki.api.credential.EndEntityProfileBinding)
                    || !responder.issuerRef().caId().equals(authorityId) || !responder.issuerRef().issuerId().equals(issuerId)
                    || !responder.issuerRef().chainPathId().equals(chainPathId)) throw new IllegalArgumentException("SDK delegated responder differs");
            var baselines = new ArrayList<zeroecho.pki.api.ca.IssuerCryptographicBinding.HybridSignatureBaseline>();
            var issuerPath = new ArrayList<byte[]>(); PkiId nextGeneration = issuerId;
            for (var credentialId : path.orderedCredentialIds()) {
                cancellation.throwIfCancelled();
                var exactGeneration = store.getIssuerGeneration(nextGeneration).orElseThrow();
                var exactBinding = store.getIssuerCryptographicBinding(nextGeneration).orElseThrow();
                var credential = store.getCredential(credentialId).orElseThrow();
                if (!exactGeneration.credentialId().equals(credentialId) || !exactBinding.credentialId().equals(credentialId)) throw new IllegalArgumentException("SDK historical generation differs");
                baselines.add(exactBinding.certificateHybridBaseline()); issuerPath.add(certificate(credentialId).getEncoded());
                nextGeneration = credential.issuerRef().issuerId();
            }
            var certificate = certificate(responderCredentialId);
            var first = sdkRole(primary, Pkix.subjectPublicKeyInfo(certificate), false);
            var second = sdkRole(alternative, zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate,
                    zeroecho.pki.impl.hybrid.AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO), true);
            requireDedicatedSdkRoles(primary, alternative, first.spki(), second.spki(), cancellation);
            var roles = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.of("primary", first.value(), "alternative", second.value()));
            zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.validateResponder(issuerPath, baselines, certificate.getEncoded(), roles, sdkNow());
            cancellation.throwIfCancelled();
            var chain = new ArrayList<PkiId>(); chain.add(responderCredentialId); chain.addAll(path.orderedCredentialIds());
            return new SdkCapturedMaterial(generation.credentialId(), path.pathCommitment(), binding.commitment(), List.copyOf(chain), List.copyOf(baselines));
        } catch (Exception invalid) { throw new PkiException("SDK OCSP binding validation failed: code=SDK_OCSP_BINDING_INVALID"); }
    }
    private record SdkCapturedMaterial(PkiId issuerCredentialId, String pathCommitment, String bindingCommitment,
            List<PkiId> chain, List<zeroecho.pki.api.ca.IssuerCryptographicBinding.HybridSignatureBaseline> baselines) { }

    @Override public zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence respondSdk(SdkCommand query, CancellationSignal cancellation) {
        requireOpen.run(); Objects.requireNonNull(query, "query"); Objects.requireNonNull(cancellation, "cancellation");
        try {
            cancellation.throwIfCancelled(); var selected = query.responder();
            java.time.Instant captured = sdkNow();
            var certificates = new HashMap<PkiId,X509Certificate>();
            var issuer = certificate(selected.issuerCredentialId(), certificates); var responder = certificate(selected.responderCredentialId(), certificates);
            var chain = new ArrayList<X509Certificate>();
            for (var id : selected.responseChain()) { cancellation.throwIfCancelled(); chain.add(certificate(id, certificates)); }
            requireSdkStoreBinding(selected);
            var primary = sdkRole(selected.primary(), Pkix.subjectPublicKeyInfo(responder), false);
            byte[] alternativeSpki = zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(responder,
                    zeroecho.pki.impl.hybrid.AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
            var alternative = sdkRole(selected.alternative(), alternativeSpki, true);
            requireDedicatedSdkRoles(selected.primary(), selected.alternative(), primary.spki(), alternative.spki(), cancellation);
            var roles = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.of("primary", primary.value(), "alternative", alternative.value()));
            var trusted = sdkTrust(query, chain, roles, captured);
            zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.validateResponder(trusted);
            var request = Pkix.parseOcspRequest(query.originalRequestDer());
            if (request.requestedCertificates().isEmpty() || request.requestedCertificates().size() > 819
                    || request.nonce().filter(value -> value.length == 0 || value.length > 4096).isPresent()) throw new IllegalArgumentException("SDK OCSP request bounds invalid");
            var requests = request.requestedCertificates().stream().map(id -> new CertId(
                    switch (id.hashAlgorithm().oid()) { case SHA1_OID -> CertIdHash.SHA1; case SHA256_OID -> CertIdHash.SHA256; default -> throw new IllegalArgumentException("SDK OCSP digest unsupported"); },
                    id.issuerNameHash(), id.issuerKeyHash(), id.serialNumber())).toList();
            java.time.Instant next = captured.plus(query.nextUpdateAfter());
            if (next.isAfter(responder.getNotAfter().toInstant())) next = responder.getNotAfter().toInstant();
            var command = new Command(selected.authorityId(), selected.issuerId(), selected.issuerCredentialId(), selected.responderCredentialId(), selected.primary().keyRef(),
                    selected.responseChain(), selected.primary().signatureAlgorithm(), selected.primary().signatureBindingId(), selected.responderId(), captured, captured, next, request.nonce(), requests);
            validateAuthority(command, issuer, responder);
            SdkStatusSnapshot snapshot;
            try (RevocationView view = store.openRevocationView()) {
                snapshot = new SdkStatusSnapshot(resolve(command, issuer, view, cancellation), view.revision(), view.commitment());
            }
            byte[] tbs = responseTbs(command, responder, snapshot.resolved());
            byte[] placeholder = sdkPrimaryPlaceholder();
            byte[] maximumNative = Pkix.assembleOcspResponse(tbs, zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.primaryAlgorithm(), placeholder, chain);
            var projected = SdkOcspProjection.parse(query.originalRequestDer(), maximumNative);
            var maximumFrame = sdkFrame(query, chain, roles, projected, maximumNative, captured);
            var maximumAlternative = new zeroecho.pki.api.hybrid.sdk.HybridSdkFrame(5, maximumFrame.fields());
            sdkEnvelopeBytes(maximumNative.length, maximumFrame.encode().length, maximumAlternative.encode().length, 104, 4627, chain);
            provider.inputCapabilities().select(primary.algorithm().identity().canonicalForm(), tbs.length);
            provider.inputCapabilities().select(primary.algorithm().identity().canonicalForm(), maximumFrame.encode().length);
            provider.inputCapabilities().select(alternative.algorithm().identity().canonicalForm(), maximumAlternative.encode().length);
            cancellation.throwIfCancelled();
            byte[] nativeSignature = rawSign(selected.authorityId(), selected.primary().keyRef(), primary.algorithm().identity(), tbs, Encoding.DER, cancellation);
            if (nativeSignature.length > 104) throw new IOException("SDK native signature exceeded captured bound");
            byte[] nativeResponse = Pkix.assembleOcspResponse(tbs, zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.primaryAlgorithm(), nativeSignature, chain);
            if (nativeResponse.length > maximumNative.length) throw new IOException("SDK native response exceeded captured bound");
            var actual = SdkOcspProjection.parse(query.originalRequestDer(), nativeResponse);
            if (!Pkix.parseOcspResponse(nativeResponse).verifySignature(responder.getPublicKey())) throw new IOException("SDK native response signature invalid");
            java.time.Instant issued = sdkNow(); if (issued.isBefore(captured)) throw new IOException("SDK clock moved backwards");
            var f4 = sdkFrame(query, chain, roles, actual, nativeResponse, issued); var f5 = new zeroecho.pki.api.hybrid.sdk.HybridSdkFrame(5, f4.fields());
            byte[] first = rawSign(selected.authorityId(), selected.primary().keyRef(), primary.algorithm().identity(), f4.encode(), Encoding.BINARY, cancellation);
            if (first.length > 104) throw new IOException("SDK primary evidence signature exceeded captured bound");
            byte[] second = rawSign(selected.authorityId(), selected.alternative().keyRef(), alternative.algorithm().identity(), f5.encode(), Encoding.BINARY, cancellation);
            if (second.length != 4627) throw new IOException("SDK alternative evidence signature exceeded captured bound");
            var encodedChain = new ArrayList<byte[]>(); for (var cert : chain) encodedChain.add(cert.getEncoded());
            var result = new zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence(nativeResponse, encodedChain, f4, f5, first, second);
            java.time.Instant evaluated = sdkNow(); if (evaluated.isBefore(issued)) throw new IOException("SDK clock moved backwards");
            cancellation.throwIfCancelled();
            zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.verify(result, sdkTrust(query, chain, roles, evaluated));
            return result;
        } catch (SigningExecutionException | SigningPendingException signingFailure) { throw signingFailure; }
        catch (Exception failure) {
            rethrowSigningBoundaryFailure(failure); throw new PkiException("SDK OCSP evidence generation failed: code=SDK_OCSP_FAILED");
        }
    }

    private java.time.Instant sdkNow() { return clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS); }
    private void requireSdkStoreBinding(SdkResponderBinding selected) {
        var generation = store.getIssuerGeneration(selected.issuerId()).orElseThrow();
        var binding = store.getIssuerCryptographicBinding(selected.issuerId()).orElseThrow();
        var path = store.getIssuerChainPath(selected.chainPathId()).orElseThrow();
        if (!generation.authorityId().equals(selected.authorityId()) || !generation.credentialId().equals(selected.issuerCredentialId())
                || !binding.commitment().equals(selected.issuerBindingCommitment()) || !path.authorityId().equals(selected.authorityId())
                || !path.issuerId().equals(selected.issuerId()) || !path.pathCommitment().equals(selected.pathCommitment())
                || !path.orderedCredentialIds().equals(selected.responseChain().subList(1, selected.responseChain().size()))) throw new IllegalArgumentException("SDK OCSP immutable issuer context differs");
        PkiId generationId = selected.issuerId();
        for (int index = 1; index < selected.responseChain().size(); index++) {
            var exactGeneration = store.getIssuerGeneration(generationId).orElseThrow();
            var exactBinding = store.getIssuerCryptographicBinding(generationId).orElseThrow();
            var credential = store.getCredential(selected.responseChain().get(index)).orElseThrow();
            if (!exactGeneration.credentialId().equals(credential.credentialId()) || !exactBinding.credentialId().equals(credential.credentialId())
                    || exactBinding.certificateHybridBaseline() != selected.issuerCertificateBaselines().get(index - 1)) throw new IllegalArgumentException("SDK OCSP historical baseline differs");
            generationId = credential.issuerRef().issuerId();
        }
        var responder = store.getCredential(selected.responderCredentialId()).orElseThrow();
        if (!(responder.profileBinding() instanceof zeroecho.pki.api.credential.EndEntityProfileBinding)
                || !responder.issuerRef().caId().equals(selected.authorityId()) || !responder.issuerRef().issuerId().equals(selected.issuerId())
                || !responder.issuerRef().chainPathId().equals(selected.chainPathId())) throw new IllegalArgumentException("SDK OCSP delegation coordinates differ");
    }
    private SdkResolvedRole sdkRole(SdkSigningRole selected, byte[] expectedSpki, boolean alternative) throws IOException {
        if (!(provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource keys)) throw new UnsupportedOperationException("SDK managed public metadata unavailable");
        var info = keys.resolvePublicKeyInfo(selected.keyRef());
        if (info.encoding() != Encoding.DER || !Arrays.equals(info.bytes(), expectedSpki)) throw new IllegalArgumentException("SDK responder key differs");
        var adapter = new BcX509AlgorithmAdapter(authority.bindings());
        var publicKey = adapter.decode(Pkix.subjectPublicKeyAlgorithm(expectedSpki), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        var signature = authority.resolveIdentity(selected.signatureAlgorithm()); X509SecurityFloor.requirePermitted(signature); X509SuiteCompatibility.requireCompatible(signature, publicKey);
        var plan = selected.signatureBindingId().isPresent() ? authority.plan(signature, publicKey, Direction.SIGN, Optional.empty(), "explicit", selected.signatureBindingId().orElseThrow(), SigningProvider.class)
                : authority.plan(signature, publicKey, Direction.SIGN, Optional.empty(), "default", SigningProvider.class);
        authority.authorize(plan, provider, Direction.SIGN);
        // Raw SigningRequest carries identity, not a format-binding selector. Only
        // the exact default-equivalent execution can therefore be honored here.
        var rawPlan = authority.plan(signature, publicKey, Direction.SIGN, Optional.empty(), "default", SigningProvider.class);
        authority.authorize(rawPlan, provider, Direction.SIGN);
        var captured = plan.selection(); var raw = rawPlan.selection();
        if (!captured.requested().equals(raw.requested()) || !captured.suite().equals(raw.suite())
                || !captured.binding().equals(raw.binding()) || captured.direction() != raw.direction()
                || !captured.authorityFingerprint().equals(raw.authorityFingerprint())
                || !captured.implementation().implementationId().equals(raw.implementation().implementationId())
                || !captured.implementation().domainFingerprint().equals(raw.implementation().domainFingerprint())
                || plan.executor() != rawPlan.executor()) throw new IllegalArgumentException("SDK responder binding cannot be carried by raw signing");
        var algorithm = BcX509AlgorithmAdapter.toLib(raw.binding());
        byte[] expected = alternative ? zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.alternativeAlgorithm() : zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.primaryAlgorithm();
        if (!Arrays.equals(Pkix.encodeAlgorithmIdentifier(algorithm), expected)) throw new IllegalArgumentException("SDK responder signature suite differs");
        var role = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.of("spki", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bytes(expectedSpki),
                "publicKeyAlgorithm", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(publicKey.canonicalForm()), "signatureAlgorithm", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(signature.canonicalForm()),
                "algorithmIdentifier", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bytes(expected)));
        return new SdkResolvedRole(new SigningAlgorithm(signature, algorithm), role, expectedSpki);
    }
    private record SdkResolvedRole(SigningAlgorithm algorithm, zeroecho.pki.api.hybrid.sdk.HybridSdkValue value, byte[] spki) { }
    private record SdkStatusSnapshot(List<Resolved> resolved, long revision, String commitment) {
        private SdkStatusSnapshot { resolved = List.copyOf(resolved); if (revision < 0 || commitment == null || !commitment.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("SDK OCSP snapshot invalid"); }
    }
    private void requireDedicatedSdkRoles(SdkSigningRole primaryRole, SdkSigningRole alternativeRole, byte[] primary, byte[] alternative, CancellationSignal cancellation) throws IOException {
        String first = sdkDigest(primary), second = sdkDigest(alternative); if (first.equals(second)) throw new IllegalArgumentException("SDK responder roles coincide");
        Optional<PkiId> after = Optional.empty();
        while (true) {
            var authorities = store.listCasPage(after, 256); if (authorities.isEmpty()) return;
            for (var ca : authorities) {
                Optional<String> issuerAfter = Optional.empty();
                while (true) {
                    var generations = store.listIssuerGenerationsPage(ca.caId(), issuerAfter, 256, value -> true, cancellation); if (generations.isEmpty()) break;
                    for (var generation : generations) {
                        cancellation.throwIfCancelled(); var binding = store.getIssuerCryptographicBinding(generation.issuerId()).orElseThrow();
                        var roles = new ArrayList<zeroecho.pki.api.ca.IssuerKeyBinding>(); roles.add(binding.primary()); binding.alternative().ifPresent(roles::add);
                        for (var role : roles) if (role.keyRef().equals(primaryRole.keyRef()) || role.keyRef().equals(alternativeRole.keyRef())
                                || role.subjectSpkiSha256().equals(first) || role.subjectSpkiSha256().equals(second)) throw new IllegalArgumentException("SDK responder reuses CA role");
                    }
                    issuerAfter = Optional.of(generations.getLast().issuerId().value());
                }
            }
            after = Optional.of(authorities.getLast().caId());
        }
    }
    private static String sdkDigest(byte[] bytes) { try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); } }
    private static zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.TrustedContext sdkTrust(SdkCommand command, List<X509Certificate> chain,
            zeroecho.pki.api.hybrid.sdk.HybridSdkValue roles, java.time.Instant now) throws java.security.cert.CertificateEncodingException {
        var selected = command.responder(); var issuerPath = new ArrayList<byte[]>();
        for (int index = 1; index < chain.size(); index++) issuerPath.add(chain.get(index).getEncoded());
        return new zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.TrustedContext(selected.realmId(), selected.canonicalOrigin(), selected.authorityId(), selected.issuerId(), selected.chainPathId(),
                selected.pathCommitment(), selected.issuerBindingCommitment(), command.originalRequestDer(), command.clientNonce(), issuerPath, selected.issuerCertificateBaselines(), chain.getFirst().getEncoded(), roles, now);
    }
    private static zeroecho.pki.api.hybrid.sdk.HybridSdkFrame sdkFrame(SdkCommand query, List<X509Certificate> chain, zeroecho.pki.api.hybrid.sdk.HybridSdkValue roles,
            SdkOcspProjection.Projection projection, byte[] nativeResponse, java.time.Instant issued) throws java.security.cert.CertificateEncodingException {
        var selected = query.responder(); java.time.Instant expires = issued.plusSeconds(120);
        if (expires.isAfter(projection.nextUpdate())) expires = projection.nextUpdate();
        if (expires.isAfter(chain.getFirst().getNotAfter().toInstant())) expires = chain.getFirst().getNotAfter().toInstant();
        var values = new TreeMap<Integer,byte[]>(); var encoded = new ArrayList<zeroecho.pki.api.hybrid.sdk.HybridSdkValue>();
        for (var certificate : chain) encoded.add(zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bytes(certificate.getEncoded()));
        values.put(1,sdkText("zeroecho-hybrid-sdk-v1"));values.put(2,sdkText(selected.realmId()));values.put(3,sdkText(selected.canonicalOrigin()));values.put(4,query.clientNonce());
        values.put(5,zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(query.originalRequestDer()));values.put(6,zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(nativeResponse));values.put(7,zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(chain.getFirst().getEncoded()));
        values.put(8,zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(zeroecho.pki.api.hybrid.sdk.HybridSdkValue.list(encoded).encode()));
        values.put(9,sdkText(selected.authorityId().value()));values.put(10,sdkText(selected.issuerId().value()));values.put(11,sdkText(selected.chainPathId().value()));values.put(12,sdkText(selected.pathCommitment()));values.put(13,sdkText(selected.issuerBindingCommitment()));values.put(14,roles.encode());
        values.put(15,sdkTime(projection.producedAt()));values.put(16,sdkTime(projection.thisUpdate()));values.put(17,sdkTime(projection.nextUpdate()));values.put(18,sdkTime(issued));values.put(19,sdkTime(expires));values.put(20,projection.nonce().encode());values.put(21,projection.statuses().encode());
        return new zeroecho.pki.api.hybrid.sdk.HybridSdkFrame(4,values);
    }
    private static byte[] sdkText(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] sdkTime(java.time.Instant value) { return java.nio.ByteBuffer.allocate(8).putLong(value.getEpochSecond()).array(); }
    private static byte[] sdkPrimaryPlaceholder() throws IOException {
        var integer = new org.bouncycastle.asn1.ASN1Integer(java.math.BigInteger.ONE.shiftLeft(383));
        return new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{integer,integer}).getEncoded("DER");
    }
    private static int sdkEnvelopeBytes(int nativeBytes, int firstFrame, int secondFrame, int firstSignature, int secondSignature, List<X509Certificate> chain) throws java.security.cert.CertificateEncodingException {
        String empty = "{\"version\":1,\"profile\":\"zeroecho-hybrid-sdk-v1\",\"primaryResponseDer\":\"\",\"responderChain\":[],\"primaryFrame\":\"\",\"alternativeFrame\":\"\",\"primarySignature\":\"\",\"alternativeSignature\":\"\"}";
        long bytes = empty.getBytes(StandardCharsets.UTF_8).length;
        for (int component : new int[]{nativeBytes,firstFrame,secondFrame,firstSignature,secondSignature}) bytes = Math.addExact(bytes,sdkBase64Bytes(component));
        for (var certificate : chain) bytes = Math.addExact(bytes,sdkBase64Bytes(certificate.getEncoded().length));
        bytes = Math.addExact(bytes,Math.addExact(2L*chain.size(),Math.max(0,chain.size()-1)));
        return Math.toIntExact(bytes);
    }
    private static long sdkBase64Bytes(int bytes) { return (Math.addExact(Math.multiplyExact(4L,bytes),2))/3; }

    @Override public void validateSigningMetadata(PkiId authorityId, PkiId responderCredentialId,
            KeyRef signingKeyRef, String signatureAlgorithm, Optional<String> signatureBindingId,
            CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(responderCredentialId, "responderCredentialId");
        Objects.requireNonNull(signingKeyRef, "signingKeyRef");
        Objects.requireNonNull(signatureBindingId, "signatureBindingId");
        Objects.requireNonNull(cancellation, "cancellation");
        try {
            cancellation.throwIfCancelled();
            var binding = signingMetadata(responderCredentialId, signatureAlgorithm, signatureBindingId);
            X509Certificate responder = binding.responder();
            if (!(provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource source)) {
                throw new UnsupportedOperationException("Public responder key metadata unavailable");
            }
            var publicInfo = Objects.requireNonNull(source.resolvePublicKeyInfo(signingKeyRef), "public key metadata");
            if (publicInfo.encoding() != Encoding.DER
                    || !java.util.Arrays.equals(publicInfo.bytes(), Pkix.subjectPublicKeyInfo(responder))) {
                throw new PkiException("OCSP signing metadata differs: code=OCSP_SIGNING_BINDING_FAILED");
            }
            cancellation.throwIfCancelled();
        } catch (IOException failure) { throw new PkiException("OCSP metadata validation failed: code=OCSP_SIGNING_BINDING_FAILED", failure); }
    }

    @Override public void validateSigningBinding(PkiId authorityId, PkiId responderCredentialId,
            KeyRef signingKeyRef, String signatureAlgorithm, Optional<String> signatureBindingId,
            CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(responderCredentialId, "responderCredentialId");
        Objects.requireNonNull(signingKeyRef, "signingKeyRef");
        Objects.requireNonNull(signatureBindingId, "signatureBindingId");
        Objects.requireNonNull(cancellation, "cancellation");
        byte[] challenge = "ZeroEcho OCSP signing binding v1".getBytes(StandardCharsets.US_ASCII);
        try {
            cancellation.throwIfCancelled();
            var binding = signingMetadata(responderCredentialId, signatureAlgorithm, signatureBindingId);
            X509Certificate responder = binding.responder();
            SigningAlgorithm algorithm = binding.algorithm();
            byte[] signature = rawSign(authorityId, signingKeyRef, algorithm.identity(), challenge, Encoding.BINARY, cancellation);
            ContentVerifier verifier = Pkix.verifier(Pkix.subjectPublicKeyInfo(responder), algorithm.identifier());
            try (java.io.OutputStream output = verifier.contentStream()) {
                output.write(challenge);
            }
            if (!verifier.verify(signature)) {
                throw new IOException("OCSP signing binding differs");
            }
        } catch (SigningExecutionException | SigningPendingException signingFailure) {
            throw signingFailure;
        } catch (Exception failure) {
            rethrowSigningBoundaryFailure(failure);
            throw new PkiException("OCSP signing binding validation failed: code=OCSP_SIGNING_BINDING_FAILED");
        }
    }

    private SigningMetadata signingMetadata(PkiId responderCredentialId, String requested,
            Optional<String> binding) throws IOException {
        X509Certificate responder = certificate(responderCredentialId);
        return new SigningMetadata(responder, algorithm(responder, requested, binding));
    }
    private record SigningMetadata(X509Certificate responder, SigningAlgorithm algorithm) { }

    private SigningAlgorithm algorithm(X509Certificate responder, String requested, Optional<String> binding) {
        AlgorithmIdentity identity = authority.resolveIdentity(requested);
        X509SecurityFloor.requirePermitted(identity);
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentity publicKey = adapter.decode(Pkix.subjectPublicKeyAlgorithm(Pkix.subjectPublicKeyInfo(responder)),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(identity, publicKey);
        X509ExecutionPlan<SigningProvider> plan = binding.isPresent()
                ? authority.plan(identity, publicKey, Direction.SIGN, Optional.empty(), "explicit",
                        binding.orElseThrow(), SigningProvider.class)
                : authority.plan(identity, publicKey, Direction.SIGN, Optional.empty(), "default", SigningProvider.class);
        authority.authorize(plan, provider, Direction.SIGN);
        return new SigningAlgorithm(identity, BcX509AlgorithmAdapter.toLib(plan.selection().binding()));
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Before accept, the caller attempts discard but preserves the original cancellation if cleanup fails.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.EmptyCatchBlock" })
    private byte[] rawSign(PkiId authorityId, KeyRef keyRef, AlgorithmIdentity algorithm,
            byte[] content, Encoding contentEncoding, CancellationSignal cancellation) throws IOException {
        provider.inputCapabilities().select(algorithm.canonicalForm(), content.length);
        SigningRequest request = new SigningRequest(signing.newSubmissionId(), ACCESS, keyRef, authorityId,
                algorithm, contentEncoding, Encoding.BINARY);
        PreparedSigningRequest prepared = signing.prepareBoundedObservation(request, oneShot(content), cancellation);
        try {
            cancellation.throwIfCancelled();
        } catch (IOException cancelled) {
            try { signing.discard(prepared); } catch (RuntimeException cleanupFailure) { /* Preserve cancellation. */ }
            throw cancelled;
        }
        // Invocation is the conservative public custody boundary: a thrown accept
        // cannot prove whether transfer happened. Never discard or resubmit afterward.
        SigningAcceptanceDisposition disposition;
        try {
            disposition = signing.accept(prepared).disposition();
        } catch (RuntimeException failure) {
            cancelAfterFailure(request.submissionId().id());
            throw failure;
        }
        if (disposition == SigningAcceptanceDisposition.CAPACITY_REJECTED) {
            throw new SigningExecutionException(SigningExecutionException.Classification.OVERLOADED,
                    "OCSP signing capacity is exhausted");
        }
        if (disposition != SigningAcceptanceDisposition.ACCEPTED
                && disposition != SigningAcceptanceDisposition.ATTACHED_EXISTING) {
            throw new IOException("OCSP signing acceptance failed");
        }
        try {
            SigningOperation operation = signing.awaitBoundedObservation(request.submissionId().id(), cancellation)
                    .orElseThrow(() -> new PkiException("OCSP signing operation is unavailable"));
            if (operation.state() == SigningOperationState.PENDING || operation.state() == SigningOperationState.CANCELLING) {
                throw new SigningPendingException();
            }
            if (operation.state() != SigningOperationState.SUCCEEDED) {
                throw new IOException("OCSP signing did not succeed");
            }
            return operation.signature().orElseThrow(() -> new IOException("OCSP signature is unavailable")).bytes();
        } catch (IOException | RuntimeException failure) {
            cancelAfterFailure(request.submissionId().id());
            throw failure;
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Preserve the post-accept disposition; a failed cancellation attempt does not establish durable cancellation.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.EmptyCatchBlock" })
    private void cancelAfterFailure(PkiId operationId) {
        try {
            signing.cancel(operationId);
        } catch (RuntimeException cleanupFailure) {
            // Keep the original disposition. This failed attempt provides no
            // evidence that cancellation was durably recorded.
        }
    }

    private static OneShotContent oneShot(byte[] content) {
        return new OneShotContent() {
            private boolean opened;
            @Override public InputStream openStream() {
                if (opened) { throw new IllegalStateException("OCSP candidate already opened"); }
                opened = true;
                return new ByteArrayInputStream(content);
            }
            @Override public OptionalLong length() { return OptionalLong.of(content.length); }
            @Override public void close() { /* Byte-array content owns no external resources. */ }
        };
    }

    private static void rethrowSigningBoundaryFailure(Exception failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < 16; depth++) {
            if (current instanceof SigningExecutionException executionFailure) {
                throw executionFailure;
            }
            if (current instanceof SigningPendingException pending) {
                throw pending;
            }
            Throwable cause = current.getCause();
            if (cause == current) return; // NOPMD - identity detects a malformed cyclic cause chain.
            current = cause;
        }
    }

    private List<Resolved> resolve(Command command, X509Certificate issuer, RevocationView view,
            CancellationSignal cancellation) throws IOException {
        List<Resolved> result = new ArrayList<>(command.requests().size());
        for (CertId request : command.requests()) {
            cancellation.throwIfCancelled();
            String digestOid = request.hash() == CertIdHash.SHA256 ? SHA256_OID : SHA1_OID;
            zeroecho.pkix.ocsp.CertId id = Pkix.computeCertId(issuer, request.serial(), digestOid);
            if (!MessageDigest.isEqual(id.issuerNameHash(), request.issuerNameHash())
                    || !MessageDigest.isEqual(id.issuerKeyHash(), request.issuerKeyHash())) {
                result.add(new Resolved(id, CertStatus.unknown()));
                continue;
            }
            Credential credential = store.getCredentialByIssuerAndSerial(command.issuerId(), request.serial())
                    .orElse(null);
            if (credential == null) {
                result.add(new Resolved(id, CertStatus.unknown()));
                continue;
            }
            CertStatus status = view.get(credential.credentialId())
                    .map(record -> status(record.transition().state(), record.transition().time(),
                            record.transition().permanentReason().orElse(RevocationReason.UNSPECIFIED)))
                    .orElse(CertStatus.good());
            result.add(new Resolved(id, status));
        }
        return List.copyOf(result);
    }

    private byte[] sign(Command command, X509Certificate responder, List<X509Certificate> chain,
            SigningAlgorithm algorithm, List<Resolved> resolved, CancellationSignal cancellation) throws Exception {
        byte[] tbs = responseTbs(command, responder, resolved);
        byte[] signature = rawSign(command.authorityId(), command.signingKeyRef(), algorithm.identity(), tbs, Encoding.DER, cancellation);
        byte[] encoded = Pkix.assembleOcspResponse(tbs, Pkix.encodeAlgorithmIdentifier(algorithm.identifier()), signature, chain);
        OcspResponse decoded = Pkix.parseOcspResponse(encoded);
        zeroecho.pkix.ocsp.ResponderId responderId = command.responderId() == ResponderId.BY_NAME
                ? zeroecho.pkix.ocsp.ResponderId.byName(responder.getSubjectX500Principal())
                : zeroecho.pkix.ocsp.ResponderId.byKey(Pkix.subjectKeyIdentifier(responder.getPublicKey()));
        if (!decoded.isSuccessful()
                || !decoded.producedAt().equals(command.producedAt())
                || !decoded.responderId().equals(responderId)
                || !decoded.signatureAlgorithm().equals(algorithm.identifier())
                || !decoded.verifySignature(responder.getPublicKey())
                || !matchesResponses(decoded.responses(), resolved, command)
                || !matchesCertificates(decoded.certificates(), chain)
                || !matchesNonce(decoded, command.nonce())) {
            throw new IOException("Generated OCSP response validation failed");
        }
        return encoded;
    }

    private static byte[] responseTbs(Command command, X509Certificate responder, List<Resolved> resolved) {
        zeroecho.pkix.ocsp.ResponderId responderId = command.responderId() == ResponderId.BY_NAME
                ? zeroecho.pkix.ocsp.ResponderId.byName(responder.getSubjectX500Principal())
                : zeroecho.pkix.ocsp.ResponderId.byKey(Pkix.subjectKeyIdentifier(responder.getPublicKey()));
        zeroecho.pkix.ocsp.OcspResponseBuilder builder = Pkix.ocspResponseBuilder().responderId(responderId)
                .producedAt(command.producedAt());
        for (Resolved item : resolved) {
            builder.addResponse(item.id(), item.status(), command.thisUpdate(), command.nextUpdate());
        }
        command.nonce().ifPresent(builder::nonce);
        return builder.buildTbs();
    }

    private static boolean matchesResponses(List<OcspResponse.SingleResponse> decoded, List<Resolved> expected,
            Command command) {
        if (decoded.size() != expected.size()) return false;
        for (int index = 0; index < decoded.size(); index++) {
            OcspResponse.SingleResponse actual = decoded.get(index);
            Resolved wanted = expected.get(index);
            if (!actual.certId().equals(wanted.id())
                    || !actual.thisUpdate().equals(command.thisUpdate())
                    || actual.nextUpdate().isEmpty()
                    || !actual.nextUpdate().orElseThrow().equals(command.nextUpdate())
                    || !statusMatches(actual.status(), wanted.status())) return false;
        }
        return true;
    }

    // Compares certificate statuses tolerating the OCSP GeneralizedTime encoding precision: the revocation
    // time is round-tripped through the DER encoding, so it is compared at whole-second granularity.
    private static boolean statusMatches(CertStatus actual, CertStatus expected) {
        if (expected instanceof CertStatus.Good) {
            return actual instanceof CertStatus.Good;
        }
        if (expected instanceof CertStatus.Unknown) {
            return actual instanceof CertStatus.Unknown;
        }
        if (expected instanceof CertStatus.Revoked expectedRevoked
                && actual instanceof CertStatus.Revoked actualRevoked) {
            return actualRevoked.reason().equals(expectedRevoked.reason())
                    && actualRevoked.revocationTime().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
                            .equals(expectedRevoked.revocationTime()
                                    .truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
        }
        return false;
    }

    private static boolean matchesCertificates(List<X509Certificate> decoded, List<X509Certificate> expected)
            throws java.security.cert.CertificateEncodingException {
        if (decoded.size() != expected.size()) return false;
        for (int index = 0; index < decoded.size(); index++) {
            if (!Arrays.equals(decoded.get(index).getEncoded(), expected.get(index).getEncoded())) return false;
        }
        return true;
    }

    private static boolean matchesNonce(OcspResponse decoded, Optional<byte[]> expected) {
        Optional<byte[]> actual = decoded.nonce();
        if (expected.isEmpty()) return actual.isEmpty();
        return actual.isPresent() && MessageDigest.isEqual(actual.orElseThrow(), expected.orElseThrow());
    }

    private void validateAuthority(Command command, X509Certificate issuer, X509Certificate responder) {
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
        boolean validOn;
        try {
            responder.checkValidity(java.util.Date.from(command.producedAt()));
            validOn = true;
        } catch (java.security.cert.CertificateExpiredException
                | java.security.cert.CertificateNotYetValidException expired) {
            validOn = false;
        }
        if (!validOn || command.nextUpdate().isAfter(responder.getNotAfter().toInstant())) {
            throw new IllegalArgumentException("OCSP response exceeds responder signing validity");
        }
    }

    private X509Certificate certificate(PkiId credentialId, Map<PkiId, X509Certificate> certificates) throws IOException {
        X509Certificate resolved = certificates.get(credentialId);
        if (resolved == null) {
            resolved = certificate(credentialId);
            certificates.put(credentialId, resolved);
        }
        return resolved;
    }

    private X509Certificate certificate(PkiId credentialId) throws IOException {
        try (PkiRepositoryContent content = new DefaultPkiRepository(store, requireOpen)
                .openCredential(credentialId); InputStream input = content.openStream()) {
            byte[] encoded = input.readNBytes(1_048_577);
            if (encoded.length > 1_048_576 || input.read() != -1) {
                throw new IOException("OCSP certificate exceeds its finite bound");
            }
            return Pkix.parseCertificate(encoded);
        }
    }

    private static CertStatus status(RevocationState state, java.time.Instant time, RevocationReason reason) {
        return switch (state) {
            case CLEAR -> CertStatus.good();
            case HELD -> CertStatus.revoked(time, CrlReason.CERTIFICATE_HOLD);
            case PERMANENTLY_REVOKED -> CertStatus.revoked(time, reason(reason));
        };
    }

    private static CrlReason reason(RevocationReason reason) {
        return switch (reason) {
            case KEY_COMPROMISE -> CrlReason.KEY_COMPROMISE;
            case CA_COMPROMISE -> CrlReason.CA_COMPROMISE;
            case AFFILIATION_CHANGED -> CrlReason.AFFILIATION_CHANGED;
            case SUPERSEDED -> CrlReason.SUPERSEDED;
            case CESSATION_OF_OPERATION -> CrlReason.CESSATION_OF_OPERATION;
            case CERTIFICATE_HOLD -> CrlReason.CERTIFICATE_HOLD;
            case REMOVE_FROM_CRL -> CrlReason.REMOVE_FROM_CRL;
            case PRIVILEGE_WITHDRAWN -> CrlReason.PRIVILEGE_WITHDRAWN;
            case AA_COMPROMISE -> CrlReason.AA_COMPROMISE;
            case UNSPECIFIED -> CrlReason.UNSPECIFIED;
        };
    }

    private record SigningAlgorithm(AlgorithmIdentity identity, AlgorithmIdentifier identifier) { }

    private record Resolved(zeroecho.pkix.ocsp.CertId id, CertStatus status) { }
}
