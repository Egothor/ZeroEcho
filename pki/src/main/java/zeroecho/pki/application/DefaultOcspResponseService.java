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

    /* default */ DefaultOcspResponseService(PkiStore store, SigningService signing, SigningProvider provider,
            X509AuthoritySnapshot authority, Runnable requireOpen) {
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
            X509Certificate responder = certificate(responderCredentialId);
            SigningAlgorithm algorithm = algorithm(responder, signatureAlgorithm, signatureBindingId);
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
        zeroecho.pkix.ocsp.ResponderId responderId = command.responderId() == ResponderId.BY_NAME
                ? zeroecho.pkix.ocsp.ResponderId.byName(responder.getSubjectX500Principal())
                : zeroecho.pkix.ocsp.ResponderId.byKey(Pkix.subjectKeyIdentifier(responder.getPublicKey()));
        zeroecho.pkix.ocsp.OcspResponseBuilder builder = Pkix.ocspResponseBuilder().responderId(responderId)
                .producedAt(command.producedAt());
        for (Resolved item : resolved) {
            builder.addResponse(item.id(), item.status(), command.thisUpdate(), command.nextUpdate());
        }
        command.nonce().ifPresent(builder::nonce);
        byte[] tbs = builder.buildTbs();
        byte[] signature = rawSign(command.authorityId(), command.signingKeyRef(), algorithm.identity(), tbs, Encoding.DER, cancellation);
        byte[] encoded = Pkix.assembleOcspResponse(tbs, Pkix.encodeAlgorithmIdentifier(algorithm.identifier()), signature, chain);
        OcspResponse decoded = Pkix.parseOcspResponse(encoded);
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
