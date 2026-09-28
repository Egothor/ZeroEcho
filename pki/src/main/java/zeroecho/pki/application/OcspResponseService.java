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

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PkiException;
import zeroecho.core.io.CancellationSignal;

/**
 * Transport-neutral strict OCSP response generation through session-owned signing.
 * Callers authorize responder policy and authority scope before invocation. The
 * service captures one revocation view and releases it before bounded raw signing;
 * it introduces no persistent OCSP operation or foreground provider executor.
 */
@SuppressWarnings("PMD.ControlStatementBraces")
public interface OcspResponseService {
    /** Supported RFC CertID digest identities. */
    enum CertIdHash {
        /** SHA-1 CertID digest used by the mandatory OCSP interoperability profile. */
        SHA1(1),
        /** SHA-256 CertID digest. */
        SHA256(2);

        private final int code;

        CertIdHash(int code) { this.code = code; }

        /**
         * Returns the stable persistence code.
         *
         * @return positive stable persistence code
         */
        public int code() { return code; }

        /**
         * Resolves an exact stable persistence code.
         *
         * @param code stable code returned by {@link #code()}
         * @return matching digest identity
         * @throws IllegalArgumentException if {@code code} is unknown
         */
        public static CertIdHash fromCode(int code) {
            return switch (code) { case 1 -> SHA1; case 2 -> SHA256;
                default -> throw new IllegalArgumentException("Unknown OCSP CertID hash code"); };
        }
    }
    /** Exact responder identifier representation. */
    enum ResponderId {
        /** Identifies the responder by its distinguished name. */
        BY_NAME(1),
        /** Identifies the responder by its public-key hash. */
        BY_KEY(2);

        private final int code;

        ResponderId(int code) { this.code = code; }

        /**
         * Returns the stable persistence code.
         *
         * @return positive stable persistence code
         */
        public int code() { return code; }

        /**
         * Resolves an exact stable persistence code.
         *
         * @param code stable code returned by {@link #code()}
         * @return matching responder identifier representation
         * @throws IllegalArgumentException if {@code code} is unknown
         */
        public static ResponderId fromCode(int code) {
            return switch (code) { case 1 -> BY_NAME; case 2 -> BY_KEY;
                default -> throw new IllegalArgumentException("Unknown OCSP responder ID code"); };
        }
    }

    /**
     * One strictly parsed CertID.
     *
     * @param hash digest identity governing both issuer hashes
     * @param issuerNameHash exact 20-byte SHA-1 or 32-byte SHA-256 issuer-name digest
     * @param issuerKeyHash exact 20-byte SHA-1 or 32-byte SHA-256 issuer-key digest
     * @param serial positive certificate serial number of at most 160 bits
     */
    record CertId(CertIdHash hash, byte[] issuerNameHash, byte[] issuerKeyHash, BigInteger serial) {
        /** Defensively owns all request values. */
        public CertId {
            Objects.requireNonNull(hash, "hash");
            issuerNameHash = Objects.requireNonNull(issuerNameHash, "issuerNameHash").clone();
            issuerKeyHash = Objects.requireNonNull(issuerKeyHash, "issuerKeyHash").clone();
            Objects.requireNonNull(serial, "serial");
            int length = hash == CertIdHash.SHA1 ? 20 : 32;
            if (issuerNameHash.length != length || issuerKeyHash.length != length
                    || serial.signum() <= 0 || serial.bitLength() > 160) {
                throw new IllegalArgumentException("OCSP CertID is invalid");
            }
        }
        /**
         * Returns the issuer-name digest without exposing internal state.
         *
         * @return defensive copy of the issuer-name digest
         */
        @Override public byte[] issuerNameHash() { return issuerNameHash.clone(); }
        /**
         * Returns the issuer-key digest without exposing internal state.
         *
         * @return defensive copy of the issuer-key digest
         */
        @Override public byte[] issuerKeyHash() { return issuerKeyHash.clone(); }
    }

    /**
     * Exact already-authorized responder generation command.
     *
     * @param authorityId authorized authority scope
     * @param issuerId exact issuer generation
     * @param issuerCredentialId issuer credential represented by the CertIDs
     * @param responderCredentialId credential whose key signs the response
     * @param signingKeyRef confined responder signing-key reference
     * @param responseChain nonempty responder chain of at most 32 credentials
     * @param signatureAlgorithm nonblank canonical signature algorithm
     * @param signatureBindingId optional exact algorithm-binding identifier
     * @param responderId responder identifier representation
     * @param producedAt response production instant
     * @param thisUpdate revocation-view effective instant, not after {@code producedAt}
     * @param nextUpdate next scheduled update, strictly after {@code thisUpdate}
     * @param nonce optional request nonce; its bytes are defensively copied
     * @param requests nonempty finite CertID request list
     */
    record Command(PkiId authorityId, PkiId issuerId, PkiId issuerCredentialId,
            PkiId responderCredentialId, KeyRef signingKeyRef, List<PkiId> responseChain,
            String signatureAlgorithm, Optional<String> signatureBindingId,
            ResponderId responderId, Instant producedAt, Instant thisUpdate, Instant nextUpdate,
            Optional<byte[]> nonce, List<CertId> requests) {
        /** Validates finite exact responder inputs. */
        public Command {
            Objects.requireNonNull(authorityId, "authorityId"); Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(issuerCredentialId, "issuerCredentialId");
            Objects.requireNonNull(responderCredentialId, "responderCredentialId");
            Objects.requireNonNull(signingKeyRef, "signingKeyRef");
            responseChain = List.copyOf(Objects.requireNonNull(responseChain, "responseChain"));
            if (responseChain.isEmpty() || responseChain.size() > 32) throw new IllegalArgumentException("OCSP chain is invalid");
            if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) throw new IllegalArgumentException("OCSP algorithm is invalid");
            signatureBindingId = Objects.requireNonNull(signatureBindingId, "signatureBindingId");
            Objects.requireNonNull(responderId, "responderId"); Objects.requireNonNull(producedAt, "producedAt");
            Objects.requireNonNull(thisUpdate, "thisUpdate"); Objects.requireNonNull(nextUpdate, "nextUpdate");
            if (thisUpdate.isAfter(producedAt) || !nextUpdate.isAfter(thisUpdate)) throw new IllegalArgumentException("OCSP times are invalid");
            nonce = Objects.requireNonNull(nonce, "nonce").map(byte[]::clone);
            requests = List.copyOf(Objects.requireNonNull(requests, "requests"));
            if (requests.isEmpty()) throw new IllegalArgumentException("OCSP request is empty");
        }
        /**
         * Returns the optional nonce without exposing internal state.
         *
         * @return optional defensive copy of the nonce
         */
        @Override public Optional<byte[]> nonce() { return nonce.map(byte[]::clone); }
    }

    /**
     * Signed canonical response and stable revocation provenance.
     *
     * @param der canonical signed OCSP response DER, defensively copied
     * @param revocationRevision nonnegative authoritative revocation revision
     * @param revocationCommitment lowercase 64-hex-character snapshot commitment
     * @param goodCount number of good single responses
     * @param revokedCount number of revoked single responses
     * @param unknownCount number of unknown single responses
     */
    record Response(byte[] der, long revocationRevision, String revocationCommitment,
            int goodCount, int revokedCount, int unknownCount) {
        /** Defensively owns response DER. */
        public Response {
            der = Objects.requireNonNull(der, "der").clone();
            if (revocationRevision < 0 || revocationCommitment == null
                    || !revocationCommitment.matches("[0-9a-f]{64}") || goodCount < 0 || revokedCount < 0
                    || unknownCount < 0 || Math.addExact(Math.addExact(goodCount, revokedCount), unknownCount) == 0) {
                throw new IllegalArgumentException("OCSP provenance is invalid");
            }
        }
        /**
         * Returns the response DER without exposing internal state.
         *
         * @return defensive copy of the canonical signed response
         */
        @Override public byte[] der() { return der.clone(); }
    }

    /**
     * Resolves one stable view and signs exactly one response.
     *
     * @param command validated responder generation command
     * @return signed response with revocation provenance
     * @throws SigningPendingException if the bounded signing attempt remains pending
     * @throws zeroecho.pki.api.SigningExecutionException if signing is overloaded or shutting down
     * @throws PkiException if response validation or signing fails, without sensitive causes
     */
    default Response respond(Command command) {
        return respond(command, CancellationSignal.NONE);
    }

    /**
     * Resolves and signs one response with originating cancellation.
     *
     * @param command validated responder generation command
     * @param cancellation originating cancellation signal
     * @return signed response with revocation provenance
     * @throws SigningPendingException if the bounded signing attempt remains pending
     * @throws zeroecho.pki.api.SigningExecutionException if signing is overloaded or shutting down
     * @throws PkiException if response validation or signing fails, without sensitive causes
     */
    Response respond(Command command, CancellationSignal cancellation);

    /**
     * Proves that one configured confined key capability signs as the exact
     * responder certificate before a durable responder is activated.
     *
     * @param authorityId explicitly authorized authority used for signing fairness, never inferred from the responder issuer
     * @param responderCredentialId exact responder credential
     * @param signingKeyRef confined signing-key reference under test
     * @param signatureAlgorithm canonical signature algorithm
     * @param signatureBindingId optional exact algorithm-binding identifier
     * @throws SigningPendingException if the bounded signing attempt remains pending
     * @throws zeroecho.pki.api.SigningExecutionException if signing is overloaded or shutting down
     * @throws PkiException if the binding cannot be verified, without sensitive causes
     */
    default void validateSigningBinding(PkiId authorityId, PkiId responderCredentialId, KeyRef signingKeyRef,
            String signatureAlgorithm, Optional<String> signatureBindingId) {
        validateSigningBinding(authorityId, responderCredentialId, signingKeyRef, signatureAlgorithm, signatureBindingId,
                CancellationSignal.NONE);
    }

    /**
     * Validates responder signing while carrying originating cancellation.
     *
     * @param authorityId explicitly authorized authority used for signing fairness, never inferred from the responder issuer
     * @param responderCredentialId exact responder credential
     * @param signingKeyRef confined signing-key reference under test
     * @param signatureAlgorithm canonical signature algorithm
     * @param signatureBindingId optional exact algorithm-binding identifier
     * @param cancellation originating cancellation signal
     * @throws SigningPendingException if the bounded signing attempt remains pending
     * @throws zeroecho.pki.api.SigningExecutionException if signing is overloaded or shutting down
     * @throws PkiException if the binding cannot be verified, without sensitive causes
     */
    void validateSigningBinding(PkiId authorityId, PkiId responderCredentialId, KeyRef signingKeyRef,
            String signatureAlgorithm, Optional<String> signatureBindingId, CancellationSignal cancellation);

    /**
     * Content-free result indicating that the bounded initial signing attempt
     * returned pending. Durable cancellation is requested without awaiting cleanup;
     * this exception carries no operation identity or provider diagnostic.
     */
    final class SigningPendingException extends PkiException {
        private static final long serialVersionUID = 825419348201647529L;

        /** Creates the fixed safe pending disposition. */
        public SigningPendingException() {
            super("OCSP signing remains pending");
        }
    }
}
