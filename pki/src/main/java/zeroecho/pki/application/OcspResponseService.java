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

/** Transport-neutral strict OCSP response generation through confined signing. */
@SuppressWarnings("PMD.ControlStatementBraces")
public interface OcspResponseService {
    /** Supported RFC CertID digest identities. */
    enum CertIdHash {
        SHA1(1), SHA256(2);

        private final int code;

        CertIdHash(int code) { this.code = code; }

        /** Stable persistence code. */
        public int code() { return code; }

        /** Resolves an exact stable persistence code. */
        public static CertIdHash fromCode(int code) {
            return switch (code) { case 1 -> SHA1; case 2 -> SHA256;
                default -> throw new IllegalArgumentException("Unknown OCSP CertID hash code"); };
        }
    }
    /** Exact responder identifier representation. */
    enum ResponderId {
        BY_NAME(1), BY_KEY(2);

        private final int code;

        ResponderId(int code) { this.code = code; }

        /** Stable persistence code. */
        public int code() { return code; }

        /** Resolves an exact stable persistence code. */
        public static ResponderId fromCode(int code) {
            return switch (code) { case 1 -> BY_NAME; case 2 -> BY_KEY;
                default -> throw new IllegalArgumentException("Unknown OCSP responder ID code"); };
        }
    }

    /** One strictly parsed CertID. */
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
        @Override public byte[] issuerNameHash() { return issuerNameHash.clone(); }
        @Override public byte[] issuerKeyHash() { return issuerKeyHash.clone(); }
    }

    /** Exact already-authorized responder generation command. */
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
        @Override public Optional<byte[]> nonce() { return nonce.map(byte[]::clone); }
    }

    /** Signed canonical response and stable revocation provenance. */
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
        @Override public byte[] der() { return der.clone(); }
    }

    /** Resolves one stable view and signs exactly one response. */
    Response respond(Command command);

    /**
     * Proves that one configured confined key capability signs as the exact
     * responder certificate before a durable responder is activated.
     */
    void validateSigningBinding(PkiId responderCredentialId, KeyRef signingKeyRef,
            String signatureAlgorithm, Optional<String> signatureBindingId);
}
