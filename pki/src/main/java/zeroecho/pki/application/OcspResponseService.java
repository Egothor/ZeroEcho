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
 *
 * <p>Native responses retain ordinary RFC 6960 single-signature semantics. The
 * optional SDK response path adds separate F4/F5 evidence; it is not a standard
 * alternative-signature BasicOCSPResponse. A GOOD status is not itself certificate
 * path validation, and retained evidence does not remain fresh independently of
 * the verifier's actual evaluation time.
 */
@SuppressWarnings("PMD.ControlStatementBraces")
public interface OcspResponseService {
    /**
     * Checks configured responder key metadata and algorithm binding without signing a challenge.
     * A successful check does not replace the approved execution's proof of key possession.
     * @param authorityId authorized logical authority
     * @param responderCredentialId exact responder credential
     * @param signingKeyRef configured managed signing key
     * @param signatureAlgorithm exact signature identity
     * @param signatureBindingId optional explicit format binding
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if public key metadata validation is unavailable
     * @throws RuntimeException if key metadata, certificate or algorithm binding differs
     */
    default void validateSigningMetadata(PkiId authorityId, PkiId responderCredentialId, KeyRef signingKeyRef,
            String signatureAlgorithm, Optional<String> signatureBindingId, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure OCSP signing metadata validation unavailable");
    }

    /**
     * Frozen server-managed responder role; this value grants no signing authority.
     * @param keyRef existing nonexportable managed key
     * @param signatureAlgorithm exact canonical outgoing signature identity
     * @param signatureBindingId optional configured binding; must be exactly default-equivalent because raw signing carries no binding selector
     */
    record SdkSigningRole(KeyRef keyRef, String signatureAlgorithm, Optional<String> signatureBindingId) {
        /**
         * Requires a key reference, binding optional and nonblank signature identity.
         *
         * <p>This constructor does not resolve managed custody, enforce the SDK's
         * role algorithm or validate default-equivalent binding selection. Those
         * checks belong to authoritative responder capture and query execution.
         *
         * @throws NullPointerException if the key reference or binding optional is null
         * @throws IllegalArgumentException if the signature identity is null or blank
         * @param keyRef existing nonexportable managed key
         * @param signatureAlgorithm exact canonical outgoing signature identity
         * @param signatureBindingId optional configured binding; must be exactly default-equivalent because raw signing carries no binding selector
         */
        public SdkSigningRole {
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(signatureBindingId, "signatureBindingId");
            if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
                throw new IllegalArgumentException("SDK OCSP role invalid");
            }
        }
    }

    /**
     * Trusted native-service responder authorization captured before a query. No caller JSON
     * or bundle may create this authority. The service verifies immutable store coordinates,
     * public key metadata, delegation and both role plans; it never follows today's CA head.
     *
     * <p>Trust is established by the native capture boundary, not by this record's
     * constructor. The constructor checks and snapshots bounded identifiers, lists
     * and role/path structure; callers must not treat applicant-supplied JSON as
     * an authoritative binding merely because that structure is valid.
     *
     * @param realmId configured trusted realm
     * @param canonicalOrigin explicitly configured HTTPS origin
     * @param authorityId exact logical issuer CA
     * @param issuerId immutable issuer generation
     * @param issuerCredentialId immutable issuer certificate
     * @param chainPathId immutable selected issuer path
     * @param pathCommitment full path commitment
     * @param issuerBindingCommitment exact raw lowercase issuer binding SHA256
     * @param responderCredentialId directly delegated hybrid OCSP-signing leaf
     * @param responseChain exact responder followed by issuer path, at most 32 credentials
     * @param primary dedicated managed P384 responder role
     * @param alternative dedicated managed ML-DSA-87 responder role
     * @param issuerCertificateBaselines independently frozen encoding baseline per issuer-path certificate
     * @param responderId existing native responder-ID representation
     */
    record SdkResponderBinding(String realmId, String canonicalOrigin, PkiId authorityId, PkiId issuerId,
            PkiId issuerCredentialId, PkiId chainPathId, String pathCommitment, String issuerBindingCommitment,
            PkiId responderCredentialId, List<PkiId> responseChain, SdkSigningRole primary, SdkSigningRole alternative,
            List<zeroecho.pki.api.ca.IssuerCryptographicBinding.HybridSignatureBaseline> issuerCertificateBaselines, ResponderId responderId) {
        /**
         * Snapshots chain/baseline lists and rejects incomplete or inconsistent role/path structure.
         *
         * <p>The response chain begins with the responder and selected issuer, contains
         * no duplicate credential, and has one encoding baseline per issuer-path
         * certificate. Both managed role references must differ. No credential,
         * public key, signature or caller authorization is resolved here.
         *
         * @throws NullPointerException if a required identity, role, responder ID,
         *         list or list entry is null
         * @throws IllegalArgumentException if realm, origin, commitment, chain shape,
         *         baseline count or role distinctness is invalid
         * @param realmId configured trusted realm
         * @param canonicalOrigin explicitly configured HTTPS origin
         * @param authorityId exact logical issuer CA
         * @param issuerId immutable issuer generation
         * @param issuerCredentialId immutable issuer certificate
         * @param chainPathId immutable selected issuer path
         * @param pathCommitment full path commitment
         * @param issuerBindingCommitment exact raw lowercase issuer binding SHA256
         * @param responderCredentialId directly delegated hybrid OCSP-signing leaf
         * @param responseChain exact responder followed by issuer path, at most 32 credentials
         * @param primary dedicated managed P384 responder role
         * @param alternative dedicated managed ML-DSA-87 responder role
         * @param issuerCertificateBaselines independently frozen encoding baseline per issuer-path certificate
         * @param responderId existing native responder-ID representation
         */
        public SdkResponderBinding {
            if (realmId == null || realmId.isBlank()) {
                throw new IllegalArgumentException("SDK OCSP realm invalid");
            }
            zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.requireOrigin(canonicalOrigin);
            Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(issuerCredentialId, "issuerCredentialId");
            Objects.requireNonNull(chainPathId, "chainPathId");
            Objects.requireNonNull(responderCredentialId, "responderCredentialId");
            if (pathCommitment == null || !pathCommitment.matches("[0-9a-f]{64}")
                    || issuerBindingCommitment == null || !issuerBindingCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("SDK OCSP commitment invalid");
            }
            responseChain = List.copyOf(responseChain);
            issuerCertificateBaselines = List.copyOf(issuerCertificateBaselines);
            Objects.requireNonNull(primary, "primary");
            Objects.requireNonNull(alternative, "alternative");
            Objects.requireNonNull(responderId, "responderId");
            if (responseChain.size() < 2 || responseChain.size() > 32 || new java.util.HashSet<>(responseChain).size() != responseChain.size()
                    || !responseChain.getFirst().equals(responderCredentialId) || !responseChain.get(1).equals(issuerCredentialId)
                    || issuerCertificateBaselines.size() != responseChain.size() - 1 || primary.keyRef().equals(alternative.keyRef())) {
                throw new IllegalArgumentException("SDK OCSP chain/roles invalid");
            }
        }
    }

    /**
     * Authorized native query with independent fresh SDK nonce. Times and statuses are service-owned.
     * @param responder trusted frozen responder authorization
     * @param originalRequestDer exact native request, at most one MiB
     * @param clientNonce fresh locally generated 32-byte SDK nonce, separate from native nonce
     * @param nextUpdateAfter positive whole-second native response interval; evidence life is at most 120 seconds
     */
    record SdkCommand(SdkResponderBinding responder, byte[] originalRequestDer, byte[] clientNonce, java.time.Duration nextUpdateAfter) {
        /**
         * Snapshots bounded request and SDK nonce bytes and validates the update interval.
         *
         * <p>The constructor checks one-MiB request and 32-byte SDK nonce bounds,
         * not native ASN.1 request syntax or nonce randomness/freshness. The response
         * interval must be positive and have whole-second precision.
         *
         * @throws NullPointerException if a component is null
         * @throws IllegalArgumentException if request length, nonce length or interval is invalid
         * @param responder trusted frozen responder authorization
         * @param originalRequestDer exact native request, at most one MiB
         * @param clientNonce fresh locally generated 32-byte SDK nonce, separate from native nonce
         * @param nextUpdateAfter positive whole-second native response interval; evidence life is at most 120 seconds
         */
        public SdkCommand {
            Objects.requireNonNull(responder, "responder");
            Objects.requireNonNull(originalRequestDer, "originalRequestDer");
            Objects.requireNonNull(clientNonce, "clientNonce");
            Objects.requireNonNull(nextUpdateAfter, "nextUpdateAfter");
            if (originalRequestDer.length == 0 || originalRequestDer.length > 1048576 || clientNonce.length != 32
                    || nextUpdateAfter.isNegative() || nextUpdateAfter.isZero() || nextUpdateAfter.getNano() != 0) {
                throw new IllegalArgumentException("SDK OCSP query invalid");
            }
            originalRequestDer = originalRequestDer.clone();
            clientNonce = clientNonce.clone();
        }
        /**
         * Returns the original native request without exposing its retained array.
         *
         * @return independently owned exact request DER bytes
         */
        @Override
        public byte[] originalRequestDer() {
            return originalRequestDer.clone();
        }
        /**
         * Returns the caller's SDK nonce without exposing its retained array.
         *
         * @return an independent 32-byte SDK nonce copy
         */
        @Override
        public byte[] clientNonce() {
            return clientNonce.clone();
        }
    }

    /**
     * Produces a complete native response and separate two-role SDK evidence from one status view.
     * No response DER, status or production time is accepted from the caller. No partial bundle
     * is returned on cancellation, pending or uncertain signing custody.
     *
     * <p>The native request is parsed and bounded to 1 through 819 CertIDs, with
     * a present native nonce limited to 1 through 4,096 bytes. Response times and
     * statuses derive from the service's actual clock and one captured revocation
     * view. The separate SDK nonce is distinct from any native nonce. Successful
     * construction self-verifies the complete native plus F4/F5 bundle; later use
     * still requires verification at the actual evaluation time and trust context.
     * No standard alternative-signature OCSP or certificate-path validity follows
     * solely from a GOOD status in this result.
     *
     * @param command genuine authorized native query and immutable responder binding
     * @param cancellation originating cancellation signal
     * @return self-verified complete evidence bundle
     * @throws UnsupportedOperationException if SDK response construction is unavailable
     * @throws SigningPendingException for inconclusive bounded signing
     * @throws PkiException for invalid binding, bounds or signatures
     */
    default zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence respondSdk(SdkCommand command, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK OCSP evidence unavailable");
    }

    /**
     * Validates trusted registration coordinates and existing managed responder roles without a listener origin.
     * Performs no signing, status lookup or durable mutation. CA key-reference/SPKI collisions and
     * managed custody are checked; no exhaustive historical client-key-purpose ledger is claimed.
     * @param authorityId authorized logical issuer CA
     * @param issuerId exact immutable issuer generation
     * @param responderCredentialId directly delegated responder credential
     * @param chainPathId exact immutable issuer path
     * @param primary existing managed primary role
     * @param alternative existing managed alternative role
     * @param responderId native responder identity representation
     * @param cancellation originating cancellation
     * @throws UnsupportedOperationException if SDK metadata validation is unavailable
     * @throws PkiException for inconsistent or unauthorized public evidence
     */
    default void validateSdkResponderMetadata(PkiId authorityId, PkiId issuerId, PkiId responderCredentialId,
            PkiId chainPathId, SdkSigningRole primary, SdkSigningRole alternative, ResponderId responderId, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK OCSP metadata validation unavailable");
    }

    /**
     * Captures a validated SDK responder binding from authoritative immutable store evidence.
     * Caller authorization and realm/origin configuration remain the trusted native service's duty.
     * This pure operation derives chain, binding commitment and explicit persisted baselines;
     * it signs nothing, opens no status snapshot, changes no metadata and never follows the CA head.
     * @param trustedRealm independently configured realm
     * @param canonicalOrigin independently configured listener origin
     * @param authorityId authorized logical issuer CA
     * @param issuerId exact immutable issuer generation
     * @param responderCredentialId directly delegated responder credential
     * @param chainPathId exact immutable issuer path
     * @param primary existing managed primary role
     * @param alternative existing managed alternative role
     * @param responderId native responder identity representation
     * @param cancellation originating cancellation
     * @return complete immutable binding derived from the owned store and public provider metadata
     * @throws UnsupportedOperationException if authoritative capture is unavailable
     * @throws PkiException for inconsistent or unauthorized public evidence
     */
    default SdkResponderBinding captureSdkResponderBinding(String trustedRealm, String canonicalOrigin, PkiId authorityId,
            PkiId issuerId, PkiId responderCredentialId, PkiId chainPathId, SdkSigningRole primary, SdkSigningRole alternative,
            ResponderId responderId, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK OCSP binding capture unavailable");
    }

    /**
     * Supported digest identities for the issuer-name and issuer-key hashes in RFC CertID values.
     */
    enum CertIdHash {
        /**
         * SHA-1 CertID digest used by the mandatory OCSP interoperability profile.
         */
        SHA1(1),
        /**
         * SHA-256 CertID digest.
         */
        SHA256(2);

        private final int code;

        /**
         * Associates the OCSP CertID digest identity with its stable persisted code.
         *
         * @param code explicit canonical code assigned by the enum declaration
         */
        CertIdHash(int code) {
            this.code = code;
        }

        /**
         * Returns the stable persistence code.
         *
         * @return positive stable persistence code
         */
        public int code() {
            return code;
        }

        /**
         * Resolves an exact stable persistence code.
         *
         * @param code stable code returned by {@link #code()}
         * @return matching digest identity
         * @throws IllegalArgumentException if {@code code} is unknown
         */
        public static CertIdHash fromCode(int code) {
            return switch (code) {
                case 1 -> SHA1;
                case 2 -> SHA256;
                default -> throw new IllegalArgumentException("Unknown OCSP CertID hash code");
            };
        }
    }
    /**
     * Selects the exact native responder identifier representation.
     */
    enum ResponderId {
        /**
         * Identifies the responder by its distinguished name.
         */
        BY_NAME(1),
        /**
         * Identifies the responder by its public-key hash.
         */
        BY_KEY(2);

        private final int code;

        /**
         * Associates the OCSP responder identifier representation with its stable persisted code.
         *
         * @param code explicit canonical code assigned by the enum declaration
         */
        ResponderId(int code) {
            this.code = code;
        }

        /**
         * Returns the stable persistence code.
         *
         * @return positive stable persistence code
         */
        public int code() {
            return code;
        }

        /**
         * Resolves an exact stable persistence code.
         *
         * @param code stable code returned by {@link #code()}
         * @return matching responder identifier representation
         * @throws IllegalArgumentException if {@code code} is unknown
         */
        public static ResponderId fromCode(int code) {
            return switch (code) {
                case 1 -> BY_NAME;
                case 2 -> BY_KEY;
                default -> throw new IllegalArgumentException("Unknown OCSP responder ID code");
            };
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
        /**
         * Copies both issuer hashes and validates their selected digest lengths and serial bounds.
         *
         * <p>This structural CertID does not prove that either digest belongs to an
         * actual issuer. The service resolves those coordinates against the selected
         * issuer generation before determining status.
         *
         * @throws NullPointerException if the digest identity, either hash or serial is null
         * @throws IllegalArgumentException if a hash length or positive 160-bit serial bound is invalid
         * @param hash digest identity governing both issuer hashes
         * @param issuerNameHash exact 20-byte SHA-1 or 32-byte SHA-256 issuer-name digest
         * @param issuerKeyHash exact 20-byte SHA-1 or 32-byte SHA-256 issuer-key digest
         * @param serial positive certificate serial number of at most 160 bits
         */
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
        @Override
        public byte[] issuerNameHash() {
            return issuerNameHash.clone();
        }
        /**
         * Returns the issuer-key digest without exposing internal state.
         *
         * @return defensive copy of the issuer-key digest
         */
        @Override
        public byte[] issuerKeyHash() {
            return issuerKeyHash.clone();
        }
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
        /**
         * Snapshots the response chain, request list and nonce and validates local time ordering.
         *
         * <p>The chain has 1 through 32 credentials, the request list is nonempty,
         * and the native update interval is positive with thisUpdate not after
         * producedAt. This constructor does not authenticate the caller, validate
         * delegation or prove signing-key custody; service execution performs those checks.
         *
         * @throws NullPointerException if a required component, optional, list or list entry is null
         * @throws IllegalArgumentException if chain size, algorithm text, time ordering or request count is invalid
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
        public Command {
            Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(issuerCredentialId, "issuerCredentialId");
            Objects.requireNonNull(responderCredentialId, "responderCredentialId");
            Objects.requireNonNull(signingKeyRef, "signingKeyRef");
            responseChain = List.copyOf(Objects.requireNonNull(responseChain, "responseChain"));
            if (responseChain.isEmpty() || responseChain.size() > 32) {
                throw new IllegalArgumentException("OCSP chain is invalid");
            }
            if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
                throw new IllegalArgumentException("OCSP algorithm is invalid");
            }
            signatureBindingId = Objects.requireNonNull(signatureBindingId, "signatureBindingId");
            Objects.requireNonNull(responderId, "responderId");
            Objects.requireNonNull(producedAt, "producedAt");
            Objects.requireNonNull(thisUpdate, "thisUpdate");
            Objects.requireNonNull(nextUpdate, "nextUpdate");
            if (thisUpdate.isAfter(producedAt) || !nextUpdate.isAfter(thisUpdate)) {
                throw new IllegalArgumentException("OCSP times are invalid");
            }
            nonce = Objects.requireNonNull(nonce, "nonce").map(byte[]::clone);
            requests = List.copyOf(Objects.requireNonNull(requests, "requests"));
            if (requests.isEmpty()) {
                throw new IllegalArgumentException("OCSP request is empty");
            }
        }
        /**
         * Returns the optional nonce without exposing internal state.
         *
         * @return optional defensive copy of the nonce
         */
        @Override
        public Optional<byte[]> nonce() {
            return nonce.map(byte[]::clone);
        }
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
        /**
         * Copies response bytes and validates nonnegative provenance/count coordinates.
         *
         * <p>The three status counts must have a positive representable sum. This
         * carrier does not parse or verify arbitrary supplied DER, validate a path
         * or establish freshness; those guarantees require the response verifier.
         *
         * @throws NullPointerException if response bytes are null
         * @throws IllegalArgumentException if revision, commitment or status counts are invalid
         * @throws ArithmeticException if the total status count exceeds the integer range
         * @param der canonical signed OCSP response DER, defensively copied
         * @param revocationRevision nonnegative authoritative revocation revision
         * @param revocationCommitment lowercase 64-hex-character snapshot commitment
         * @param goodCount number of good single responses
         * @param revokedCount number of revoked single responses
         * @param unknownCount number of unknown single responses
         */
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
        @Override
        public byte[] der() {
            return der.clone();
        }
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

        /**
         * Creates the fixed pending disposition without provider details or an operation identity.
         */
        public SigningPendingException() {
            super("OCSP signing remains pending");
        }
    }
}
