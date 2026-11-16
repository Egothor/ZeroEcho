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
package zeroecho.pki.server.enrollment;

import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.server.RealmId;

/**
 * Closed version-one enrollment SDK challenge or consumed tombstone. This value
 * does not reserve capacity or authorize admission. Arrays are copied at both
 * boundaries; instances are immutable and safe for concurrent reads. Validation
 * takes linear time in the bounded original request, wire and proof bytes.
 *
 * <p>The original typed payload and native wire retain exact request evidence,
 * potentially including confidential native attributes. Hash commitments and
 * redacted diagnostics do not sanitize these bytes. Construction validates their
 * relationships but neither verifies client signatures nor consults a current
 * clock. Consumed tombstones support exact accepted replay through the coordinator;
 * they do not reopen an expired challenge or grant fresh enrollment authority.</p>
 *
 * @param id canonical server intent identity
 * @param version payload version, exactly one
 * @param realmId exact owning realm
 * @param admission retained trusted native context
 * @param originalPayload exact typed original request, shared by the admission codec
 * @param nativeWire bounded original SCEP/CMP protected wire, absent otherwise
 * @param primaryFrame retained F1 frame
 * @param authenticationContext retained F6 frame
 * @param targetFrame retained F7 frame
 * @param issuedAt trusted creation time
 * @param expiresAt creation plus the fixed 300-second lifetime
 * @param state closed consumption state
 * @param revision nonnegative mutation revision
 * @param sdkRequestId exact accepted stable request identity
 * @param primaryProof accepted primary client signature
 * @param alternativeProof accepted alternative client signature
 * @param proofCommitment accepted F3 SHA-512 commitment
 * @param acceptedAt trusted proof acceptance time
 * @param enrollmentId linked durable enrollment receipt identity
 */
public record EnrollmentSdkIntent(String id, int version, RealmId realmId, EnrollmentSdkAdmission admission,
        X509EnrollmentPayload originalPayload, Optional<byte[]> nativeWire, HybridSdkFrame primaryFrame,
        HybridSdkFrame authenticationContext, HybridSdkFrame targetFrame, Instant issuedAt, Instant expiresAt,
        State state, long revision, Optional<String> sdkRequestId, Optional<byte[]> primaryProof,
        Optional<byte[]> alternativeProof, Optional<String> proofCommitment, Optional<Instant> acceptedAt,
        Optional<String> enrollmentId) {
    /**
     * Closed durable consumption state; unknown states are never treated as OPEN.
     */
    public enum State {
        /**
         * Challenge has not admitted any enrollment.
         */
        OPEN,
        /**
         * Exact proofs and one enrollment receipt are retained atomically.
         */
        CONSUMED
    }
    /**
     * Copies optional wire/proof arrays and checks frozen context and consumption-state correspondence.
     *
     * @param id canonical server intent identity
     * @param version payload version, exactly one
     * @param realmId exact owning realm
     * @param admission retained trusted native context
     * @param originalPayload exact typed original request, shared by the admission codec
     * @param nativeWire bounded original SCEP/CMP protected wire, absent otherwise
     * @param primaryFrame retained F1 frame
     * @param authenticationContext retained F6 frame
     * @param targetFrame retained F7 frame
     * @param issuedAt trusted creation time
     * @param expiresAt creation plus the fixed 300-second lifetime
     * @param state closed consumption state
     * @param revision nonnegative mutation revision
     * @param sdkRequestId exact accepted stable request identity
     * @param primaryProof accepted primary client signature
     * @param alternativeProof accepted alternative client signature
     * @param proofCommitment accepted F3 SHA-512 commitment
     * @param acceptedAt trusted proof acceptance time
     * @param enrollmentId linked durable enrollment receipt identity
     * @throws NullPointerException if a required object or optional container is null
     * @throws IllegalArgumentException if identity/version/revision, exact frame/request/time/wire
     *     correspondence or consumed proof/receipt shape is invalid
     */
    public EnrollmentSdkIntent {
        if (id == null || !id.matches("[0-9a-f]{64}") || version != 1 || revision < 0) throw EnrollmentTransaction.invalid();
        Objects.requireNonNull(realmId, "realmId"); Objects.requireNonNull(admission, "admission");
        Objects.requireNonNull(originalPayload, "originalPayload");
        nativeWire = copy(nativeWire); primaryProof = copy(primaryProof); alternativeProof = copy(alternativeProof);
        Objects.requireNonNull(primaryFrame, "primaryFrame"); Objects.requireNonNull(authenticationContext, "authenticationContext");
        Objects.requireNonNull(targetFrame, "targetFrame"); Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt"); Objects.requireNonNull(state, "state");
        Objects.requireNonNull(sdkRequestId, "sdkRequestId"); Objects.requireNonNull(proofCommitment, "proofCommitment");
        Objects.requireNonNull(acceptedAt, "acceptedAt"); Objects.requireNonNull(enrollmentId, "enrollmentId");
        if (!realmId.equals(admission.admission().requester().aliases().realmId())
                || originalPayload.kind() != admission.admission().payload().kind()
                || !Arrays.equals(originalPayload.der(), admission.admission().payload().der())
                || primaryFrame.kind() != 1 || authenticationContext.kind() != 6 || targetFrame.kind() != 7
                || !Arrays.equals(authenticationContext.encode(), admission.authenticationContext().encode())
                || !HexFormat.of().formatHex(primaryFrame.field(3)).equals(id)
                || !Arrays.equals(primaryFrame.field(11), HybridSdkFrame.hash(originalPayload.der()))
                || !Arrays.equals(primaryFrame.field(12), HybridSdkFrame.hash(authenticationContext.encode()))
                || !Arrays.equals(primaryFrame.field(17), HybridSdkFrame.hash(targetFrame.encode()))
                || java.nio.ByteBuffer.wrap(primaryFrame.field(7)).getLong() != issuedAt.getEpochSecond()
                || java.nio.ByteBuffer.wrap(primaryFrame.field(8)).getLong() != expiresAt.getEpochSecond()
                || !issuedAt.plusSeconds(300).equals(expiresAt)) throw EnrollmentTransaction.invalid();
        boolean protectedWire = admission.admission().protocol() == EnrollmentTransaction.Protocol.SCEP
                || admission.admission().protocol() == EnrollmentTransaction.Protocol.CMP;
        if (protectedWire != nativeWire.isPresent() || admission.nativeWire().isPresent() != nativeWire.isPresent()
                || nativeWire.isPresent() && !Arrays.equals(nativeWire.orElseThrow(), admission.nativeWire().orElseThrow())
                || nativeWire.filter(bytes -> bytes.length == 0 || bytes.length > 524_288).isPresent()) throw EnrollmentTransaction.invalid();
        boolean consumed = state == State.CONSUMED;
        if (sdkRequestId.isPresent() != consumed || primaryProof.isPresent() != consumed
                || alternativeProof.isPresent() != consumed || proofCommitment.isPresent() != consumed
                || acceptedAt.isPresent() != consumed || enrollmentId.isPresent() != consumed) throw EnrollmentTransaction.invalid();
        sdkRequestId.ifPresent(EnrollmentTransaction::id); enrollmentId.ifPresent(EnrollmentTransaction::id);
        if (primaryProof.filter(bytes -> bytes.length == 0 || bytes.length > 104).isPresent()
                || alternativeProof.filter(bytes -> bytes.length != 4627).isPresent()
                || proofCommitment.filter(value -> !value.matches("sha512:[0-9a-f]{128}")).isPresent()
                || acceptedAt.filter(value -> value.isBefore(issuedAt) || !value.isBefore(expiresAt)).isPresent()) throw EnrollmentTransaction.invalid();
    }
    private static Optional<byte[]> copy(Optional<byte[]> value) {
        return Objects.requireNonNull(value, "bytes").map(bytes -> Objects.requireNonNull(bytes, "bytes").clone());
    }
    /**
     * Returns fresh copy of the retained protected wire, if applicable.
     *
     * @return fresh copy of the retained protected wire, if applicable
     */
    @Override public Optional<byte[]> nativeWire() { return copy(nativeWire); }
    /**
     * Returns fresh copy of the accepted primary proof, if consumed.
     *
     * @return fresh copy of the accepted primary proof, if consumed
     */
    @Override public Optional<byte[]> primaryProof() { return copy(primaryProof); }
    /**
     * Returns fresh copy of the accepted alternative proof, if consumed.
     *
     * @return fresh copy of the accepted alternative proof, if consumed
     */
    @Override public Optional<byte[]> alternativeProof() { return copy(alternativeProof); }
    /**
     * Returns redacted state description without wire, proof or requester contents.
     *
     * @return redacted state description without wire, proof or requester contents
     */
    @Override public String toString() { return "EnrollmentSdkIntent[state=" + state + ", revision=" + revision + "]"; }
}
