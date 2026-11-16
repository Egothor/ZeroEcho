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

import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget;

/**
 * Immutable trusted adapter input, not an authentication DTO or authority grant.
 * Validation is bounded by the supplied public frames and native request metadata;
 * no provider, credential or store is accessed. Instances are safe for concurrent reads.
 *
 * <p>The original request and protected native wire are retained evidence, not a
 * sanitized public projection. Native request content may include confidential
 * attributes and must remain under its existing request-retention controls.
 * Redacted toString output does not make the retained payload safe to disclose.</p>
 *
 * @param admission genuine native authenticated admission
 * @param expectedEndpointCommitment frozen endpoint commitment
 * @param canonicalOrigin configured listener origin, never a caller header
 * @param authenticationContext exact native F6 context
 * @param target typed enrollment target for F7
 * @param cmpManifest frozen CMP manifest, mandatory only for CMP
 * @param nativeWire exact original protected SCEP/CMP wire; defensive and absent otherwise
 */
public record EnrollmentSdkAdmission(EnrollmentCoordinator.Admission admission, String expectedEndpointCommitment,
        String canonicalOrigin, HybridSdkFrame authenticationContext, SdkEnrollmentTarget target,
        Optional<CmpTransaction.Frozen> cmpManifest, Optional<byte[]> nativeWire) {
    /**
     * Creates a non-protected-wire admission; SCEP/CMP require the complete constructor.
     *
     * @param admission native admission
     * @param expectedEndpointCommitment exact endpoint commitment
     * @param canonicalOrigin configured origin
     * @param authenticationContext genuine F6
     * @param target frozen enrollment target
     * @param cmpManifest optional CMP manifest
     * @throws NullPointerException if a required object or optional container is null
     * @throws IllegalArgumentException if delegated correspondence or operation constraints fail
     */
    public EnrollmentSdkAdmission(EnrollmentCoordinator.Admission admission, String expectedEndpointCommitment,
            String canonicalOrigin, HybridSdkFrame authenticationContext, SdkEnrollmentTarget target,
            Optional<CmpTransaction.Frozen> cmpManifest) {
        this(admission, expectedEndpointCommitment, canonicalOrigin, authenticationContext, target, cmpManifest, Optional.empty());
    }
    /**
     * Checks native/F6/F7/protected-wire correspondence without authenticating or reserving capacity.
     *
     * @param admission genuine native authenticated admission
     * @param expectedEndpointCommitment frozen endpoint commitment
     * @param canonicalOrigin configured listener origin, never a caller header
     * @param authenticationContext exact native F6 context
     * @param target typed enrollment target for F7
     * @param cmpManifest frozen CMP manifest, mandatory only for CMP
     * @param nativeWire exact original protected SCEP/CMP wire; defensive and absent otherwise
     * @throws NullPointerException if a required object or optional container is null
     * @throws IllegalArgumentException if endpoint/origin syntax, protected-wire presence/size, frame kind,
     *     protocol/request/transaction or CMP manifest coordinates disagree
     */
    public EnrollmentSdkAdmission {
        Objects.requireNonNull(admission, "admission"); EnrollmentTransaction.digest(expectedEndpointCommitment);
        HybridSdkFrame.requireOrigin(canonicalOrigin); Objects.requireNonNull(authenticationContext, "authenticationContext");
        Objects.requireNonNull(target, "target"); Objects.requireNonNull(cmpManifest, "cmpManifest");
        nativeWire = Objects.requireNonNull(nativeWire, "nativeWire").map(bytes -> bytes.clone());
        boolean protectedWire = admission.protocol() == EnrollmentTransaction.Protocol.SCEP || admission.protocol() == EnrollmentTransaction.Protocol.CMP;
        if (protectedWire != nativeWire.isPresent() || nativeWire.filter(bytes -> bytes.length == 0 || bytes.length > 524_288).isPresent()) throw EnrollmentTransaction.invalid();
        if (authenticationContext.kind() != 6 || admission.operation() == EnrollmentTransaction.Operation.SERVER_KEYGEN
                || !admission.protocol().name().equals(target.protocol())
                || admission.protocol() != EnrollmentTransaction.Protocol.ACME && !admission.endpointId().equals(target.endpointId())
                || !expectedEndpointCommitment.equals(target.endpointCommitment())
                || !admission.operation().name().equals(target.operation()) || admission.payload().kind() != target.requestKind()
                || !admission.transactionId().equals(target.transactionIdSha256())
                || (admission.protocol() == EnrollmentTransaction.Protocol.CMP) != cmpManifest.isPresent()) throw EnrollmentTransaction.invalid();
        if (cmpManifest.isPresent()) {
            var manifest = cmpManifest.orElseThrow();
            if (!manifest.enrollment() || !manifest.requester().equals(admission.requester())
                    || !manifest.source().label().equals(admission.endpointId())
                    || !manifest.source().commitment().equals(expectedEndpointCommitment)
                    || !manifest.transactionSha256().equals(admission.transactionId())) throw EnrollmentTransaction.invalid();
        }
    }
    /**
     * Returns independent copy of the protected native wire, when required.
     *
     * @return independent copy of the protected native wire, when required
     */
    @Override public Optional<byte[]> nativeWire() { return nativeWire.map(bytes -> bytes.clone()); }
    /**
     * Returns redacted trusted input description.
     *
     * @return redacted trusted input description
     */
    @Override public String toString() { return "EnrollmentSdkAdmission[redacted]"; }

    /**
     * Immutable public challenge projection; F2 is derived from the retained F1 fields.
     *
     * @param intentId canonical retained intent identity
     * @param primaryFrame exact F1 frame
     * @param targetFrame exact F7 frame
     */
    public record Challenge(String intentId, HybridSdkFrame primaryFrame, HybridSdkFrame targetFrame) {
        /**
         * Checks intent-ID syntax and F1/F7 roles without proving that the challenge is retained.
         *
         * @param intentId canonical retained intent identity
         * @param primaryFrame exact F1 frame
         * @param targetFrame exact F7 frame
         * @throws NullPointerException if either frame is null
         * @throws IllegalArgumentException if the intent identity is not 64 lowercase hexadecimal characters or
         *     frame kinds differ
         */
        public Challenge {
            if (intentId == null || !intentId.matches("[0-9a-f]{64}")) throw EnrollmentTransaction.invalid();
            Objects.requireNonNull(primaryFrame, "primaryFrame"); Objects.requireNonNull(targetFrame, "targetFrame");
            if (primaryFrame.kind() != 1 || targetFrame.kind() != 7) throw EnrollmentTransaction.invalid();
        }
        /**
         * Returns redacted challenge description.
         *
         * @return redacted challenge description
         */
        @Override public String toString() { return "EnrollmentSdkAdmission.Challenge[redacted]"; }
    }
}
