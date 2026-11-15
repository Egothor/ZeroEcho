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
package zeroecho.pki.spi.store;

import java.io.IOException;
import java.security.GeneralSecurityException;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.profile.CertificateProfileDefinition;

/**
 * Pure process-local verification authority for native CRL child adoption.
 * Implementations capture immutable configured public algorithm rules and must
 * be thread-safe. They never sign, resolve private keys, mutate storage, or
 * substitute built-in defaults for contributed public bindings. Streamed work
 * uses O(B) buffer space plus bounded public headers, keys, and signatures,
 * independently of CRL entry count; input content remains caller-owned.
 */
@FunctionalInterface
public interface CrlHybridNativeChildVerifier {
    /**
     * Verifies the actual retained alternative result and the exact native TBS
     * reconstruction against the captured issuer binding and parent command.
     * Both content handles are borrowed; implementations close streams they open
     * but do not close or retire the handles. No caller-provided success flag is authority.
     * @param binding exact retained issuer-generation public signing binding
     * @param issuerCertificate bounded DER issuer certificate carrying both public keys
     * @param parent authoritative parent workflow including its retained alternative result
     * @param alternativeTranscript exact accepted alternative signing content
     * @param nativeChild proposed raw native-child acceptance with inherited execution authority
     * @param nativeTbs proposed final native signing content
     * @param cancellation cooperative cancellation for all streamed reads
     * @throws GeneralSecurityException if signatures, algorithms, or public-key evidence cannot be verified
     * @throws IOException if borrowed content cannot be read or its canonical reconstruction differs
     * @throws IllegalArgumentException if the proposed child contradicts the captured command
     */
    void verify(IssuerCryptographicBinding binding, EncodedObject issuerCertificate,
            SignWorkflowStore.Workflow parent, RepeatableContent alternativeTranscript,
            SignWorkflowStore.AcceptanceCommand nativeChild, RepeatableContent nativeTbs,
            CancellationSignal cancellation) throws GeneralSecurityException, IOException;

    /**
     * Validates hybrid CRL admission using only immutable public authority before
     * any alternative signature is requested. Checks the captured generation,
     * certificate, creation profile, canonical descriptor, alternative role,
     * actual CRL presentation tuple and publicly proven signature-size bounds.
     * Verification authority does not imply private SIGN implementation access;
     * provider configuration and exact frozen runtime plans remain execution guards.
     * @param binding exact immutable issuer-generation public signing binding
     * @param issuerCertificate bounded DER issuer certificate carrying role public keys
     * @param profile exact immutable creation profile identified by the binding
     * @param parent complete proposed public alternative-signing acceptance
     * @throws UnsupportedOperationException if configured public admission validation is unavailable
     * @throws GeneralSecurityException if public algorithm or key authority cannot be established
     * @throws IOException if public certificate, descriptor or profile evidence is malformed
     * @throws IllegalArgumentException if the parent contradicts its captured public authority
     */
    default void validateAdmission(IssuerCryptographicBinding binding, EncodedObject issuerCertificate,
            CertificateProfileDefinition profile, SignWorkflowStore.AcceptanceCommand parent)
            throws GeneralSecurityException, IOException {
        throw new UnsupportedOperationException("Configured hybrid CRL admission validation unavailable");
    }

    /**
     * Derives the lowercase raw 64-character SHA-256 commitment of the actual
     * configured CRL signing presentation tuple. Resolves CRL-role algorithm DER
     * using the immutable creation profile and configured public catalog, including
     * contributed bindings; certificate-role DER is not a substitute. Missing or
     * inconsistent policy fails closed without fabricating a standard binding.
     * This pure operation uses only bounded public certificate, profile and key
     * evidence. It grants no store, provider, signing or private-key capability.
     * Implementations must be thread-safe and do not retain caller-owned input.
     * @param binding exact immutable issuer-generation public signing binding
     * @param issuerCertificate bounded DER issuer certificate carrying the role public keys
     * @param profile exact immutable creation profile identified by the binding
     * @return canonical lowercase SHA-256 presentation-tuple commitment without a prefix
     * @throws UnsupportedOperationException if configured CRL tuple resolution is unavailable
     * @throws GeneralSecurityException if public algorithms, keys or profile bindings cannot be verified
     * @throws IOException if public certificate or policy evidence is malformed
     */
    default String roleTupleCommitment(IssuerCryptographicBinding binding, EncodedObject issuerCertificate,
            CertificateProfileDefinition profile) throws GeneralSecurityException, IOException {
        throw new UnsupportedOperationException("Configured CRL signing tuple resolution unavailable");
    }
}
