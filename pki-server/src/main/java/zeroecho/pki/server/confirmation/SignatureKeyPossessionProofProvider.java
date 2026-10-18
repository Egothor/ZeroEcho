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
package zeroecho.pki.server.confirmation;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.spi.confirmation.KeyPossessionProofChallengeContext;
import zeroecho.pki.spi.confirmation.KeyPossessionProofCredential;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;
import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofProvider;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;
import zeroecho.pki.spi.confirmation.KeyPossessionProofVerification;

/**
 * Stateless thread-safe provider for the standard ZeroEcho signature
 * key-possession proof suite.
 *
 * <p>Each call reconstructs the exact immutable suite profile from the supplied
 * portable binding. The provider retains no credential, key, challenge,
 * response, transcript, or mutable verification state and performs no I/O,
 * persistence, clock access, configuration lookup, or lifecycle mutation.</p>
 */
public final class SignatureKeyPossessionProofProvider implements KeyPossessionProofProvider {
    /** Canonical version-one signature proof-suite identity. */
    public static final String SUITE_ID = "zeroecho.signature-pop.v1";

    /** Creates one stateless provider. */
    public SignatureKeyPossessionProofProvider() {
        // Stateless by design.
    }

    /** {@inheritDoc} */
    @Override
    public String suiteId() {
        return SUITE_ID;
    }

    /** {@inheritDoc} */
    @Override
    public KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits) {
        SignatureProofSuite suite = new SignatureProofSuite(rsaMaximumModulusBits);
        return externalDescriptor(suite, rsaMaximumModulusBits);
    }

    /** {@inheritDoc} */
    @Override
    public void validateCredential(KeyPossessionProofCredential credential) {
        KeyPossessionProofCredential exact = Objects.requireNonNull(credential, "credential");
        ProviderProfile profile = requireProfile(exact.proofSuiteBinding());
        profile.suite().validatePublicKey(exact.publicKey());
    }

    /** {@inheritDoc} */
    @Override
    public KeyPossessionProofPresentation createChallenge(
            KeyPossessionProofChallengeContext context) {
        KeyPossessionProofChallengeContext exact = Objects.requireNonNull(context, "context");
        ProviderProfile profile = requireProfile(exact.proofSuiteBinding());
        byte[] nonce = exact.rawChallenge();
        CanonicalProofTranscript transcript = null;
        ProofChallengeEnvelope challenge = null;
        byte[] presentation = null;
        try {
            transcript = new CanonicalProofTranscript(exact.realm(), exact.serverAudience(),
                    exact.credentialId(), profile.suite().descriptor(), nonce, exact.expiresAt());
            challenge = profile.suite().createChallenge(transcript);
            presentation = challenge.signatureInput();
            return new KeyPossessionProofPresentation(presentation);
        } finally {
            Arrays.fill(nonce, (byte) 0);
            clear(presentation);
            if (challenge != null) {
                challenge.clear();
            }
            if (transcript != null) {
                transcript.clear();
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public KeyPossessionProofVerification verify(KeyPossessionProofChallengeContext context,
            KeyPossessionProofCredential credential, KeyPossessionProofResponse response) {
        KeyPossessionProofChallengeContext exactContext = Objects.requireNonNull(context, "context");
        KeyPossessionProofCredential exactCredential = Objects.requireNonNull(credential, "credential");
        KeyPossessionProofResponse exactResponse = Objects.requireNonNull(response, "response");
        if (!exactContext.credentialId().equals(exactCredential.credentialId())
                || !exactContext.proofSuiteBinding().equals(exactCredential.proofSuiteBinding())) {
            throw new IllegalArgumentException(
                    "Proof context and authoritative credential coordinates differ");
        }
        ProviderProfile profile = requireProfile(exactContext.proofSuiteBinding());
        byte[] nonce = exactContext.rawChallenge();
        byte[] responseBytes = exactResponse.bytes();
        CanonicalProofTranscript transcript = null;
        ProofChallengeEnvelope challenge = null;
        ProofResponseEnvelope responseEnvelope = null;
        try {
            transcript = new CanonicalProofTranscript(exactContext.realm(), exactContext.serverAudience(),
                    exactContext.credentialId(), profile.suite().descriptor(), nonce,
                    exactContext.expiresAt());
            challenge = profile.suite().createChallenge(transcript);
            responseEnvelope = new ProofResponseEnvelope(responseBytes,
                    profile.descriptor().maximumResponseBytes());
            VerificationResult result = profile.suite().verify(
                    challenge, exactCredential.publicKey(), responseEnvelope);
            return result == VerificationResult.VERIFIED
                    ? KeyPossessionProofVerification.VERIFIED
                    : KeyPossessionProofVerification.REJECTED;
        } finally {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(responseBytes, (byte) 0);
            if (responseEnvelope != null) {
                responseEnvelope.clear();
            }
            if (challenge != null) {
                challenge.clear();
            }
            if (transcript != null) {
                transcript.clear();
            }
        }
    }

    private static ProviderProfile requireProfile(ConfirmationProofSuiteBinding binding) {
        ConfirmationProofSuiteBinding exact = Objects.requireNonNull(binding, "proofSuiteBinding");
        SignatureProofSuite suite = new SignatureProofSuite(exact.rsaMaximumModulusBits());
        KeyPossessionProofDescriptor descriptor = externalDescriptor(
                suite, exact.rsaMaximumModulusBits());
        if (!descriptor.proofSuiteBinding().equals(exact)) {
            throw new IllegalArgumentException(
                    "Proof binding does not identify this exact signature suite profile");
        }
        return new ProviderProfile(suite, descriptor);
    }

    private static KeyPossessionProofDescriptor externalDescriptor(SignatureProofSuite suite,
            int rsaMaximumModulusBits) {
        ProofSuiteDescriptor internal = suite.descriptor();
        byte[] commitment = internal.configurationCommitment().bytes();
        try {
            ConfirmationProofSuiteRef reference = new ConfirmationProofSuiteRef(
                    internal.suiteId().value(), HexFormat.of().formatHex(commitment));
            return new KeyPossessionProofDescriptor(
                    new ConfirmationProofSuiteBinding(reference, rsaMaximumModulusBits),
                    internal.challengeBytes(), internal.maximumResponseBytes());
        } finally {
            Arrays.fill(commitment, (byte) 0);
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record ProviderProfile(SignatureProofSuite suite,
            KeyPossessionProofDescriptor descriptor) {
    }
}
