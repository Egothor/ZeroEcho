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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Objects;

/** Signature-based proof suite for the sealed standard X.509 signing-key domain. */
final class SignatureProofSuite implements KeyPossessionProofSuite {

    /* default */ static final ProofSuiteId SUITE_ID = new ProofSuiteId("zeroecho.signature-pop.v1");
    /* default */ static final int CHALLENGE_BYTES = 32;

    private static final int MINIMUM_RSA_BITS = 2_048;
    private static final int DEFAULT_MAXIMUM_RSA_BITS = 8_192;
    private static final int MAXIMUM_CONFIGURED_RSA_BITS = 16_384;
    private static final BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65_537L);
    private static final String ED25519 = "Ed25519";
    private static final String ED448 = "Ed448";
    private static final PSSParameterSpec RSA_PSS_SHA256 = new PSSParameterSpec("SHA-256", "MGF1",
            MGF1ParameterSpec.SHA256, 32, 1);
    private final int maximumRsaBits;
    private final ProofSuiteDescriptor descriptor;

    /* default */ SignatureProofSuite() {
        this(DEFAULT_MAXIMUM_RSA_BITS);
    }

    /* default */ SignatureProofSuite(int maximumRsaBits) {
        if (maximumRsaBits < MINIMUM_RSA_BITS || maximumRsaBits > MAXIMUM_CONFIGURED_RSA_BITS) {
            throw new IllegalArgumentException("Maximum RSA modulus length must be between 2048 and 16384 bits");
        }
        this.maximumRsaBits = maximumRsaBits;
        int maximumResponseBytes = (maximumRsaBits + Byte.SIZE - 1) / Byte.SIZE;
        String profile = String.join("|",
                "zeroecho.signature-pop.v1",
                "transcript=zeroecho.credential-key-possession.v1",
                "challenge-bytes=32",
                "response-max-bytes=" + maximumResponseBytes,
                "rsa=RSASSA-PSS,SHA-256,MGF1-SHA-256,salt-32,trailer-1,exponent=65537,bits-2048.."
                        + maximumRsaBits,
                "ec-p256=SHA256withECDSA,asn1-der,max-80",
                "ec-p384=SHA384withECDSA,asn1-der,max-112",
                "ec-p521=SHA512withECDSA,asn1-der,max-144",
                "ed25519=Ed25519,bytes-64",
                "ed448=Ed448,bytes-114");
        this.descriptor = new ProofSuiteDescriptor(SUITE_ID,
                new ProofSuiteCommitment(sha256(profile.getBytes(StandardCharsets.US_ASCII))), CHALLENGE_BYTES,
                maximumResponseBytes);
    }

    @Override
    public ProofSuiteDescriptor descriptor() {
        return descriptor;
    }

    @Override
    public void validatePublicKey(PublicKey publicKey) {
        requireProfile(Objects.requireNonNull(publicKey, "publicKey"));
    }

    @Override
    public ProofChallengeEnvelope createChallenge(CanonicalProofTranscript transcript) {
        Objects.requireNonNull(transcript, "transcript");
        requireExactDescriptor(transcript.descriptor());
        byte[] signatureInput = transcript.encoded();
        try {
            return new ProofChallengeEnvelope(descriptor, signatureInput, transcript.expiresAt());
        } finally {
            Arrays.fill(signatureInput, (byte) 0);
        }
    }

    @Override
    public VerificationResult verify(ProofChallengeEnvelope challenge, PublicKey publicKey,
            ProofResponseEnvelope response) {
        ProofChallengeEnvelope exactChallenge = Objects.requireNonNull(challenge, "challenge");
        PublicKey exactKey = Objects.requireNonNull(publicKey, "publicKey");
        ProofResponseEnvelope exactResponse = Objects.requireNonNull(response, "response");
        if (!descriptor.equals(exactChallenge.descriptor())) {
            throw new IllegalArgumentException("Proof challenge does not identify this exact suite profile");
        }
        byte[] signatureInput = exactChallenge.signatureInput();
        byte[] signature = exactResponse.response();
        CanonicalProofTranscript transcript = null;
        try {
            transcript = CanonicalProofTranscript.decode(signatureInput, descriptor);
            if (!transcript.expiresAt().equals(exactChallenge.expiresAt())) {
                throw new IllegalArgumentException("Proof challenge expiry differs from its canonical transcript");
            }
            SignatureProfile profile = requireProfile(exactKey);
            if (!hasValidSignatureLength(profile, signature.length)) {
                return VerificationResult.REJECTED;
            }
            return verifySignature(profile, exactKey, signatureInput, signature);
        } catch (SignatureException exception) {
            return VerificationResult.REJECTED;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Signature proof verification is unavailable", exception);
        } finally {
            if (transcript != null) {
                transcript.clear();
            }
            Arrays.fill(signatureInput, (byte) 0);
            Arrays.fill(signature, (byte) 0);
        }
    }

    private static boolean hasValidSignatureLength(SignatureProfile profile, int signatureBytes) {
        if (signatureBytes > profile.maximumSignatureBytes()) {
            return false;
        }
        return switch (profile.jcaName()) {
            case ED25519 -> signatureBytes == 64;
            case ED448 -> signatureBytes == 114;
            case "RSASSA-PSS" -> signatureBytes == profile.maximumSignatureBytes();
            default -> true;
        };
    }

    private static VerificationResult verifySignature(SignatureProfile profile, PublicKey publicKey,
            byte[] signatureInput, byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance(profile.jcaName());
        if (profile.parameters() != null) {
            verifier.setParameter(profile.parameters());
        }
        verifier.initVerify(publicKey);
        verifier.update(signatureInput);
        return verifier.verify(signature) ? VerificationResult.VERIFIED : VerificationResult.REJECTED;
    }

    private void requireExactDescriptor(ProofSuiteDescriptor candidate) {
        if (!descriptor.equals(candidate)) {
            throw new IllegalArgumentException("Proof transcript does not identify this exact suite profile");
        }
    }

    private SignatureProfile requireProfile(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsa) {
            int bits = rsa.getModulus().bitLength();
            if (bits < MINIMUM_RSA_BITS || bits > maximumRsaBits
                    || !RSA_PUBLIC_EXPONENT.equals(rsa.getPublicExponent())) {
                throw unsupportedKey();
            }
            return new SignatureProfile("RSASSA-PSS", RSA_PSS_SHA256, (bits + 7) / 8);
        }
        if (publicKey instanceof ECKey ec) {
            ECParameterSpec parameters = ec.getParams();
            if (matchesNamedCurve(parameters, "secp256r1")) {
                return new SignatureProfile("SHA256withECDSA", null, 80);
            }
            if (matchesNamedCurve(parameters, "secp384r1")) {
                return new SignatureProfile("SHA384withECDSA", null, 112);
            }
            if (matchesNamedCurve(parameters, "secp521r1")) {
                return new SignatureProfile("SHA512withECDSA", null, 144);
            }
            throw unsupportedKey();
        }
        if (publicKey instanceof EdECPublicKey ed) {
            if (ED25519.equals(ed.getParams().getName())) {
                return new SignatureProfile(ED25519, null, 64);
            }
            if (ED448.equals(ed.getParams().getName())) {
                return new SignatureProfile(ED448, null, 114);
            }
        }
        throw unsupportedKey();
    }

    private static boolean matchesNamedCurve(ECParameterSpec candidate, String name) {
        if (candidate == null) {
            return false;
        }
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(name));
            ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
            return expected.getCurve().equals(candidate.getCurve())
                    && expected.getGenerator().equals(candidate.getGenerator())
                    && expected.getOrder().equals(candidate.getOrder())
                    && expected.getCofactor() == candidate.getCofactor();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Required standard EC parameters are unavailable", exception);
        }
    }

    private static IllegalArgumentException unsupportedKey() {
        return new IllegalArgumentException("Public key is outside the signature proof-suite v1 profile");
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Required SHA-256 implementation is unavailable", exception);
        }
    }

    /** Exact JCA verification parameters and response bound for one supported key. */
    private record SignatureProfile(String jcaName, PSSParameterSpec parameters, int maximumSignatureBytes) {
    }

}
