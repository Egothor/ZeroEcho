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
package zeroecho.pki.impl.framework.x509.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Set;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.sign.ContentVerifier;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;

/**
 * Stateless verification executor at the X.509 adapter edge.
 *
 * <p>
 * This executor never selects identity, OID, parameters, policy, or provider
 * precedence. It accepts only an execution plan minted by the same authority
 * snapshot and performs verification after immediate provenance validation.
 * Cryptographic verification is delegated to the ZeroEcho PKIX library and to the
 * globally registered JCA providers; this class holds no concrete cryptographic
 * toolkit type.
 * </p>
 */
public final class BcX509VerificationExecutor implements AlgorithmExecutionCapabilityProvider {

    /** Stable semantic implementation identifier. */
    public static final String IMPLEMENTATION_ID = "bc.x509-verification";

    private static final int BUFFER_BYTES = 16 * 1024;
    private static final Set<AlgorithmIdentity> ML_DSA_SIGNATURES = Set.of(
            BootstrapAlgorithmIdentities.ML_DSA_44_SIGNATURE,
            BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE,
            BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE);
    private static final Set<AlgorithmIdentity> SLH_DSA_SIGNATURES = Set.of(
            BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128S_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128F_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192S_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192F_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256S_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256F_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128S_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128F_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192S_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192F_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256S_SIGNATURE,
            BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256F_SIGNATURE);
    private static final Set<AlgorithmIdentity> SIGNATURES;
    static {
        Set<AlgorithmIdentity> all = new java.util.HashSet<>(Set.of(
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512, BootstrapAlgorithmIdentities.RSA_PSS_SHA256,
                BootstrapAlgorithmIdentities.ECDSA_SHA256, BootstrapAlgorithmIdentities.ECDSA_SHA384,
                BootstrapAlgorithmIdentities.ECDSA_SHA512, BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                BootstrapAlgorithmIdentities.ED448_SIGNATURE,
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE));
        all.addAll(ML_DSA_SIGNATURES);
        all.addAll(SLH_DSA_SIGNATURES);
        SIGNATURES = Set.copyOf(all);
    }

    /** Creates a stateless X.509 verification executor. */
    public BcX509VerificationExecutor() {
        // Stateless.
    }

    @Override
    public List<AlgorithmExecutionCapability> capabilities() {
        return List.of(new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return IMPLEMENTATION_ID;
            }

            @Override
            public String domainFingerprint() {
                return "bc-x509-verification-v2:bootstrap-classic+pqc";
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.VERIFY && SIGNATURES.contains(identity)
                        && identity.equals(suite.signature());
            }
        });
    }

    /**
     * Verifies one signature using an already-authorized exact plan.
     *
     * @param authority owning authority snapshot
     * @param plan exact verification plan
     * @param publicKeyInfoDer exact subject public key info DER
     * @param algorithmIdentifier exact signature algorithm identifier
     * @param signedContent exact repeatable signed content
     * @param signature signature bytes
     * @return whether the signature is valid
     * @throws IllegalArgumentException if the supplied signature or public-key
     *                                  algorithm does not exactly match the
     *                                  authorized plan
     * @throws GeneralSecurityException if key or provider processing fails
     * @throws IOException if the signed bytes cannot be supplied
     */
    public boolean verify(X509AuthoritySnapshot authority, X509ExecutionPlan<BcX509VerificationExecutor> plan,
            byte[] publicKeyInfoDer, zeroecho.pkix.AlgorithmIdentifier algorithmIdentifier,
            RepeatableContent signedContent, byte[] signature) throws GeneralSecurityException, IOException {
        authority.authorize(plan, this, AlgorithmExecutionCapability.Direction.VERIFY);
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentity signatureIdentity = adapter.decode(algorithmIdentifier,
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
        if (!plan.selection().requested().equals(signatureIdentity)
                || !plan.selection().binding().equals(BcX509AlgorithmAdapter.fromLib(algorithmIdentifier))) {
            throw new IllegalArgumentException("Signature AlgorithmIdentifier does not match execution plan");
        }
        AlgorithmIdentity publicKeyIdentity = adapter.decode(Pkix.subjectPublicKeyAlgorithm(publicKeyInfoDer),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        if (!plan.selection().suite().publicKey().equals(publicKeyIdentity)) {
            throw new IllegalArgumentException("SubjectPublicKeyInfo does not match execution plan");
        }
        byte[] nativePublicKey = new BcX509PublicKeyAdapter(authority.bindings()).unwrap(publicKeyInfoDer);
        if (BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE.equals(signatureIdentity)) {
            return verifyNamed(nativePublicKey, "SLH-DSA", signedContent, signature);
        }
        if (ML_DSA_SIGNATURES.contains(signatureIdentity)) {
            return verifyNamed(nativePublicKey, "MLDSA", signedContent, signature);
        }
        if (SLH_DSA_SIGNATURES.contains(signatureIdentity)) {
            return verifyNamed(nativePublicKey, "SLH-DSA", signedContent, signature);
        }
        if (!authority.bindings().resolve(signatureIdentity, X509AlgorithmRole.SIGNATURE_ALGORITHM)
                .equals(BcX509AlgorithmAdapter.fromLib(algorithmIdentifier))) {
            return verifyCustomClassic(signatureIdentity, nativePublicKey, signedContent, signature);
        }
        ContentVerifier verifier = Pkix.verifier(nativePublicKey, algorithmIdentifier);
        try (InputStream input = signedContent.openStream(); OutputStream output = verifier.contentStream()) {
            copy(input, output);
        }
        return verifier.verify(signature);
    }

    private static boolean verifyCustomClassic(AlgorithmIdentity identity, byte[] publicKeyInfoDer,
            RepeatableContent signedContent, byte[] signatureBytes) throws GeneralSecurityException, IOException {
        String algorithm;
        if (BootstrapAlgorithmIdentities.ED25519_SIGNATURE.equals(identity)) {
            algorithm = "Ed25519";
        } else if (BootstrapAlgorithmIdentities.ED448_SIGNATURE.equals(identity)) {
            algorithm = "Ed448";
        } else {
            throw new GeneralSecurityException("Custom classic binding lacks an exact JCA verification contract");
        }
        return verifyNamed(publicKeyInfoDer, algorithm, signedContent, signatureBytes);
    }

    private static boolean verifyNamed(byte[] publicKeyInfoDer, String jcaAlgorithm, RepeatableContent signedContent,
            byte[] signatureBytes) throws GeneralSecurityException, IOException {
        PublicKey publicKey = KeyFactory.getInstance(jcaAlgorithm)
                .generatePublic(new X509EncodedKeySpec(publicKeyInfoDer));
        Signature verifier = Signature.getInstance(jcaAlgorithm);
        verifier.initVerify(publicKey);
        try (InputStream input = signedContent.openStream()) {
            byte[] buffer = new byte[BUFFER_BYTES];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                CancellationSignal.NONE.throwIfCancelled();
                if (read != 0) {
                    verifier.update(buffer, 0, read);
                }
            }
        }
        return verifier.verify(signatureBytes);
    }

    private static void copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[BUFFER_BYTES];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            CancellationSignal.NONE.throwIfCancelled();
            if (read != 0) {
                output.write(buffer, 0, read);
            }
        }
    }
}
