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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;

/**
 * Stateless Bouncy Castle verification executor at the X.509 adapter edge.
 *
 * <p>
 * This executor never selects identity, OID, parameters, policy, or provider
 * precedence. It accepts only an execution plan minted by the same authority
 * snapshot and performs verification after immediate provenance validation.
 * </p>
 */
public final class BcX509VerificationExecutor implements AlgorithmExecutionCapabilityProvider {

    /** Stable semantic implementation identifier. */
    public static final String IMPLEMENTATION_ID = "bc.x509-verification";

    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
    private static final Set<AlgorithmIdentity> SIGNATURES = Set.of(
            BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384,
            BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512, BootstrapAlgorithmIdentities.RSA_PSS_SHA256,
            BootstrapAlgorithmIdentities.ECDSA_SHA256, BootstrapAlgorithmIdentities.ECDSA_SHA384,
            BootstrapAlgorithmIdentities.ECDSA_SHA512, BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
            BootstrapAlgorithmIdentities.ED448_SIGNATURE, BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE);
    private static final BouncyCastlePQCProvider BC_PQC_PROVIDER = new BouncyCastlePQCProvider();

    @Override
    public List<AlgorithmExecutionCapability> capabilities() {
        return List.of(new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return IMPLEMENTATION_ID;
            }

            @Override
            public String domainFingerprint() {
                return "bc-x509-verification-v1:bootstrap-classic";
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
     * @param publicKeyInfo exact subject public key
     * @param algorithmIdentifier exact signature AlgorithmIdentifier
     * @param signedContent exact repeatable signed content
     * @param signature signature bytes
     * @return whether the signature is valid
     * @throws IllegalArgumentException if the supplied signature or public-key
     *                                  algorithm does not exactly match the
     *                                  authorized plan
     * @throws GeneralSecurityException if key or provider processing fails
     * @throws IOException if the signed bytes cannot be supplied
     * @throws OperatorCreationException if verifier construction fails
     */
    public boolean verify(X509AuthoritySnapshot authority, X509ExecutionPlan<BcX509VerificationExecutor> plan,
            SubjectPublicKeyInfo publicKeyInfo, AlgorithmIdentifier algorithmIdentifier, RepeatableContent signedContent,
            byte[] signature) throws GeneralSecurityException, IOException, OperatorCreationException {
        authority.authorize(plan, this, AlgorithmExecutionCapability.Direction.VERIFY);
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentity signatureIdentity = adapter.decode(algorithmIdentifier,
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
        if (!plan.selection().requested().equals(signatureIdentity)
                || !plan.selection().binding().equals(BcX509AlgorithmAdapter.fromBc(algorithmIdentifier))) {
            throw new IllegalArgumentException("Signature AlgorithmIdentifier does not match execution plan");
        }
        AlgorithmIdentity publicKeyIdentity = adapter.decode(publicKeyInfo.getAlgorithm(),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        if (!plan.selection().suite().publicKey().equals(publicKeyIdentity)) {
            throw new IllegalArgumentException("SubjectPublicKeyInfo does not match execution plan");
        }
        SubjectPublicKeyInfo nativePublicKey = new BcX509PublicKeyAdapter(authority.bindings()).unwrap(publicKeyInfo);
        if (BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE.equals(signatureIdentity)) {
            return verifySphincs(nativePublicKey, signedContent, signature);
        }
        if (!authority.bindings().resolve(signatureIdentity, X509AlgorithmRole.SIGNATURE_ALGORITHM)
                .equals(BcX509AlgorithmAdapter.fromBc(algorithmIdentifier))) {
            return verifyCustomClassic(signatureIdentity, nativePublicKey, signedContent, signature);
        }
        ContentVerifier verifier = new JcaContentVerifierProviderBuilder().setProvider(BC_PROVIDER)
                .build(nativePublicKey).get(algorithmIdentifier);
        try (InputStream input = signedContent.openStream(); OutputStream output = verifier.getOutputStream()) {
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                CancellationSignal.NONE.throwIfCancelled();
                if (read != 0) {
                    output.write(buffer, 0, read);
                }
            }
        }
        return verifier.verify(signature);
    }

    private static boolean verifySphincs(SubjectPublicKeyInfo publicKeyInfo, RepeatableContent signedContent,
            byte[] signatureBytes) throws GeneralSecurityException, IOException {
        PublicKey publicKey = KeyFactory.getInstance("SPHINCS+", BC_PQC_PROVIDER)
                .generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        Signature verifier = Signature.getInstance("SPHINCS+", BC_PQC_PROVIDER);
        verifier.initVerify(publicKey);
        try (InputStream input = signedContent.openStream()) {
            byte[] buffer = new byte[16 * 1024];
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

    private static boolean verifyCustomClassic(AlgorithmIdentity identity, SubjectPublicKeyInfo publicKeyInfo,
            RepeatableContent signedContent, byte[] signatureBytes) throws GeneralSecurityException, IOException {
        String algorithm;
        if (BootstrapAlgorithmIdentities.ED25519_SIGNATURE.equals(identity)) {
            algorithm = "Ed25519";
        } else if (BootstrapAlgorithmIdentities.ED448_SIGNATURE.equals(identity)) {
            algorithm = "Ed448";
        } else {
            throw new GeneralSecurityException("Custom classic binding lacks an exact JCA verification contract");
        }
        PublicKey publicKey = KeyFactory.getInstance(algorithm, BC_PROVIDER)
                .generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        Signature verifier = Signature.getInstance(algorithm, BC_PROVIDER);
        verifier.initVerify(publicKey);
        try (InputStream input = signedContent.openStream()) {
            byte[] buffer = new byte[16 * 1024];
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
}
