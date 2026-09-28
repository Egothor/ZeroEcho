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

package zeroecho.pki.impl.framework.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.common.sig.SignatureInteropProfile;
import zeroecho.core.alg.common.sig.SignatureInteropProfiles;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.impl.framework.x509.bc.BcX509PublicKeyAdapter;
import zeroecho.pkix.Pkix;
import zeroecho.sdk.ZeroEchoSession;

/** Stateless streaming signature verification shared by CRL preparation and publication. */
public final class StreamingCrlSignatureVerifier {
    private StreamingCrlSignatureVerifier() { }

    /**
     * Verifies exact TBS bytes against the supplied issuer and returns their SHA-256.
     * The caller checks signed layout, algorithm agreement and its configured
     * pure-EdDSA input bound before invoking this cryptographic operation.
     *
     * @param tbs caller-owned exact TBS slice
     * @param algorithm canonical actual signature algorithm
     * @param issuer certificate whose public key must verify the signature
     * @param signature external X.509 signature bytes
     * @param bindings immutable algorithm and public-key binding catalog
     * @param cancellation cooperative streaming cancellation
     * @return lowercase hexadecimal SHA-256 of the verified TBS
     * @throws GeneralSecurityException if signature verification or key conversion fails
     * @throws IOException if streaming or cancellation fails
     */
    public static String verify(RepeatableContent tbs, String algorithm, X509Certificate issuer,
            byte[] signature, X509BindingCatalog bindings, CancellationSignal cancellation)
            throws GeneralSecurityException, IOException {
        SignatureInteropProfile profile = SignatureInteropProfiles.resolve(algorithm)
                .orElseThrow(() -> new GeneralSecurityException("CRL signature algorithm is unsupported"));
        byte[] nativeSpki = new BcX509PublicKeyAdapter(bindings).unwrap(Pkix.subjectPublicKeyInfo(issuer));
        String keyAlgorithm = "ECDSA".equals(profile.keyAlgorithmId()) ? "EC" : profile.keyAlgorithmId();
        PublicKey key = KeyFactory.getInstance(keyAlgorithm).generatePublic(new X509EncodedKeySpec(nativeSpki));
        byte[] expected = profile.externalToInternalSignature(signature);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (SignatureContext verifier = new ZeroEchoSession().createContext(profile.contextAlgorithmId(),
                    KeyUsage.VERIFY, key, profile.contextSpec());
                InputStream source = tbs.openStream();
                InputStream input = new DigestInputStream(source, digest)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(expected);
            try (InputStream verified = verifier.wrap(input)) {
                StreamingDerWriter.copy(verified, OutputStream.nullOutputStream(), cancellation);
            }
            return HexFormat.of().formatHex(digest.digest());
        } finally { Arrays.fill(expected, (byte) 0); }
    }
}
