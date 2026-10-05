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
package zeroecho.sdk.util;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;

/**
 * BIKE-256 key pair utilities for modules that depend on {@code zeroecho.lib}.
 *
 * <p>BouncyCastle is an internal implementation detail of {@code zeroecho.lib}.
 * This class provides BIKE key-pair operations through standard JCA types
 * ({@link KeyPair}, {@link PublicKey}, {@link PrivateKey}) so that callers
 * do not need to depend on BouncyCastle directly.</p>
 */
public final class BikeKeySupport {
    private static final String PROVIDER = "BCPQC";
    private static final String ALGORITHM = "BIKE";

    private BikeKeySupport() {}

    /**
     * Generates a fresh BIKE-256 key pair using the BCPQC provider.
     *
     * @return a new key pair whose private key is owned by the caller
     * @throws GeneralSecurityException if the provider or key generator is unavailable
     */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        BouncyCastleActivator.init();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        kpg.initialize(BIKEParameterSpec.bike256, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /**
     * Decodes a BIKE public key from a SubjectPublicKeyInfo structure.
     * The parameter set is taken from the encoding; this method does not
     * restrict imported keys to BIKE-256.
     *
     * @param x509Der non-null DER-encoded SubjectPublicKeyInfo
     * @return the decoded public key
     * @throws GeneralSecurityException if the provider is unavailable or the encoding is invalid
     */
    public static PublicKey loadPublicKey(byte[] x509Der) throws GeneralSecurityException {
        BouncyCastleActivator.init();
        return KeyFactory.getInstance(ALGORITHM, PROVIDER)
                .generatePublic(new X509EncodedKeySpec(x509Der));
    }

    /**
     * Decodes a BIKE private key from a PKCS#8 structure.
     * The parameter set is taken from the encoding. The caller remains
     * responsible for protecting and clearing its input byte array.
     *
     * @param pkcs8Der non-null DER-encoded private key
     * @return the decoded private key, owned by the caller
     * @throws GeneralSecurityException if the provider is unavailable or the encoding is invalid
     */
    public static PrivateKey loadPrivateKey(byte[] pkcs8Der) throws GeneralSecurityException {
        BouncyCastleActivator.init();
        return KeyFactory.getInstance(ALGORITHM, PROVIDER)
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8Der));
    }
}
