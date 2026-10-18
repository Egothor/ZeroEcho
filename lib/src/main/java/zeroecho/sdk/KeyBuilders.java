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
package zeroecho.sdk;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import javax.crypto.SecretKey;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.core.spi.PrivateKeyImporter;
import zeroecho.core.spi.PublicKeyImporter;
import zeroecho.core.spi.SymmetricKeyGenerator;
import zeroecho.core.spi.SymmetricKeyImporter;

/**
 * Session-bound entry point for exact key-material operations.
 *
 * <p>
 * Capability lookup fails before an operation object is returned. Returned
 * objects guarantee the requested operation and report successful execution to
 * the owning session's audit listener on a best-effort basis.
 * </p>
 *
 * @since 1.0
 */
public final class KeyBuilders {
    private final ZeroEchoSession session;
    private final Symmetric symmetric = new Symmetric();
    private final Asymmetric asymmetric = new Asymmetric();

    /* default */ KeyBuilders(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Returns symmetric key operations.
     *
     * @return session-bound symmetric namespace
     */
    public Symmetric symmetric() {
        return symmetric;
    }

    /**
     * Returns asymmetric key operations.
     *
     * @return session-bound asymmetric namespace
     */
    public Asymmetric asymmetric() {
        return asymmetric;
    }

    /**
     * Symmetric generation and import lookups.
     */
    public final class Symmetric {
        private Symmetric() {
        }

        /**
         * Resolves an exact symmetric generator.
         *
         * @param algorithmId canonical algorithm identifier
         * @param specType    exact specification class
         * @param <S>         specification type
         * @return guaranteed generator
         * @throws IllegalArgumentException if the capability is absent
         */
        public <S extends AlgorithmKeySpec> SymmetricKeyGenerator<S> generator(String algorithmId, Class<S> specType) {
            CryptoAlgorithm algorithm = session.require(algorithmId);
            SymmetricKeyGenerator<S> delegate = algorithm.symmetricKeyGenerator(specType);
            return spec -> {
                SecretKey key = delegate.generateSecret(spec);
                session.notifyKeyGenerated(algorithm, spec, key);
                return key;
            };
        }

        /**
         * Resolves an exact symmetric importer.
         *
         * @param algorithmId canonical algorithm identifier
         * @param specType    exact specification class
         * @param <S>         specification type
         * @return guaranteed importer
         * @throws IllegalArgumentException if the capability is absent
         */
        public <S extends AlgorithmKeySpec> SymmetricKeyImporter<S> importer(String algorithmId, Class<S> specType) {
            CryptoAlgorithm algorithm = session.require(algorithmId);
            SymmetricKeyImporter<S> delegate = algorithm.symmetricKeyImporter(specType);
            return spec -> {
                SecretKey key = delegate.importSecret(spec);
                session.notifyKeyBuilt(algorithm, spec, key);
                return key;
            };
        }

        /**
         * Generates a symmetric key using the exact runtime specification type.
         *
         * @param algorithmId canonical algorithm identifier
         * @param spec        generation specification
         * @param <S>         specification type
         * @return generated secret key
         * @throws java.security.GeneralSecurityException if generation fails
         * @throws IllegalArgumentException               if the capability is absent
         * @throws NullPointerException                   if {@code spec} is
         *                                                {@code null}
         */
        public <S extends AlgorithmKeySpec> SecretKey generate(String algorithmId, S spec)
                throws java.security.GeneralSecurityException {
            Objects.requireNonNull(spec, "spec");
            @SuppressWarnings("unchecked")
            Class<S> specType = (Class<S>) spec.getClass();
            return generator(algorithmId, specType).generateSecret(spec);
        }

        /**
         * Imports a symmetric key using the exact runtime specification type.
         *
         * @param algorithmId canonical algorithm identifier
         * @param spec        import specification
         * @param <S>         specification type
         * @return imported secret key
         * @throws java.security.GeneralSecurityException if import fails
         * @throws IllegalArgumentException               if the capability is absent
         * @throws NullPointerException                   if {@code spec} is
         *                                                {@code null}
         */
        public <S extends AlgorithmKeySpec> SecretKey importKey(String algorithmId, S spec)
                throws java.security.GeneralSecurityException {
            Objects.requireNonNull(spec, "spec");
            @SuppressWarnings("unchecked")
            Class<S> specType = (Class<S>) spec.getClass();
            return importer(algorithmId, specType).importSecret(spec);
        }
    }

    /**
     * Asymmetric generation and import lookups.
     */
    public final class Asymmetric {
        private Asymmetric() {
        }

        /**
         * Resolves an exact key-pair generator.
         *
         * @param algorithmId canonical algorithm identifier
         * @param specType    exact specification class
         * @param <S>         specification type
         * @return guaranteed generator
         * @throws IllegalArgumentException if the capability is absent
         */
        public <S extends AlgorithmKeySpec> AsymmetricKeyPairGenerator<S> keyPairGenerator(String algorithmId,
                Class<S> specType) {
            CryptoAlgorithm algorithm = session.require(algorithmId);
            AsymmetricKeyPairGenerator<S> delegate = algorithm.asymmetricKeyPairGenerator(specType);
            return spec -> {
                KeyPair pair = delegate.generateKeyPair(spec);
                session.notifyKeyPairGenerated(algorithm, spec, pair);
                return pair;
            };
        }

        /**
         * Resolves an exact public-key importer.
         *
         * @param algorithmId canonical algorithm identifier
         * @param specType    exact specification class
         * @param <S>         specification type
         * @return guaranteed importer
         * @throws IllegalArgumentException if the capability is absent
         */
        public <S extends AlgorithmKeySpec> PublicKeyImporter<S> publicImporter(String algorithmId, Class<S> specType) {
            CryptoAlgorithm algorithm = session.require(algorithmId);
            PublicKeyImporter<S> delegate = algorithm.publicKeyImporter(specType);
            return spec -> {
                PublicKey key = delegate.importPublic(spec);
                session.notifyKeyBuilt(algorithm, spec, key);
                return key;
            };
        }

        /**
         * Resolves an exact private-key importer.
         *
         * @param algorithmId canonical algorithm identifier
         * @param specType    exact specification class
         * @param <S>         specification type
         * @return guaranteed importer
         * @throws IllegalArgumentException if the capability is absent
         */
        public <S extends AlgorithmKeySpec> PrivateKeyImporter<S> privateImporter(String algorithmId,
                Class<S> specType) {
            CryptoAlgorithm algorithm = session.require(algorithmId);
            PrivateKeyImporter<S> delegate = algorithm.privateKeyImporter(specType);
            return spec -> {
                PrivateKey key = delegate.importPrivate(spec);
                session.notifyKeyBuilt(algorithm, spec, key);
                return key;
            };
        }

        /**
         * Generates a key pair using the exact runtime specification type.
         *
         * @param algorithmId canonical algorithm identifier
         * @param spec        generation specification
         * @param <S>         specification type
         * @return generated key pair
         * @throws java.security.GeneralSecurityException if generation fails
         * @throws IllegalArgumentException               if the capability is absent
         * @throws NullPointerException                   if {@code spec} is
         *                                                {@code null}
         */
        public <S extends AlgorithmKeySpec> KeyPair generateKeyPair(String algorithmId, S spec)
                throws java.security.GeneralSecurityException {
            Objects.requireNonNull(spec, "spec");
            @SuppressWarnings("unchecked")
            Class<S> specType = (Class<S>) spec.getClass();
            return keyPairGenerator(algorithmId, specType).generateKeyPair(spec);
        }

        /**
         * Imports a public key using the exact runtime specification type.
         *
         * @param algorithmId canonical algorithm identifier
         * @param spec        public-key import specification
         * @param <S>         specification type
         * @return imported public key
         * @throws java.security.GeneralSecurityException if import fails
         * @throws IllegalArgumentException               if the capability is absent
         * @throws NullPointerException                   if {@code spec} is
         *                                                {@code null}
         */
        public <S extends AlgorithmKeySpec> PublicKey importPublic(String algorithmId, S spec)
                throws java.security.GeneralSecurityException {
            Objects.requireNonNull(spec, "spec");
            @SuppressWarnings("unchecked")
            Class<S> specType = (Class<S>) spec.getClass();
            return publicImporter(algorithmId, specType).importPublic(spec);
        }

        /**
         * Imports a private key using the exact runtime specification type.
         *
         * @param algorithmId canonical algorithm identifier
         * @param spec        private-key import specification
         * @param <S>         specification type
         * @return imported private key
         * @throws java.security.GeneralSecurityException if import fails
         * @throws IllegalArgumentException               if the capability is absent
         * @throws NullPointerException                   if {@code spec} is
         *                                                {@code null}
         */
        public <S extends AlgorithmKeySpec> PrivateKey importPrivate(String algorithmId, S spec)
                throws java.security.GeneralSecurityException {
            Objects.requireNonNull(spec, "spec");
            @SuppressWarnings("unchecked")
            Class<S> specType = (Class<S>) spec.getClass();
            return privateImporter(algorithmId, specType).importPrivate(spec);
        }
    }
}
