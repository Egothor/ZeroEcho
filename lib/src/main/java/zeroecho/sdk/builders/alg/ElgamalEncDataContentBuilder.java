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
package zeroecho.sdk.builders.alg;

import zeroecho.sdk.ZeroEchoSession;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.elgamal.ElgamalEncSpec;
import zeroecho.core.alg.elgamal.ElgamalKeyGenSpec;
import zeroecho.core.alg.elgamal.ElgamalParamSpec;
import zeroecho.core.alg.elgamal.ElgamalPrivateKeySpec;
import zeroecho.core.alg.elgamal.ElgamalPublicKeySpec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.EncryptedContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * ElgamalEncDataContentBuilder builds streaming ElGamal encryption or
 * decryption pipelines that operate as an InputStream is consumed.
 *
 * <h2>Overview</h2> This builder creates
 * {@link zeroecho.sdk.content.api.DataContent} for ElGamal public key
 * encryption. In encrypt mode it returns content that transforms upstream
 * plaintext into ciphertext using a
 * {@link zeroecho.core.context.EncryptionContext}; in decrypt mode it produces
 * plaintext from ciphertext. Keys may be supplied, generated, or imported from
 * standard encodings. Padding mode is selected via {@link ElgamalEncSpec}.
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Encrypt with a generated 2048-bit key pair using PKCS#1-style padding:
 * DataContent enc = ElgamalEncDataContentBuilder.builder()
 *     .generateKeyPair(ElgamalKeyGenSpec.elgamal2048())
 *     .pkcs1()
 *     .build(true);
 *
 * // Decrypt with an imported private key (PKCS#8) and no padding:
 * DataContent dec = ElgamalEncDataContentBuilder.builder()
 *     .noPadding()
 *     .importPrivatePkcs8(pkcs8Bytes)
 *     .build(false);
 *
 * // Encrypt with an existing public key and parameter preset:
 * DataContent enc2 = ElgamalEncDataContentBuilder.builder()
 *     .withPublicKey(pub)
 *     .spec(ElgamalEncSpec.pkcs1())
 *     .build(true);
 * }</pre>
 *
 * <h2>Key material</h2> You can:
 * <ul>
 * <li>Provide keys directly via {@link #withPublicKey(PublicKey)} or
 * {@link #withPrivateKey(PrivateKey)}.</li>
 * <li>Generate a pair using a size-based {@link ElgamalKeyGenSpec} or a preset
 * {@link ElgamalParamSpec}.</li>
 * <li>Import from encodings with {@link #importPublicX509(byte[])} and
 * {@link #importPrivatePkcs8(byte[])}.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see zeroecho.sdk.builders.core.DataContentBuilder
 * @see zeroecho.core.CryptoAlgorithms
 * @see zeroecho.core.context.EncryptionContext
 * @see ElgamalEncSpec
 * @see ElgamalKeyGenSpec
 * @see ElgamalParamSpec
 */
public final class ElgamalEncDataContentBuilder implements DataContentBuilder<DataContent> {
    private static final String ALGORITHM_ID = "ElGamal";
    private final ZeroEchoSession session;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    private boolean genKeyPairPredef;
    private ElgamalParamSpec paramSpec;

    private boolean genKeyPair;
    private ElgamalKeyGenSpec keyGen = ElgamalKeyGenSpec.elgamal2048();

    private byte[] importPrivatePkcs8;
    private byte[] importPublicX509;

    private ElgamalEncSpec spec = ElgamalEncSpec.pkcs1();

    private ElgamalEncDataContentBuilder(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Creates a new builder for constructing ElGamal encryption or decryption
     * pipelines.
     *
     * <h4>Example</h4> <pre>{@code
     * ElgamalEncDataContentBuilder b = ElgamalEncDataContentBuilder.builder();
     * }</pre>
     *
     * @return a new {@code ElgamalEncDataContentBuilder} instance
     */
    public static ElgamalEncDataContentBuilder builder(ZeroEchoSession session) {
        return new ElgamalEncDataContentBuilder(session);
    }

    /**
     * Sets the encryption specification such as padding mode.
     *
     * @param s the ElGamal encryption spec to use; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code s} is null
     */
    public ElgamalEncDataContentBuilder spec(ElgamalEncSpec s) {
        this.spec = Objects.requireNonNull(s);
        return this;
    }

    /**
     * Selects the no-padding variant of ElGamal encryption.
     *
     * <p>
     * Use with caution. No padding may be appropriate only for specific protocols
     * that add their own randomness and structure.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public ElgamalEncDataContentBuilder noPadding() {
        this.spec = ElgamalEncSpec.noPadding();
        return this;
    }

    /**
     * Selects the PKCS#1-style padding variant of ElGamal encryption.
     *
     * @return {@code this} builder for chaining
     */
    public ElgamalEncDataContentBuilder pkcs1() {
        this.spec = ElgamalEncSpec.pkcs1();
        return this;
    }

    /**
     * Supplies the public key to use for encryption.
     *
     * @param k the public key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public ElgamalEncDataContentBuilder withPublicKey(PublicKey k) {
        this.publicKey = Objects.requireNonNull(k);
        return this;
    }

    /**
     * Supplies the private key to use for decryption.
     *
     * @param k the private key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public ElgamalEncDataContentBuilder withPrivateKey(PrivateKey k) {
        this.privateKey = Objects.requireNonNull(k);
        return this;
    }

    /**
     * Requests generation of a fresh ElGamal key pair using the provided key
     * generation specification.
     *
     * <p>
     * This method clears any preset-parameter request. The generated keys will be
     * used for subsequent {@link #build(boolean)} calls unless overridden by
     * imports or explicit keys.
     * </p>
     *
     * @param spec the key generation spec; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code spec} is null
     */
    public ElgamalEncDataContentBuilder generateKeyPair(ElgamalKeyGenSpec spec) {
        this.genKeyPair = true;
        this.genKeyPairPredef = false;
        this.keyGen = Objects.requireNonNull(spec);
        return this;
    }

    /**
     * Requests generation of a fresh ElGamal key pair with the specified modulus
     * length and default certainty.
     *
     * @param bits modulus size in bits
     * @return {@code this} builder for chaining
     */
    public ElgamalEncDataContentBuilder generateKeyPair(int bits) {
        return generateKeyPair(new ElgamalKeyGenSpec(bits, 128));
    }

    /**
     * Requests generation of a fresh ElGamal key pair using a predefined parameter
     * set.
     *
     * <p>
     * This method clears any size-based generation request. The generated keys will
     * be used for subsequent {@link #build(boolean)} calls unless overridden.
     * </p>
     *
     * @param spec the predefined parameter set; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code spec} is null
     */
    public ElgamalEncDataContentBuilder generateKeyPair(ElgamalParamSpec spec) {
        this.genKeyPairPredef = true;
        this.genKeyPair = false;
        this.paramSpec = Objects.requireNonNull(spec);
        return this;
    }

    /**
     * Imports a private key from PKCS#8-encoded bytes.
     *
     * @param pkcs8 PKCS#8 PrivateKeyInfo bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code pkcs8} is null
     */
    public ElgamalEncDataContentBuilder importPrivatePkcs8(byte[] pkcs8) {
        this.importPrivatePkcs8 = Objects.requireNonNull(pkcs8).clone();
        return this;
    }

    /**
     * Imports a public key from X.509 SubjectPublicKeyInfo bytes.
     *
     * @param x509 X.509 public key bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code x509} is null
     */
    public ElgamalEncDataContentBuilder importPublicX509(byte[] x509) {
        this.importPublicX509 = Objects.requireNonNull(x509).clone();
        return this;
    }

    /**
     * Builds a streaming encryption or decryption pipeline according to the current
     * configuration.
     *
     * <p>
     * When {@code encrypt} is true, a public key must be available either from
     * prior configuration, generation, or import. When {@code encrypt} is false, a
     * private key must be available.
     * </p>
     *
     * <h4>Key resolution order</h4> During build, the builder may generate keys,
     * import keys, or use explicitly provided keys based on the configuration.
     * Generation by size and generation by predefined parameters are mutually
     * exclusive; the last selected mode wins.
     *
     * <h4>Examples</h4> <pre>{@code
     * DataContent enc = ElgamalEncDataContentBuilder.builder()
     *     .generateKeyPair(2048)
     *     .pkcs1()
     *     .build(true);
     *
     * DataContent dec = ElgamalEncDataContentBuilder.builder()
     *     .importPrivatePkcs8(pkcs8)
     *     .build(false);
     * }</pre>
     *
     * @param encrypt {@code true} to build an encrypting pipeline, {@code false}
     *                for a decrypting pipeline
     * @return a {@link zeroecho.sdk.content.api.DataContent} that performs the
     *         requested operation when its stream is consumed
     * @throws IllegalStateException if a required key is missing or if key setup
     *                               fails
     */
    @Override
    public DataContent build(boolean encrypt) {
        try {
            resolveKeys();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ElGamal key setup failed", e);
        }
        if (encrypt) {
            if (publicKey == null) {
                throw new IllegalStateException("Encrypt requires a PublicKey");
            }
            return new Encrypt(publicKey, spec);
        } else {
            if (privateKey == null) {
                throw new IllegalStateException("Decrypt requires a PrivateKey");
            }
            return new Decrypt(privateKey, spec);
        }
    }

    private void resolveKeys() throws GeneralSecurityException {
        if (genKeyPair) {
            KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair(ALGORITHM_ID, keyGen);
            this.publicKey = kp.getPublic();
            this.privateKey = kp.getPrivate();
        } else if (genKeyPairPredef) {
            KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair(ALGORITHM_ID, paramSpec);
            this.publicKey = kp.getPublic();
            this.privateKey = kp.getPrivate();
        }
        if (importPrivatePkcs8 != null) {
            this.privateKey = session.keyBuilders().asymmetric().importPrivate(ALGORITHM_ID,
                    new ElgamalPrivateKeySpec(importPrivatePkcs8));
        }
        if (importPublicX509 != null) {
            this.publicKey = session.keyBuilders().asymmetric().importPublic(ALGORITHM_ID,
                    new ElgamalPublicKeySpec(importPublicX509));
        }
    }

    /**
     * Encrypt is a streaming content adapter that reads plaintext from an upstream
     * {@link zeroecho.sdk.content.api.DataContent} and exposes the
     * ElGamal-encrypted view as an {@link java.io.InputStream}.
     *
     * <p>
     * The class is configured with a {@link java.security.PublicKey} and an
     * {@link ElgamalEncSpec}. When {@link #getStream()} is called, it creates an
     * {@link zeroecho.core.context.EncryptionContext} for the "ElGamal" algorithm
     * in {@link zeroecho.core.KeyUsage#ENCRYPT} role via
     * {@link zeroecho.sdk.ZeroEchoSession#createContext(String,
     * zeroecho.core.KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)},
     * attaches the upstream stream, and returns a pull-based stream that encrypts
     * on the fly.
     * </p>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe and must be used from a
     * single thread.
     */
    private final class Encrypt implements EncryptedContent {
        private final PublicKey key;
        private final ElgamalEncSpec spec;
        private DataContent upstream;

        private Encrypt(PublicKey key, ElgamalEncSpec spec) {
            this.key = key;
            this.spec = spec;
        }

        /**
         * Sets the upstream content that supplies plaintext bytes.
         *
         * @param in the source content to be encrypted; must not be null
         * @throws NullPointerException if {@code in} is null
         */
        @Override
        public void setInput(DataContent in) {
            this.upstream = Objects.requireNonNull(in);
        }

        /**
         * Returns a stream that yields the encrypted view of the upstream content.
         *
         * <p>
         * This method creates an {@link zeroecho.core.context.EncryptionContext} for
         * the configured key and spec, then attaches the upstream stream. The returned
         * stream performs ElGamal encryption as bytes are read.
         * </p>
         *
         * @return an input stream producing ElGamal ciphertext
         * @throws IOException           if the upstream stream cannot be obtained or if
         *                               the encryption context fails to attach
         * @throws IllegalStateException if no upstream has been set via
         *                               {@link #setInput(DataContent)}
         */
        @Override
        public InputStream getStream() throws IOException {
            if (upstream == null) {
                throw new IllegalStateException("elgamal encrypt: upstream not set");
            }
            EncryptionContext ctx = session.createContext(ALGORITHM_ID, KeyUsage.ENCRYPT, key, spec); // NOPMD
            return ctx.attach(upstream.getStream());
        }
    }

    /**
     * Decrypt is a streaming content adapter that reads ciphertext from an upstream
     * {@link zeroecho.sdk.content.api.DataContent} and exposes the
     * ElGamal-decrypted plaintext as an {@link java.io.InputStream}.
     *
     * <p>
     * The class is configured with a {@link java.security.PrivateKey} and an
     * {@link ElgamalEncSpec}. When {@link #getStream()} is called, it creates an
     * {@link zeroecho.core.context.EncryptionContext} for the "ElGamal" algorithm
     * in {@link zeroecho.core.KeyUsage#DECRYPT} role via
     * {@link zeroecho.sdk.ZeroEchoSession#createContext(String,
     * zeroecho.core.KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)},
     * attaches the upstream stream, and returns a pull-based stream that decrypts
     * on the fly.
     * </p>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe and must be used from a
     * single thread.
     */
    private final class Decrypt implements PlainContent {
        private final PrivateKey key;
        private final ElgamalEncSpec spec;
        private DataContent upstream;

        private Decrypt(PrivateKey key, ElgamalEncSpec spec) {
            this.key = key;
            this.spec = spec;
        }

        /**
         * Sets the upstream content that supplies ciphertext bytes.
         *
         * @param in the source content to be decrypted; must not be null
         * @throws NullPointerException if {@code in} is null
         */
        @Override
        public void setInput(DataContent in) {
            this.upstream = Objects.requireNonNull(in);
        }

        /**
         * Returns a stream that yields the decrypted view of the upstream content.
         *
         * <p>
         * This method creates an {@link zeroecho.core.context.EncryptionContext} for
         * the configured key and spec, then attaches the upstream stream. The returned
         * stream performs ElGamal decryption as bytes are read.
         * </p>
         *
         * @return an input stream producing plaintext bytes
         * @throws IOException           if the upstream stream cannot be obtained or if
         *                               the decryption context fails to attach
         * @throws IllegalStateException if no upstream has been set via
         *                               {@link #setInput(DataContent)}
         */
        @Override
        public InputStream getStream() throws IOException {
            if (upstream == null) {
                throw new IllegalStateException("elgamal decrypt: upstream not set");
            }
            EncryptionContext ctx = session.createContext(ALGORITHM_ID, KeyUsage.DECRYPT, key, spec); // NOPMD
            return ctx.attach(upstream.getStream());
        }
    }
}
