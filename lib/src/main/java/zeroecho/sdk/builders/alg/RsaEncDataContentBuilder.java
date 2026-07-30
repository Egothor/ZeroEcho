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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.rsa.RsaEncSpec;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.rsa.RsaPrivateKeySpec;
import zeroecho.core.alg.rsa.RsaPublicKeySpec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.EncryptedContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * RsaEncDataContentBuilder builds streaming RSA encryption or decryption
 * pipelines that operate while an InputStream is consumed.
 *
 * <h2>Overview</h2> This builder produces
 * {@link zeroecho.sdk.content.api.DataContent} backed by an
 * {@link zeroecho.core.context.EncryptionContext} created from
 * {@code CryptoAlgorithms}. In encrypt mode it transforms upstream plaintext
 * into ciphertext; in decrypt mode it transforms ciphertext back to plaintext.
 * Padding and OAEP parameters are configured via {@link RsaEncSpec}.
 *
 * <h2>Key material</h2> Keys can be supplied directly, generated from
 * {@link RsaKeyGenSpec}, or imported from standard encodings: PKCS#8 for
 * private keys and X.509 SubjectPublicKeyInfo for public keys. If both
 * generation and import are requested, the last configuration applied before
 * {@link #build(boolean)} takes effect.
 *
 * <h2>Examples</h2> <pre>{@code
 * // Encrypt with OAEP-SHA-256 and a generated 2048-bit key pair
 * DataContent enc = RsaEncDataContentBuilder.builder()
 *     .oaepSha256()
 *     .generateKeyPair(RsaKeyGenSpec.rsa2048())
 *     .build(true);
 *
 * // Decrypt with an imported PKCS#8 private key
 * DataContent dec = RsaEncDataContentBuilder.builder()
 *     .importPrivatePkcs8(pkcs8Bytes)
 *     .build(false);
 *
 * // Encrypt with OAEP-SHA-512 and an application label
 * DataContent enc2 = RsaEncDataContentBuilder.builder()
 *     .oaep(RsaEncSpec.Hash.SHA512)
 *     .oaepLabelUtf8("session-1")
 *     .withPublicKey(pub)
 *     .build(true);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see zeroecho.sdk.builders.core.DataContentBuilder
 * @see zeroecho.core.CryptoAlgorithms
 * @see zeroecho.core.context.EncryptionContext
 * @see RsaEncSpec
 * @see RsaKeyGenSpec
 */
public final class RsaEncDataContentBuilder implements DataContentBuilder<DataContent> {
    private final ZeroEchoSession session;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private boolean genKeyPair;
    private RsaKeyGenSpec keyGen = RsaKeyGenSpec.rsa2048();

    private byte[] importPrivatePkcs8;
    private byte[] importPublicX509;

    private RsaEncSpec spec = RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256); // default

    private RsaEncDataContentBuilder(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Creates a new builder for constructing RSA encryption or decryption
     * pipelines.
     *
     * <pre>{@code
     * RsaEncDataContentBuilder b = RsaEncDataContentBuilder.builder();
     * }</pre>
     *
     * @return a new {@code RsaEncDataContentBuilder} instance
     */
    public static RsaEncDataContentBuilder builder(ZeroEchoSession session) {
        return new RsaEncDataContentBuilder(session);
    }

    /**
     * Sets the RSA encryption specification, including padding and OAEP parameters.
     *
     * @param s the RSA encryption spec; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code s} is null
     */
    public RsaEncDataContentBuilder spec(RsaEncSpec s) {
        this.spec = Objects.requireNonNull(s);
        return this;
    }

    /**
     * Selects RSA-OAEP with SHA-256 for MGF1 and hash.
     *
     * @return {@code this} builder for chaining
     */
    public RsaEncDataContentBuilder oaepSha256() {
        this.spec = RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256);
        return this;
    }

    /**
     * Selects RSA-OAEP with the given hash algorithm for MGF1 and hash.
     *
     * @param h the OAEP hash function
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code h} is null
     */
    public RsaEncDataContentBuilder oaep(RsaEncSpec.Hash h) {
        this.spec = RsaEncSpec.oaep(h);
        return this;
    }

    /**
     * Sets the OAEP label as arbitrary bytes.
     *
     * <p>
     * The label is included in the OAEP parameter set. It is not encrypted and must
     * be supplied identically during decryption.
     * </p>
     *
     * @param label the OAEP label bytes; may be null to clear
     * @return {@code this} builder for chaining
     */
    public RsaEncDataContentBuilder oaepLabel(byte[] label) {
        this.spec = this.spec.withLabel(label);
        return this;
    }

    /**
     * Sets the OAEP label from a UTF-8 string.
     *
     * @param s the label text; may be null to clear
     * @return {@code this} builder for chaining
     */
    public RsaEncDataContentBuilder oaepLabelUtf8(String s) {
        this.spec = this.spec.withLabelUtf8(s);
        return this;
    }

    /**
     * Selects PKCS#1 v1.5 padding for RSA.
     *
     * @return {@code this} builder for chaining
     */
    public RsaEncDataContentBuilder pkcs1v15() {
        this.spec = RsaEncSpec.pkcs1v15();
        return this;
    }

    /**
     * Supplies the public key to use for encryption.
     *
     * @param k the public key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public RsaEncDataContentBuilder withPublicKey(PublicKey k) {
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
    public RsaEncDataContentBuilder withPrivateKey(PrivateKey k) {
        this.privateKey = Objects.requireNonNull(k);
        return this;
    }

    /**
     * Requests generation of a fresh RSA key pair with the provided key generation
     * specification.
     *
     * @param spec the RSA key generation spec; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code spec} is null
     */
    public RsaEncDataContentBuilder generateKeyPair(RsaKeyGenSpec spec) {
        this.genKeyPair = true;
        this.keyGen = Objects.requireNonNull(spec);
        return this;
    }

    /**
     * Requests generation of a fresh RSA key pair using the given modulus size and
     * public exponent.
     *
     * @param bits           modulus size in bits
     * @param publicExponent public exponent (for example 65537)
     * @return {@code this} builder for chaining
     */
    public RsaEncDataContentBuilder generateKeyPair(int bits, int publicExponent) {
        return generateKeyPair(new RsaKeyGenSpec(bits, publicExponent));
    }

    /**
     * Imports a private key from PKCS#8-encoded bytes.
     *
     * @param pkcs8 PKCS#8 PrivateKeyInfo bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code pkcs8} is null
     */
    public RsaEncDataContentBuilder importPrivatePkcs8(byte[] pkcs8) {
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
    public RsaEncDataContentBuilder importPublicX509(byte[] x509) {
        this.importPublicX509 = Objects.requireNonNull(x509).clone();
        return this;
    }

    /**
     * Builds a streaming encryption or decryption pipeline according to the current
     * configuration.
     *
     * <p>
     * When {@code encrypt} is true, a public key must be available from prior
     * configuration, generation, or import. When {@code encrypt} is false, a
     * private key must be available.
     * </p>
     *
     * <pre>{@code
     * DataContent enc = RsaEncDataContentBuilder.builder()
     *     .oaepSha256()
     *     .generateKeyPair(2048, 65537)
     *     .build(true);
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
            throw new IllegalStateException("RSA key setup failed", e);
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
            KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("RSA", keyGen);
            this.publicKey = kp.getPublic();
            this.privateKey = kp.getPrivate();
        }
        if (importPrivatePkcs8 != null) {
            this.privateKey = session.keyBuilders().asymmetric().importPrivate("RSA",
                    new RsaPrivateKeySpec(importPrivatePkcs8));
        }
        if (importPublicX509 != null) {
            this.publicKey = session.keyBuilders().asymmetric().importPublic("RSA",
                    new RsaPublicKeySpec(importPublicX509));
        }
    }

    /**
     * Encrypt is a streaming adapter that reads plaintext from an upstream
     * {@link zeroecho.sdk.content.api.DataContent} and exposes the RSA-encrypted
     * view as an {@link java.io.InputStream}.
     *
     * <p>
     * When {@link #getStream()} is invoked, this class creates an
     * {@link zeroecho.core.context.EncryptionContext} for the "RSA" algorithm in
     * {@link zeroecho.core.KeyUsage#ENCRYPT} role via
     * {@link zeroecho.sdk.ZeroEchoSession#createContext(String,
     * zeroecho.core.KeyUsage, java.security.Key,
     * zeroecho.core.spec.ContextSpec)},
     * attaches the upstream stream, and returns a pull-based stream that encrypts
     * on-the-fly using the configured {@link RsaEncSpec}.
     * </p>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe and must be used from a
     * single thread.
     */
    private final class Encrypt implements EncryptedContent {
        private final PublicKey key;
        private final RsaEncSpec spec;
        private DataContent upstream;

        private Encrypt(PublicKey key, RsaEncSpec spec) {
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
         * Returns a stream that yields the RSA-encrypted view of the upstream content.
         *
         * <p>
         * The method constructs an {@link zeroecho.core.context.EncryptionContext} for
         * the configured public key and {@link RsaEncSpec}, then attaches the upstream
         * stream. The returned stream performs encryption as bytes are read.
         * </p>
         *
         * @return an input stream producing RSA ciphertext bytes
         * @throws IOException           if the upstream stream cannot be obtained or if
         *                               the encryption context fails to attach
         * @throws IllegalStateException if no upstream has been set via
         *                               {@link #setInput(DataContent)}
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "rsa encrypt: upstream not set");
            EncryptionContext ctx = session.createContext("RSA", KeyUsage.ENCRYPT, key, spec); // NOPMD
            return ctx.attach(upstream.getStream());
        }
    }

    /**
     * Decrypt is a streaming adapter that reads ciphertext from an upstream
     * {@link zeroecho.sdk.content.api.DataContent} and exposes the RSA-decrypted
     * plaintext as an {@link java.io.InputStream}.
     *
     * <p>
     * When {@link #getStream()} is invoked, this class creates an
     * {@link zeroecho.core.context.EncryptionContext} for the "RSA" algorithm in
     * {@link zeroecho.core.KeyUsage#DECRYPT} role via
     * {@link zeroecho.sdk.ZeroEchoSession#createContext(String,
     * zeroecho.core.KeyUsage, java.security.Key,
     * zeroecho.core.spec.ContextSpec)},
     * attaches the upstream stream, and returns a pull-based stream that decrypts
     * on-the-fly using the configured {@link RsaEncSpec}.
     * </p>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe and must be used from a
     * single thread.
     */
    private final class Decrypt implements PlainContent {
        private final PrivateKey key;
        private final RsaEncSpec spec;
        private DataContent upstream;

        private Decrypt(PrivateKey key, RsaEncSpec spec) {
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
         * Returns a stream that yields the RSA-decrypted view of the upstream content.
         *
         * <p>
         * The method constructs an {@link zeroecho.core.context.EncryptionContext} for
         * the configured private key and {@link RsaEncSpec}, then attaches the upstream
         * stream. The returned stream performs decryption as bytes are read.
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
            Objects.requireNonNull(upstream, "rsa decrypt: upstream not set");
            EncryptionContext ctx = session.createContext("RSA", KeyUsage.DECRYPT, key, spec); // NOPMD
            return ctx.attach(upstream.getStream());
        }
    }
}
