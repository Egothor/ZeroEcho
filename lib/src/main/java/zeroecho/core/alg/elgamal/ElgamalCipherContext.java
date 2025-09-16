/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.elgamal;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHKey;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.io.CipherTransformInputStreamBuilder;

/**
 * Streaming ElGamal cipher context that adapts an upstream stream into an
 * encrypted or decrypted stream.
 *
 * <p>
 * The context applies ElGamal block-by-block over a pull pipeline. For a
 * modulus of size {@code pBytes}, each ciphertext block is fixed at
 * {@code 2 * pBytes} bytes (two group elements), while the plaintext-per-block
 * depends on the padding:
 * </p>
 *
 * <ul>
 * <li>NOPADDING: {@code ptBlock = pBytes - 1}</li>
 * <li>PKCS1: {@code ptBlock = pBytes - 11}</li>
 * </ul>
 *
 * <h2>Padding subtleties</h2>
 * <ul>
 * <li><b>NOPADDING:</b> some providers encode integers with a leading
 * {@code 0x00} byte for positive sign. This implementation trims a leading sign
 * byte and enforces a fixed plaintext length for <i>non-last</i> blocks only.
 * The last block is emitted as-is.</li>
 * <li><b>PKCS1:</b> the last plaintext block may be shorter by design; it is
 * never padded on output.</li>
 * </ul>
 *
 * <h2>EOF rules</h2>
 * <ul>
 * <li><b>Encrypt:</b> a short final plaintext block is allowed and produces a
 * single ciphertext block.</li>
 * <li><b>Decrypt:</b> ciphertext must be an integral number of full ciphertext
 * blocks; a partial tail is rejected.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances are not thread-safe. Create one context per
 * pipeline.
 */
public final class ElgamalCipherContext implements EncryptionContext {
    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final ElgamalEncSpec spec;
    private final boolean encrypt;

    /**
     * Creates a new ElGamal cipher context.
     *
     * <p>
     * The transformation used is {@code "ElGamal/None/NOPADDING"} for
     * {@link ElgamalEncSpec.Padding#NOPADDING} and
     * {@code "ElGamal/None/PKCS1Padding"} for {@link ElgamalEncSpec.Padding#PKCS1}.
     * The JCE provider must support the chosen transformation and the provided
     * {@code key} for the requested direction.
     * </p>
     *
     * @param algorithm the owning algorithm for metadata; must not be {@code null}
     * @param key       public key for encrypt or private key for decrypt; must not
     *                  be {@code null}
     * @param spec      ElGamal encoding/padding specification; must not be
     *                  {@code null}
     * @param encrypt   {@code true} for encryption, {@code false} for decryption
     * @throws NullPointerException if any argument is {@code null}
     */
    public ElgamalCipherContext(CryptoAlgorithm algorithm, Key key, ElgamalEncSpec spec, boolean encrypt) {
        this.algorithm = java.util.Objects.requireNonNull(algorithm, "algorithm");
        this.key = java.util.Objects.requireNonNull(key, "key");
        this.spec = java.util.Objects.requireNonNull(spec, "spec");
        this.encrypt = encrypt;
    }

    /**
     * Returns an input stream that transforms bytes on-the-fly using ElGamal.
     *
     * <p>
     * A fresh {@link Cipher} is created and initialized per call. The returned
     * stream implements the block model and EOF rules described in the class
     * documentation. Callers must close the returned stream to finalize the
     * transformation and release resources.
     * </p>
     *
     * @param upstream the upstream source to transform; must not be {@code null}
     * @return a transforming input stream
     * @throws IOException          if the cipher cannot be created or initialized
     * @throws NullPointerException if {@code upstream} is {@code null}
     */
    @Override
    public InputStream attach(InputStream upstream) throws IOException {
        java.util.Objects.requireNonNull(upstream, "upstream");
        final Cipher cipher = newCipher(spec.padding(), encrypt, key);
        final BlockGeometry g = new BlockGeometry(modulusBytes(key), spec.padding(), encrypt);

        return CipherTransformInputStreamBuilder.builder().withCipher(cipher).withUpstream(upstream)
                .withInputBlockSize(g.inputBlockSize()).withOutputBlockSize(g.perBlockOutput())
                .withLeftZeroPadding(g.noPadding).build();
    }

    /**
     * Returns the associated algorithm object for metadata and auditing.
     *
     * @return the algorithm that created this context
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * @return the key used for encryption or decryption
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes this context.
     *
     * <p>
     * The returned transforming streams are independent of the context object, so
     * closing the context has no effect on previously created streams. This method
     * is provided to satisfy the {@link zeroecho.core.context.CryptoContext}
     * contract and may be used by higher layers for lifecycle hooks.
     * </p>
     */
    @Override
    public void close() throws IOException {
        // No resources to release here. Streams manage their own lifetimes.
    }

    private static Cipher newCipher(ElgamalEncSpec.Padding padding, boolean encrypt, Key key) throws IOException {
        final String transformation = switch (padding) {
            case NOPADDING -> "ElGamal/None/NOPADDING";
            case PKCS1 -> "ElGamal/None/PKCS1Padding";
        };
        try {
            Cipher c = Cipher.getInstance(transformation);
            c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
            return c;
        } catch (GeneralSecurityException e) {
            throw new IOException("ElGamal cipher init failed: " + e.getMessage(), e);
        }
    }

    /**
     * Derives the modulus size in bytes from a DH-like key (FFDHE/ElGamal).
     */
    private static int modulusBytes(Key key) {
        if (key instanceof DHKey dh) {
            // FFDHE: p bit length is a multiple of 64; convert to exact bytes.
            final int bits = dh.getParams().getP().bitLength();
            return (bits + 7) >>> 3;
        }
        // If your keys expose p through a different interface, add handling here.
        throw new IllegalArgumentException("Unsupported key type for ElGamal modulus: " + key.getClass().getName());
    }

    /**
     * Immutable description of the ElGamal block layout for a given modulus size,
     * padding, and direction.
     */
    private static final class BlockGeometry {
        private final int pBytes; // modulus size in bytes
        private final int ptBlock; // plaintext-per-block
        private final int ctBlock; // ciphertext-per-block (always 2*pBytes)
        private final boolean encrypt;
        private final boolean noPadding;

        private BlockGeometry(int pBytes, ElgamalEncSpec.Padding padding, boolean encrypt) {
            this.pBytes = pBytes;
            this.ctBlock = 2 * pBytes;
            this.encrypt = encrypt;
            this.noPadding = (padding == ElgamalEncSpec.Padding.NOPADDING);
            this.ptBlock = switch (padding) {
                case NOPADDING -> pBytes - 1;
                case PKCS1 -> pBytes - 11;
            };
        }

        private int inputBlockSize() {
            // How many upstream bytes constitute one cipher operation
            return encrypt ? ptBlock : ctBlock;
        }

        private int perBlockOutput() {
            // Upper-bound for bytes produced by one operation (for buffer sizing)
            return encrypt ? ctBlock : ptBlock;
        }

        @Override
        public String toString() {
            return "BlockGeometry [pBytes=" + pBytes + ", ptBlock=" + ptBlock + ", ctBlock=" + ctBlock + ", encrypt="
                    + encrypt + ", noPadding=" + noPadding + ", inputBlockSize()=" + inputBlockSize()
                    + ", perBlockOutput()=" + perBlockOutput() + "]";
        }
    }
}
