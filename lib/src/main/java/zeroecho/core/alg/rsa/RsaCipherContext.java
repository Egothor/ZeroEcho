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
package zeroecho.core.alg.rsa;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.io.CipherTransformInputStreamBuilder;

/**
 * Streaming RSA cipher context that transforms data block-by-block using OAEP
 * or PKCS#1 v1.5 padding.
 *
 * <p>
 * An instance is created for a specific role (encrypt or decrypt) and a
 * concrete {@link RsaEncSpec}. The context exposes a pull-style pipeline via
 * {@link #attach(java.io.InputStream)} that converts bytes on-the-fly, making
 * it suitable for large streams without buffering the whole message in memory.
 * </p>
 *
 * <h2>Behavior</h2>
 * <ul>
 * <li>Encryption reads plaintext in RSA-size blocks according to the selected
 * padding, producing fixed-size ciphertext blocks equal to the modulus
 * length.</li>
 * <li>Decryption requires ciphertext in full modulus-length blocks and yields
 * variable-size plaintext blocks determined by padding.</li>
 * <li>Finalization occurs on end of stream; decryption rejects trailing partial
 * ciphertext blocks.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * RsaEncSpec spec = RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256);
 * try (RsaCipherContext ctx = new RsaCipherContext(algo, pubKey, true, spec);
 *      InputStream in  = Files.newInputStream(plaintextPath);
 *      InputStream enc = ctx.attach(in)) {
 *     Files.copy(enc, ciphertextPath);
 * }
 * }</pre>
 *
 * <p>
 * <b>Security note:</b> OAEP with SHA-256 is preferred over PKCS#1 v1.5.
 * Decryption enforces full ciphertext blocks to avoid truncation hazards. The
 * context does not manage or destroy keys.
 * </p>
 */
public final class RsaCipherContext implements EncryptionContext {

    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encrypt;
    private final RsaEncSpec spec;

    /**
     * Creates a new RSA cipher context for encryption or decryption with the given
     * parameters.
     *
     * <p>
     * The {@code encrypt} flag selects the role of this context: {@code true} for
     * encryption (public key is typical), {@code false} for decryption (private key
     * is required). The {@code spec} defines padding and hash parameters; for OAEP
     * the hash is used both for the digest and MGF1 unless specified otherwise by
     * the spec.
     * </p>
     *
     * @param algorithm the owning algorithm descriptor used for metadata and
     *                  auditing
     * @param key       the RSA key for this role; public for encryption/verify,
     *                  private for decrypt/sign
     * @param encrypt   {@code true} to encrypt, {@code false} to decrypt
     * @param spec      RSA encryption specification including padding mode and hash
     * @throws NullPointerException if any argument is {@code null}
     */
    public RsaCipherContext(CryptoAlgorithm algorithm, Key key, boolean encrypt, RsaEncSpec spec) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.key = Objects.requireNonNull(key, "key must not be null");
        this.encrypt = encrypt;
        this.spec = Objects.requireNonNull(spec, "spec must not be null");
    }

    /**
     * Returns the algorithm descriptor associated with this context.
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
     * @return the RSA key used by this context
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes the context and releases resources.
     *
     * <p>
     * This implementation is a no-op because the attached stream performs
     * finalize-on-close.
     * </p>
     */
    @Override
    public void close() {
        // no-op; stream handles finalize-on-close
    }

    /**
     * Attaches this cipher to an upstream stream and returns a transforming stream.
     *
     * <p>
     * The returned stream pulls from {@code upstream} and emits encrypted or
     * decrypted bytes according to the constructor-selected role and
     * {@link RsaEncSpec}. On EOF, encryption will process a final short plaintext
     * block if present, while decryption requires that the final buffered
     * ciphertext forms a complete modulus-sized block.
     * </p>
     *
     * <p>
     * The caller is responsible for closing the returned stream to ensure
     * finalization and resource cleanup.
     * </p>
     *
     * @param upstream the source stream to transform
     * @return a new input stream that produces transformed bytes
     * @throws NullPointerException if {@code upstream} is {@code null}
     * @throws IOException          if the cipher cannot be initialized or a block
     *                              transform fails
     */
    @Override
    public InputStream attach(InputStream upstream) throws IOException {
        Objects.requireNonNull(upstream, "upstream must not be null");
        try {
            Cipher cipher = Cipher.getInstance(transformation(spec));
            init(cipher);
            // int modBytes = modulusBytes(key);
            // int inBlock = encrypt ? plainBlockSize(modBytes, spec) : modBytes;
            // return new Stream(upstream, cipher, inBlock, modBytes, encrypt);

            BlockGeometry rsaGeometry = BlockGeometry.forRsa(spec, key, encrypt);

            return CipherTransformInputStreamBuilder.builder().withUpstream(upstream).withCipher(cipher)
                    .withInputBlockSize(rsaGeometry.inChunkSize).withOutputBlockSize(rsaGeometry.outChunkSize)
                    .withBufferedBlocks(100).withFinalizationOutputChunks(rsaGeometry.finalizationOutputChunks)
                    .withUpdateStreaming(false).build();
        } catch (GeneralSecurityException e) {
            throw new IOException(spec.description() + " RSA attach/init failed: " + e.getMessage(), e);
        }
    }

    private void init(Cipher cipher) throws GeneralSecurityException {
        if (spec.padding() == RsaEncSpec.Padding.OAEP) {
            OAEPParameterSpec oaep = new OAEPParameterSpec(jcaHash(spec.hash()), "MGF1", mgf1(spec.hash()),
                    spec.label() == null ? PSource.PSpecified.DEFAULT : new PSource.PSpecified(spec.label()));
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, oaep);
        } else {
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
        }
    }

    private static String transformation(RsaEncSpec s) {
        if (s.padding() == RsaEncSpec.Padding.PKCS1V15) {
            return "RSA/ECB/PKCS1Padding";
        }
        return "RSA/ECB/OAEPWith" + jcaHash(s.hash()) + "AndMGF1Padding";
    }

    private static String jcaHash(RsaEncSpec.Hash h) {
        return switch (h) {
            case SHA1 -> "SHA-1";
            case SHA256 -> "SHA-256";
            case SHA384 -> "SHA-384";
            case SHA512 -> "SHA-512";
        };
    }

    private static MGF1ParameterSpec mgf1(RsaEncSpec.Hash h) {
        return switch (h) {
            case SHA1 -> MGF1ParameterSpec.SHA1;
            case SHA256 -> MGF1ParameterSpec.SHA256;
            case SHA384 -> MGF1ParameterSpec.SHA384;
            case SHA512 -> MGF1ParameterSpec.SHA512;
        };
    }
}
