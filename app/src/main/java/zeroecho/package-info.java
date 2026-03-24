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
/**
 * Command-line tooling built around streaming cryptographic pipelines for
 * encryption, tagging, key management, and covert transport.
 *
 * <p>
 * This package provides a small set of composable subcommands exposed through a
 * single dispatcher and implemented on top of builder-style SDK components. The
 * design favors streaming I/O so large inputs are never fully buffered in
 * memory, and it emphasizes strong defaults with explicit opt-ins for advanced
 * parameters.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li><b>Single front end, multiple tools:</b> the {@link ZeroEcho} dispatcher
 * selects a subcommand and passes through the remaining CLI arguments to it,
 * allowing each tool to define its own options without global conflicts.</li>
 * <li><b>Streaming composition:</b> subcommands assemble {@code DataContent}
 * chains so input is transformed on the fly (encrypt, tag, verify, embed) and
 * written to the destination stream. This keeps memory usage low and makes
 * stdin/stdout a first-class I/O mode.</li>
 * <li><b>Safe, explicit defaults:</b> symmetric modes default to authenticated
 * variants when available, headers are on by default when they carry required
 * parameters, and verification errors cause clear exit codes and cleanup of
 * incomplete outputs.</li>
 * </ul>
 *
 * <h2>Core ideas and algorithms</h2>
 * <p>
 * The tools build on two families of primitives:
 * </p>
 * <ul>
 * <li><b>Asymmetric/KEM envelopes:</b> hybrid encryption encapsulates a
 * content-encryption key with a chosen KEM, then applies a symmetric cipher
 * (AES-GCM/CTR/CBC or ChaCha AEAD/stream). HKDF-SHA256 is supported for
 * deriving the payload key from the KEM secret, with limits on accepted
 * KEM-ciphertext sizes.</li>
 * <li><b>Trailer tags:</b> a trailer at the end of the stream carries either a
 * digital signature or a digest. Produce mode computes and appends the tag;
 * verify mode validates and strips it, returning a non-zero status on
 * mismatch.</li>
 * </ul>
 * <p>
 * Key material is loaded from a simple, text-based keyring that supports
 * listing, generation, and import/export of versioned snippets for both
 * symmetric and asymmetric algorithms.
 * </p>
 *
 * <h2>Subcommands overview</h2>
 * <ul>
 * <li>{@link Guard} - multi-recipient envelope that mixes public-key recipients
 * and passwords, optionally shuffling recipients; payload is AES or ChaCha with
 * optional header and AAD.</li>
 * <li>{@link Kem} - KEM-based hybrid encryption and decryption with AES or
 * ChaCha payloads, HKDF support, counters/nonces, and compact symmetric
 * headers.</li>
 * <li>{@link KeyStoreManagement} - maintenance of a text keyring: list
 * algorithms and aliases, generate keys, and import/export versioned
 * snippets.</li>
 * <li>{@link Tag} - produce or verify trailer tags using digital signatures or
 * message digests.</li>
 * <li>{@link CovertCommand} - embed or extract a binary payload in JPEG files
 * via configurable EXIF slots.</li>
 * </ul>
 *
 * <h2>I/O conventions and exit codes</h2>
 * <ul>
 * <li>All tools accept "-" for stdin/stdout when appropriate, enabling shell
 * pipelines.</li>
 * <li>Exit code {@code 0} indicates success; non-zero codes signal parse
 * errors, verification failures, or I/O problems. Verification failures attempt
 * to remove partially written outputs.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * # Multi-recipient envelope (AES-GCM) with shuffled recipients
 * ZeroEcho -G --encrypt in.bin --output out.enc \
 *   --keyring keyring.txt --to-alias alice --to-psw s3cret \
 *   --alg aes-gcm --tag-bits 128 --aad-hex DEADBEEF
 *
 * # KEM + ChaCha AEAD with header
 * ZeroEcho -E --encrypt in.bin -o out.enc \
 *   --keyring keyring.txt --pub alice-pub \
 *   --kem Kyber-768 --chacha --chacha-nonce 00112233445566778899AABB \
 *   --aad 01020304 --header
 *
 * # Generate a key into the keyring
 * ZeroEcho -K --keystore keyring.txt --generate --alg Ed25519 --alias signing
 *
 * # Trailer signature (produce/verify)
 * ZeroEcho -T --type signature --mode produce --alg Ed25519 \
 *   --ks keyring.txt --priv signing.prv --in file.bin --out file.tagged
 *
 * # Covert EXIF embedding
 * ZeroEcho -C --embed --jpeg in.jpg --payload secret.bin --output out.jpg
 * }</pre>
 *
 * @since 1.0
 */
package zeroecho;
