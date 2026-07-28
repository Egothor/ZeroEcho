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
 * Human-editable key storage persisted in a compact UTF-8 text format.
 *
 * <p>
 * This package provides a lightweight keyring that applications can read and
 * write without specialized tooling. The store keeps entries in insertion
 * order, allows simple alias-based lookups, and materializes keys through the
 * core catalog.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link KeyringStore} - in-memory map of aliases to immutable records with
 * helpers to add, load, save, import, export, and resolve keys.</li>
 * <li>{@link KeyringStore.Record} - value object describing one entry: alias,
 * algorithm id, {@link KeyringStore.Record.Kind kind}, spec class, and a
 * {@link zeroecho.core.marshal.PairSeq} payload.</li>
 * <li><i>Resolution helpers</i> - {@link KeyringStore#getPublic(String)},
 * {@link KeyringStore#getPrivate(String)}, and
 * {@link KeyringStore#getSecret(String)} plus
 * {@link KeyringStore.PublicWithId}, {@link KeyringStore.PrivateWithId},
 * {@link KeyringStore.SecretWithId} to return the algorithm id together with
 * the key.</li>
 * </ul>
 *
 * <h2>File format</h2>
 * <p>
 * Files begin with a magic header followed by one or more <code>@entry</code>
 * blocks. Keys that belong to the spec payload are prefixed with
 * <code>s.</code> to avoid collisions with top-level fields; in-memory they are
 * stored without the prefix. Lines beginning with <code>#</code> are comments.
 * A blank line terminates an entry.
 * </p>
 *
 * <pre>{@code
 * # KeyringStore v1
 * &#64;entry
 * alias=my-rsa
 * algorithm=RSA
 * kind=PUBLIC_KEY
 * spec=zeroecho.core.alg.rsa.RsaPublicKeySpec
 * s.x509B64=MIIBIjANBgkqh...
 * }</pre>
 *
 * <h2>Spec marshaling contract</h2>
 * <p>
 * Each spec class named in the <code>spec</code> field must expose two public
 * static methods discovered by reflection:
 * </p>
 * <ul>
 * <li><code>static PairSeq marshal(SpecType spec)</code></li>
 * <li><code>static SpecType unmarshal(PairSeq pairs)</code></li>
 * </ul>
 * <p>
 * {@link KeyringStore} validates each persisted specification type against the
 * selected algorithm's registered import operation before invoking these
 * methods.
 * </p>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Create and persist a keyring.
 * zeroecho.sdk.ZeroEchoSession session = new zeroecho.sdk.ZeroEchoSession();
 * KeyringStore ks = new KeyringStore(session);
 * ks.putPublic("site-signing", "Ed25519", myEd25519PublicSpec);
 * ks.putPrivate("site-signing", "Ed25519", myEd25519PrivateSpec);
 * ks.save(java.nio.file.Path.of("keyring.txt"));
 *
 * // Load and resolve a key later.
 * KeyringStore reloaded = KeyringStore.load(session, java.nio.file.Path.of("keyring.txt"));
 * java.security.PublicKey pub = reloaded.getPublic("site-signing");
 * }</pre>
 *
 * <h2>Notes and recommendations</h2>
 * <ul>
 * <li>Persistence is plaintext. Treat files as sensitive, protect with OS
 * permissions, and avoid committing to VCS.</li>
 * <li>Resolution delegates to {@link zeroecho.core.CryptoAlgorithms}; the
 * algorithm id must be one that the catalog recognizes.</li>
 * <li>Records are immutable;
 * {@link KeyringStore#putPublic(String, String, zeroecho.core.spec.AlgorithmKeySpec)},
 * {@link KeyringStore#putPrivate(String, String, zeroecho.core.spec.AlgorithmKeySpec)},
 * and
 * {@link KeyringStore#putSecret(String, String, zeroecho.core.spec.AlgorithmKeySpec)}
 * replace entries by alias.</li>
 * <li>Lookups validate kind; for example,
 * {@link KeyringStore#getPublic(String)} fails if the alias stores a private
 * key.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.storage;
