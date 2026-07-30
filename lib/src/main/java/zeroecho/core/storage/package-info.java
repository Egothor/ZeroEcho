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
 * Encrypted local software-keyring storage.
 *
 * <p>
 * {@link zeroecho.core.storage.KeyringStore} binds an unlocked store to one
 * filesystem path and holds exclusive process-lifetime ownership until close.
 * It wraps one random store master key with PBKDF2-HMAC-SHA-256 and
 * AES-256-GCM, encrypts every entry independently, and authenticates the
 * ordered entry manifest. Mutations use owner-only temporary files and atomic
 * replacement.
 * </p>
 *
 * <p>
 * Nonce-reservation authentication is cryptographically separated from AES
 * entry and manifest encryption. A dedicated 256-bit MAC key is derived with
 * HKDF-HMAC-SHA-256 from the store master key, canonical binary store UUID, and
 * fixed nonce-reservation domain. It is never persisted, remains owned by the
 * open store, and is destroyed on close. Only the current sidecar version is
 * accepted.
 * </p>
 *
 * <p>
 * Unlock passwords are destroyable, transfer ownership to the receiver, and are
 * destroyed immediately after the master key is unwrapped. The unlocked store
 * retains the master key, its domain-separated nonce-reservation MAC key, and
 * encrypted entry records; closing the store clears this material. The store
 * requires a POSIX filesystem on which owner-only permissions can be verified.
 * A directory-force failure after atomic replacement makes the open instance
 * unusable until close and authenticated reopen resolves which complete image
 * is current. Non-exportable keys must remain behind an external provider
 * reference.
 * </p>
 *
 * <p>
 * Only the current binary format is accepted. Earlier plaintext development
 * formats are rejected without migration. Persisted input contains no Java
 * class or provider names and cannot trigger runtime class loading. Import
 * specifications are selected from a closed mapping of canonical ZeroEcho
 * algorithm, key kind, standard encoding, and (only for HMAC) one of the
 * explicit SHA-256, SHA-384, or SHA-512 variants. Standard encodings are
 * reconstructed through the current runtime's canonical importer; the
 * originating JCA provider identity is not persisted or guaranteed. Keys that
 * are provider-bound, non-exportable, or not canonically reconstructable must
 * remain behind an external provider reference.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.core.storage;
