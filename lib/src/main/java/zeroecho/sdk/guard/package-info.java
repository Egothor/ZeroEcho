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
 * Multi-recipient envelope for symmetric payloads with pluggable recipients,
 * reusable openers, and a compact header.
 *
 * <h2>Overview</h2> This package implements a streaming envelope that protects
 * one content-encryption key (CEK) for multiple recipients and delegates the
 * actual payload protection to a symmetric data-content builder (for example,
 * AES-GCM or AES-CBC). At encrypt time the envelope generates a fresh CEK,
 * creates a table of recipient entries that can recover that CEK, and then
 * streams the symmetric stage header and ciphertext. At decrypt time openers
 * scan the recipient table using a single piece of unlocking material until one
 * opener recovers the CEK, after which the symmetric stage processes the
 * remainder of the stream.
 *
 * <h2>Header format</h2> The envelope header is self-delimiting and precedes
 * the symmetric stage bytes. All lengths are encoded as unsigned pack7 integers
 * and all byte sequences are length-prefixed by pack7.
 *
 * <table border="1">
 * <caption>Header format</caption> <thead>
 * <tr>
 * <th>Field</th>
 * <th>Type</th>
 * <th>Encoding</th>
 * <th>Description</th>
 * </tr>
 * </thead> <tbody>
 * <tr>
 * <td>recipientCount</td>
 * <td>int</td>
 * <td>pack7</td>
 * <td>Number of recipient entries that follow.</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>Repeated for i = 1..recipientCount</em></td>
 * </tr>
 * <tr>
 * <td>entryId</td>
 * <td>String</td>
 * <td>pack7 length + UTF-8 bytes</td>
 * <td>Human-readable identifier that helps route to a matching opener, for
 * example "RSA:OAEP-SHA256" or "KEM:ML-KEM:GCM-WRAP".</td>
 * </tr>
 * <tr>
 * <td>entryBlob</td>
 * <td>byte[]</td>
 * <td>pack7 length + bytes</td>
 * <td>Opaque per-recipient data sufficient for a matching opener to recover the
 * CEK. Examples include RSA-wrapped CEK, KEM ciphertext plus salts and IVs, or
 * AEAD-wrapped CEK.</td>
 * </tr>
 * <tr>
 * <td colspan="4"><em>End repeated section</em></td>
 * </tr>
 * <tr>
 * <td>symmetricHeader</td>
 * <td>byte[]</td>
 * <td>builder-defined</td>
 * <td>Optional header owned and emitted by the symmetric stage (for example,
 * IV, tag size, or AAD hash), if the chosen symmetric builder is configured to
 * write one.</td>
 * </tr>
 * <tr>
 * <td>ciphertext</td>
 * <td>byte stream</td>
 * <td>builder-defined</td>
 * <td>Payload bytes produced by the symmetric stage.</td>
 * </tr>
 * </tbody>
 * </table>
 *
 * <h2>Key ideas</h2>
 * <ul>
 * <li><strong>Separation of concerns:</strong> the envelope manages CEK
 * generation and recipient entries; the symmetric builder manages algorithm
 * parameters and payload framing.</li>
 * <li><strong>Reusable opener strategies:</strong> recipients encode entries;
 * openers attempt every applicable entry and create fresh cryptographic
 * contexts per attempt. Neither carries long-lived secret state.</li>
 * <li><strong>Defensive parsing:</strong> the builder applies limits to the
 * number of recipients and the size of each entry blob; the symmetric stage
 * applies its own limits to its header and payload.</li>
 * </ul>
 *
 * <h2>Design decision: separate unlocking material from openers</h2> This
 * package intentionally keeps {@link zeroecho.sdk.guard.UnlockMaterial}
 * separate from {@link zeroecho.sdk.guard.RecipientOpener}. Openers encode how
 * to interpret and attempt a specific entry type and are reusable and
 * stateless; unlocking material centralizes ownership of secrets (private keys
 * or passwords), which simplifies secret lifecycle management and allows the
 * envelope to try one piece of material across heterogeneous entries in a
 * uniform scan. Custom openers receive the borrowed material for each attempt
 * and must not retain it.
 *
 * <h2>Hardening options</h2> The following options are design targets and not
 * yet implemented in this package:
 * <ul>
 * <li><strong>Label suppression:</strong> omit human-readable {@code entryId}
 * strings and write empty identifiers, forcing openers to attempt blind parses
 * of entry blobs.</li>
 * <li><strong>Entry padding or bucketing:</strong> normalize entry blob sizes
 * to reduce size-based fingerprinting.</li>
 * </ul>
 * Both options trade additional compute and bandwidth for reduced metadata
 * leakage and can be added without changing the basic header framing shown
 * above.
 *
 * <h2>Typical usage</h2> <pre>{@code
 * ZeroEchoSession session = new ZeroEchoSession();
 * EncryptionContext rsaRecipient =
 *     session.createContext("RSA", KeyUsage.ENCRYPT, rsaPub);
 * KemContext kemRecipient =
 *     session.createContext("ML-KEM", KeyUsage.ENCAPSULATE, kemPub);
 *
 * // Encrypt for multiple recipients; AES-256/GCM carries its own header.
 * MultiRecipientContent enc = MultiRecipientDataSourceBuilder.builder(session)
 *     .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
 *     .payloadKeyBytes(32)
 *     .addRecipient(rsaRecipient)
 *     .addRecipient(kemRecipient, 32, 16)
 *     .build(true);
 * enc.setInput(plainSource);
 *
 * // Decrypt with any one unlocking material; openers are installed by default.
 * MultiRecipientContent dec = MultiRecipientDataSourceBuilder.builder(session)
 *     .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
 *     .payloadKeyBytes(32)
 *     .unlockWith(new UnlockMaterial.Private(rsaPrv))
 *     .build(false);
 * dec.setInput(cipherSource);
 * }</pre>
 */
package zeroecho.sdk.guard;
