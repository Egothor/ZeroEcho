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
/**
 * Internal credential key-possession proof profiles.
 *
 * <p>The signature profile follows the established signature-based proof-of-
 * possession principle used by CRMF, while defining a ZeroEcho-internal
 * transcript. It does not claim to be a CRMF, CMP, CMC, or other standardized
 * endpoint or wire representation.</p>
 *
 * <p>Transcript version 1 starts with ASCII {@code ZEPP}, an unsigned two-byte
 * field count, and nine ordered fields. Every field is encoded as a one-byte tag,
 * a four-byte unsigned big-endian length, and its value. The fields bind:</p>
 * <ol>
 * <li>four-byte big-endian version {@code 1};</li>
 * <li>ASCII purpose {@code credential-key-possession-confirmation};</li>
 * <li>the canonical realm identifier;</li>
 * <li>the UTF-8 server audience;</li>
 * <li>the exact {@code x509:} SHA-256 credential identifier of canonical DER;</li>
 * <li>the versioned proof-suite identifier;</li>
 * <li>the 32-byte SHA-256 suite-configuration commitment;</li>
 * <li>the 32-byte random challenge;</li>
 * <li>expiry as an eight-byte epoch second and four-byte nanosecond value.</li>
 * </ol>
 *
 * <p>Verification decodes and canonically re-encodes the complete bounded
 * transcript for each request and retains no verifier capability or request
 * state after return. The package is an internal foundation only. It provides
 * no endpoint, persistence, registry discovery, challenge retention, or
 * lifecycle transition.</p>
 */
package zeroecho.pki.server.confirmation;
