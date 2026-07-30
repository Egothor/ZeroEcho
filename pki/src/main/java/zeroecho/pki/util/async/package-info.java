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
 * Generic asynchronous operation bus with durable tracking and callback
 * dispatch.
 *
 * <p>
 * This package provides a reusable, strongly-typed abstraction for submitting
 * asynchronous operations, tracking their status, and delivering status changes
 * to registered callback handlers. It is intentionally generic: concrete
 * subsystems (e.g., PKI issuance, publishing, signing workflows) instantiate
 * the bus by selecting:
 * </p>
 *
 * <ul>
 * <li>operation identifier type (e.g., {@code PkiId}),</li>
 * <li>operation owner type (e.g., {@code Principal}),</li>
 * <li>endpoint identifier type (e.g., {@code String}),</li>
 * <li>result type (application-specific, may be empty).</li>
 * </ul>
 *
 * <h2>Durability model</h2>
 * <p>
 * The default reference implementation is append-only: it persists operation
 * snapshots and status transitions to a file log. On startup it replays the log
 * and then optionally re-synchronizes open operations by asking the endpoint
 * for their current status.
 * </p>
 *
 * <h2>Security</h2>
 * <ul>
 * <li>No secrets must be logged.</li>
 * <li>Persistence encodings should avoid plaintext secrets. If sensitive result
 * data exists, store it encrypted outside of this package or provide a redacted
 * {@code ResultCodec}.</li>
 * </ul>
 */
package zeroecho.pki.util.async;
