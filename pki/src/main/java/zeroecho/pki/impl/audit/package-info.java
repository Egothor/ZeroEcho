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
 * Audit logging reference implementations for ZeroEcho PKI.
 *
 * <h2>Scope</h2>
 * <p>
 * This package provides concrete implementations of the audit runtime, based on
 * the public API {@code zeroecho.pki.api.audit.*} and the SPI
 * {@code zeroecho.pki.spi.AuditSink}.
 * </p>
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li><strong>No secrets in logs:</strong> JUL logs never include audit payload
 * maps, attribute values, keys, seeds, plaintext, or other sensitive
 * material.</li>
 * <li><strong>No secrets by default:</strong> reference sinks avoid printing
 * {@link zeroecho.pki.api.audit.AuditEvent#details()} unless explicitly
 * required by a custom sink implementation.</li>
 * <li><strong>Fail-fast recording:</strong> sink failures are propagated to the
 * caller to avoid silent audit loss.</li>
 * </ul>
 *
 * <h2>Determinism</h2>
 * <ul>
 * <li>Search results are deterministically sorted.</li>
 * <li>Stable event identifiers are derived from canonicalized content
 * (SHA-256).</li>
 * <li>File enumeration is deterministic (lexicographic order).</li>
 * </ul>
 *
 * <h2>Persistence</h2>
 * <p>
 * {@link zeroecho.pki.impl.audit.FileAuditSink} provides a baseline persistent
 * store using daily gzip files and sequential scanning. It is suitable as an
 * initial production-grade implementation without introducing a database.
 * </p>
 */
package zeroecho.pki.impl.audit;
