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
 * Filesystem-based reference implementation of the PKI persistence layer.
 *
 * <p>
 * This package provides a deterministic, auditable, and strictly defined
 * filesystem-backed implementation of the {@code PkiStore} SPI. It is intended
 * as a <em>reference implementation</em> and a correctness baseline rather than
 * a high-performance backend.
 * </p>
 *
 * <h2>Design principles</h2>
 *
 * <ul>
 * <li><strong>Deterministic layout</strong> – all persisted objects are stored
 * in a stable, predictable directory structure.</li>
 * <li><strong>Write-once semantics</strong> – immutable domain objects are
 * never overwritten; attempts to do so result in explicit failures.</li>
 * <li><strong>Auditable mutation</strong> – mutable objects are versioned using
 * append-only history with timestamped entries.</li>
 * <li><strong>Atomic updates</strong> – all writes use a write-to-temp +
 * move-into-place strategy based on NIO.</li>
 * <li><strong>Closed current schema</strong> – persisted values use fixed type
 * identifiers and compile-time codecs. Java class names are never persisted or
 * resolved, nested collections have exact element schemas, and attribute sets
 * are stored structurally and decoded to the canonical core
 * implementation.</li>
 * <li><strong>Strict snapshot semantics</strong> – snapshot export reconstructs
 * a complete store state for a given point in time and fails explicitly if no
 * valid history entry exists.</li>
 * <li><strong>No hidden magic</strong> – behavior is explicit, observable, and
 * suitable for forensic analysis.</li>
 * </ul>
 *
 * <h2>Time travel and snapshots</h2>
 *
 * <p>
 * History directories retain timestamped versions of mutable records. Snapshot
 * export reconstructs a new store root by selecting, for each mutable entity,
 * the latest history entry whose timestamp is less than or equal to the
 * requested snapshot instant.
 * </p>
 *
 * <p>
 * If no such entry exists for any required object, snapshot export fails with
 * an exception. This strict behavior ensures that snapshots never represent
 * states that did not exist in reality.
 * </p>
 *
 * <h2>Security considerations</h2>
 *
 * <ul>
 * <li>No private keys or secret material are persisted.</li>
 * <li>No encryption at rest is performed (by design, for this reference
 * implementation).</li>
 * <li>Logging uses {@code java.util.logging} exclusively and never includes
 * sensitive domain data.</li>
 * <li>The codec performs no runtime class loading or reflective construction.
 * Earlier pre-release persistence formats are rejected rather than
 * migrated.</li>
 * </ul>
 *
 * <h2>Scope</h2>
 *
 * <p>
 * This package is <strong>not</strong> part of the public PKI API. It may
 * evolve independently and may be replaced or complemented by other persistence
 * backends (e.g. database-backed implementations).
 * </p>
 */
package zeroecho.pki.impl.fs;
