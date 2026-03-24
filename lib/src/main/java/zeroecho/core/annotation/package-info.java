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
 * Provides metadata contracts and annotations for cryptographic algorithms and
 * specifications.
 *
 * <p>
 * This package offers simple mechanisms for attaching human-readable labels to
 * classes, specifications, or capabilities. The metadata is intended for
 * display, diagnostics, and serialization, helping avoid exposure of internal
 * class names or verbose {@code toString()} output.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link Describable} - interface for supplying a concise, human-readable
 * description string.</li>
 * <li>{@link DisplayName} - annotation that associates a type with a stable,
 * human-friendly label preferred by catalogs and UIs.</li>
 * </ul>
 *
 * <h2>Usage notes</h2>
 * <ul>
 * <li>Annotate user-facing types with the display-name annotation to keep
 * labels stable even if class names change.</li>
 * <li>Have specification objects implement the description interface to provide
 * short, precise labels for configuration and documentation.</li>
 * <li>Consumers should prefer the display-name label when present; otherwise
 * use the provided description, then fall back to the class name.</li>
 * </ul>
 *
 * <h2>Design philosophy</h2>
 * <ul>
 * <li>Metadata must never include sensitive information such as keys or raw
 * secrets.</li>
 * <li>These constructs are for human-facing contexts (logs, configuration
 * dumps, UIs), not for protocol negotiation or security decisions.</li>
 * <li>Separating descriptive metadata from functional APIs keeps labels stable
 * and predictable without impacting core security behavior.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.annotation;
