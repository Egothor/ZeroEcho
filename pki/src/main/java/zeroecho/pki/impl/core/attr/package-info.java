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
 * Internal attribute-set implementation support for PKI core runtime services.
 *
 * <p>
 * This package contains lightweight internal implementations used to transport
 * and assemble {@link zeroecho.pki.api.attr.AttributeSet} values inside the PKI
 * core runtime. It is intended primarily for service-layer override handling,
 * backend input assembly, and persistence-friendly internal attribute
 * representation.
 * </p>
 *
 * <p>
 * The package is part of the PKI implementation layer and is not intended to be
 * the primary public extension surface for consumers. Public attribute
 * contracts remain defined in {@code zeroecho.pki.api.attr}.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li>immutability of produced attribute-set instances,</li>
 * <li>explicit and deterministic lookup semantics,</li>
 * <li>stable representation suitable for codec-based persistence,</li>
 * <li>minimal implementation complexity for internal runtime use.</li>
 * </ul>
 *
 * <h2>Semantics</h2>
 * <ul>
 * <li>Attribute identifiers are represented by
 * {@link zeroecho.pki.api.attr.AttributeId}.</li>
 * <li>Attribute values are represented by
 * {@link zeroecho.pki.api.attr.AttributeValue}.</li>
 * <li>Builder-based assembly preserves insertion order of identifiers.</li>
 * <li>For repeated builder writes to the same identifier, the most recently
 * written value list replaces the previous one.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Attributes carried through this package may contain operationally
 * sensitive metadata, runtime overrides, or backend wiring inputs.</li>
 * <li>Implementations using this package must not assume that attribute content
 * is safe for unrestricted logging.</li>
 * <li>The package provides transport and representation semantics only;
 * validation of attribute meaning, policy admissibility, and secrecy
 * requirements remains the responsibility of higher layers.</li>
 * </ul>
 */
package zeroecho.pki.impl.core.attr;
