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
 * Public, framework-agnostic PKI API.
 *
 * <p>
 * This package provides stable entry points and core value types for operating
 * a PKI instance. The API is intentionally independent of any concrete
 * certificate framework (for example X.509), allowing multiple frameworks to be
 * integrated via SPIs in {@code zeroecho.pki.spi.*}.
 * </p>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li><strong>Framework independence:</strong> the API models PKI concepts (CA,
 * issuance, revocation, status objects, publication, backup/restore) without
 * binding to a single certificate technology.</li>
 * <li><strong>Explicit commands and queries:</strong> mutable operations are
 * expressed as command objects and retrieval via query objects in
 * subpackages.</li>
 * <li><strong>Safety and auditability:</strong> security-relevant operations
 * are designed to be auditable; sensitive data must never be exposed by API
 * abstractions.</li>
 * </ul>
 *
 * <h2>Key entry points</h2>
 * <ul>
 * <li>{@link zeroecho.pki.api.CaService}</li>
 * <li>{@link zeroecho.pki.api.CertificationRequestService}</li>
 * <li>{@link zeroecho.pki.api.IssuanceService}</li>
 * <li>{@link zeroecho.pki.api.RevocationService}</li>
 * <li>{@link zeroecho.pki.api.StatusObjectService}</li>
 * <li>{@link zeroecho.pki.api.PublicationService}</li>
 * <li>{@link zeroecho.pki.api.ProfileService}</li>
 * <li>{@link zeroecho.pki.api.PolicyService}</li>
 * <li>{@link zeroecho.pki.api.ImportExportService}</li>
 * <li>{@link zeroecho.pki.api.BackupService}</li>
 * </ul>
 *
 * <p>
 * Subpackages further organize domain models: {@code ca}, {@code issuance},
 * {@code request}, {@code revocation}, {@code status}, {@code publication},
 * {@code profile}, {@code policy}, {@code transfer}, plus attribute and audit
 * domains in {@code attr} and {@code audit}.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.pki.api;
