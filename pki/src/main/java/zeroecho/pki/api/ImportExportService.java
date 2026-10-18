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
package zeroecho.pki.api;

import zeroecho.pki.api.transfer.ExportArtifact;
import zeroecho.pki.api.transfer.ExportFormat;
import zeroecho.pki.api.transfer.ExportQuery;
import zeroecho.pki.api.transfer.ImportPolicy;

/**
 * Import and export operations for migration and interoperability.
 *
 * <p>
 * Import does not imply trust; it is a controlled operation governed by policy.
 * Import/export is expected to be auditable.
 * </p>
 */
public interface ImportExportService {

    /**
     * Imports an issued credential payload into inventory.
     *
     * @param formatId   credential format id
     * @param credential encoded credential payload
     * @param policy     import policy
     * @return imported credential id
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if import fails
     */
    PkiId importCredential(FormatId formatId, EncodedObject credential, ImportPolicy policy);

    /**
     * Imports a CA certificate payload into an existing CA entity's credential set.
     *
     * @param caId          CA entity id
     * @param caCertificate CA certificate payload
     * @param policy        import policy
     * @return imported credential id
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if import fails
     */
    PkiId importCaCertificate(PkiId caId, EncodedObject caCertificate, ImportPolicy policy);

    /**
     * Exports credentials matching the query constraints in the requested export
     * format.
     *
     * @param query  export query
     * @param format export format
     * @return export artifact
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if export fails
     */
    ExportArtifact exportCredentials(ExportQuery query, ExportFormat format);

    /**
     * Exports revocation records matching the query constraints in the requested
     * export format.
     *
     * @param query  export query
     * @param format export format
     * @return export artifact
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if export fails
     */
    ExportArtifact exportRevocations(ExportQuery query, ExportFormat format);

    /**
     * Exports CA materials for a given CA entity in the requested export format.
     *
     * @param caId   CA entity id
     * @param format export format
     * @return export artifact
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if export fails
     */
    ExportArtifact exportCa(PkiId caId, ExportFormat format);
}
