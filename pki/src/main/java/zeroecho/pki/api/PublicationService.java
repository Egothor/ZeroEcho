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

import java.util.Optional;

import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationQuery;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationResult;

/**
 * Publication and distribution operations.
 *
 * <p>
 * Publishing is an explicit operation enabling parity with established PKI
 * systems. Implementations publish committed credential and status-object
 * content to administrator-configured targets such as filesystem mirrors, LDAP
 * directories, HTTP endpoints, or object stores. Publication never establishes
 * source-object authority.
 * </p>
 */
public interface PublicationService extends AutoCloseable {

    /**
     * Registers one publication operation after its source object is committed.
     *
     * @param request immutable registration request
     * @return committed pending record, or the identical existing operation
     * @throws IllegalArgumentException if the request is invalid or conflicting
     * @throws PkiException if registration cannot be established durably
     */
    PublicationRecord register(PublicationRequest request);

    /**
     * Processes one pending operation synchronously.
     *
     * @param publicationId operation identity
     * @return durably classified result
     * @throws IllegalArgumentException if the operation is absent or ineligible
     * @throws PkiException if persistence or content validation fails
     */
    PublicationResult process(PkiId publicationId);

    /**
     * Explicitly retries one retryable operation as a new numbered attempt.
     *
     * @param publicationId operation identity
     * @return durably classified result
     * @throws IllegalArgumentException if the operation is not retryable
     * @throws PkiException if persistence or content validation fails
     */
    PublicationResult retry(PkiId publicationId);

    /**
     * Reconciles one unknown external outcome using the original attempt token.
     *
     * @param publicationId operation identity
     * @return current durable result; unresolved operations remain unknown
     * @throws IllegalArgumentException if the operation is not unknown
     * @throws PkiException if reconciliation persistence fails
     */
    PublicationResult reconcile(PkiId publicationId);

    /**
     * Reads one durable publication operation.
     *
     * @param publicationId operation identity
     * @return current record, or empty when absent
     */
    Optional<PublicationRecord> find(PkiId publicationId);

    /**
     * Opens a stable lazy query over publication operations.
     *
     * @param query finite query constraints
     * @return closeable cursor
     * @throws PkiException if the stable view cannot be opened
     */
    PublicationCursor openPublications(PublicationQuery query);

    /** Rejects new operations while allowing an in-flight synchronous call to classify its result. */
    @Override
    void close();
}
