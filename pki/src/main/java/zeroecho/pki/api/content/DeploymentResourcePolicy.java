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
package zeroecho.pki.api.content;

import java.util.Objects;

/**
 * Immutable deployment-owned resource policy for streaming PKI operations.
 *
 * <p>
 * ZeroEcho provides no built-in operational values. A deployment explicitly
 * supplies every dimension as either unrestricted by deployment or positively
 * limited. Checks are incremental and do not alter algorithm, certificate or
 * binding semantics.
 * </p>
 *
 * @param acceptedSourceBytes   accepted input bytes
 * @param generatedObjectBytes generated signed-object bytes
 * @param entryCount            streamed entry count
 * @param stagedContentBytes    durable staged-content bytes
 * @param temporaryStorageBytes temporary spool bytes
 * @param publicationBytes      bytes supplied to a publisher
 * @param openStagedObjects     concurrently open staged objects
 */
public record DeploymentResourcePolicy(ResourceLimit acceptedSourceBytes, ResourceLimit generatedObjectBytes,
        ResourceLimit entryCount, ResourceLimit stagedContentBytes, ResourceLimit temporaryStorageBytes,
        ResourceLimit publicationBytes, ResourceLimit openStagedObjects) {

    /**
     * Creates a deployment resource policy.
     *
     * @throws NullPointerException if a dimension is {@code null}
     */
    public DeploymentResourcePolicy {
        Objects.requireNonNull(acceptedSourceBytes, "acceptedSourceBytes");
        Objects.requireNonNull(generatedObjectBytes, "generatedObjectBytes");
        Objects.requireNonNull(entryCount, "entryCount");
        Objects.requireNonNull(stagedContentBytes, "stagedContentBytes");
        Objects.requireNonNull(temporaryStorageBytes, "temporaryStorageBytes");
        Objects.requireNonNull(publicationBytes, "publicationBytes");
        Objects.requireNonNull(openStagedObjects, "openStagedObjects");
    }
}
