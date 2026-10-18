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
package zeroecho.pki.api.ca;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Command to create a new intermediate CA entity and issue its initial CA
 * credential.
 * Execution requires separate authorization and performs a fresh internal subject-key
 * proof under the same durable CA admission before signing the certificate.
 * Construction only validates structure; it neither generates keys nor verifies
 * possession, resolves retained evidence, or authorizes an operation.
 *
 * @param formatId   credential format id
 * @param issuerCaId issuer CA entity id, strict UTF-8 at most 4,096 bytes
 * @param subjectRef normalized subject reference for the intermediate
 * @param profileId  nonblank strict UTF-8 profile id, at most 256 bytes
 * @param keyRef     managed subject key, strict UTF-8 at most 1,048,576 bytes
 * @param attributes universal attributes (may be empty but not null)
 */
public record IntermediateCreateCommand(FormatId formatId, PkiId issuerCaId, SubjectRef subjectRef, String profileId,
        KeyRef keyRef, AttributeSet attributes) {

    /**
     * Creates an intermediate create command.
     *
     * @throws IllegalArgumentException if any component is null, bounded text is invalid
     */
    public IntermediateCreateCommand {
        CaCommandInputs.required(formatId);
        CaCommandInputs.identifier(issuerCaId);
        CaCommandInputs.required(subjectRef);
        CaCommandInputs.profile(profileId);
        CaCommandInputs.key(keyRef);
        CaCommandInputs.required(attributes);
    }

    /** Returns a diagnostic representation without command coordinates or attributes. */
    @Override public String toString() { return "IntermediateCreateCommand[redacted]"; }
}
