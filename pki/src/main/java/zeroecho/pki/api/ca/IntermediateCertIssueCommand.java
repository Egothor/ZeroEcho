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
package zeroecho.pki.api.ca;

import java.util.Optional;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Command to issue a new CA credential for an existing intermediate CA entity.
 *
 * <p>
 * This command supports cross-signing (issuing with a different issuer CA) and
 * renewal scenarios. The key is an expected current subject key, not a rotation
 * request. Execution must match it against authoritative subject state, authorize
 * issuance separately, and complete a fresh internal subject-key proof under the
 * same durable admission before certificate signing.
 * Construction does not resolve evidence, prove possession or grant authorization.
 * </p>
 *
 * @param formatId          credential format id
 * @param issuerCaId        issuer CA entity id, strict UTF-8 at most 4,096 bytes
 * @param subjectCaId       subject CA entity id, strict UTF-8 at most 4,096 bytes
 * @param profileId         nonblank strict UTF-8 profile id, at most 256 bytes
 * @param keyRef            expected current subject key, strict UTF-8 at most 1,048,576 bytes
 * @param requestedValidity optional requested validity (policy may
 *                          override/deny)
 * @param attributes        universal attributes (may be empty but not null)
 */
public record IntermediateCertIssueCommand(FormatId formatId, PkiId issuerCaId, PkiId subjectCaId, String profileId,
        KeyRef keyRef, Optional<Validity> requestedValidity, AttributeSet attributes) {

    /**
     * Creates an intermediate CA credential issuance command.
     *
     * @throws IllegalArgumentException if any component is null, bounded text is invalid
     */
    public IntermediateCertIssueCommand {
        CaCommandInputs.required(formatId);
        CaCommandInputs.identifier(issuerCaId);
        CaCommandInputs.identifier(subjectCaId);
        CaCommandInputs.profile(profileId);
        CaCommandInputs.key(keyRef);
        CaCommandInputs.required(requestedValidity);
        CaCommandInputs.required(attributes);
    }

    /** Returns a diagnostic representation without command coordinates or attributes. */
    @Override public String toString() { return "IntermediateCertIssueCommand[redacted]"; }
}
