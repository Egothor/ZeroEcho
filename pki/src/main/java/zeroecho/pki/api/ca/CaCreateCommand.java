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

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Command to create a new root CA entity and issue its initial CA credential.
 *
 * <p>
 * The managed key is mandatory; construction neither generates keys nor proves
 * possession or authorizes creation. Execution must authorize the operation
 * separately and verify a fresh self-signature against the same frozen canonical
 * SubjectPublicKeyInfo used for the new credential. No retained proof substitutes
 * for this fresh root self-signature.
 * </p>
 *
 * @param formatId   target credential format
 * @param subjectRef normalized CA subject reference
 * @param profileId  nonblank strict UTF-8 profile id, at most 256 bytes
 * @param keyRef     existing managed key, nonblank strict UTF-8, at most 1,048,576 bytes
 * @param attributes universal attributes (may be empty but not null)
 */
public record CaCreateCommand(FormatId formatId, SubjectRef subjectRef, String profileId, KeyRef keyRef,
        AttributeSet attributes) {

    /**
     * Creates a CA create command.
     *
     * @throws IllegalArgumentException if any component is null or bounded text is invalid
     */
    public CaCreateCommand {
        CaCommandInputs.required(formatId);
        CaCommandInputs.required(subjectRef);
        CaCommandInputs.profile(profileId);
        CaCommandInputs.key(keyRef);
        CaCommandInputs.required(attributes);
    }

    /** Returns a diagnostic representation without command coordinates or attributes. */
    @Override public String toString() { return "CaCreateCommand[redacted]"; }
}
