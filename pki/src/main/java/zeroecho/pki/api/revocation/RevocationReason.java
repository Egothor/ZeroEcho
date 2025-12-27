/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.api.revocation;

/**
 * Revocation reason codes with PKIX-compatible semantics.
 *
 * <p>
 * Framework backends may map these reasons to framework-native reason codes.
 * </p>
 */
public enum RevocationReason {

    /**
     * Reason not specified.
     */
    UNSPECIFIED,

    /**
     * Subject private key is compromised.
     */
    KEY_COMPROMISE,

    /**
     * CA private key is compromised.
     */
    CA_COMPROMISE,

    /**
     * Subject affiliation has changed.
     */
    AFFILIATION_CHANGED,

    /**
     * Credential has been superseded by a newer one.
     */
    SUPERSEDED,

    /**
     * Subject has ceased operation.
     */
    CESSATION_OF_OPERATION,

    /**
     * Credential is temporarily on hold.
     */
    CERTIFICATE_HOLD,

    /**
     * Remove the credential from status list (unhold semantics).
     */
    REMOVE_FROM_CRL,

    /**
     * Privileges granted to the subject have been withdrawn.
     */
    PRIVILEGE_WITHDRAWN,

    /**
     * Attribute authority is compromised.
     */
    AA_COMPROMISE
}
