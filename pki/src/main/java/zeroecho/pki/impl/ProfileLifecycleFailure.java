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
package zeroecho.pki.impl;

import zeroecho.pki.api.PkiException;

/**
 * Internal typed classification for redacted profile lifecycle failures.
 */
public final class ProfileLifecycleFailure extends PkiException {
    private static final long serialVersionUID = -6689413907385449245L;

    /** Closed profile lifecycle failure codes. */
    public enum Code {
        PROFILE_DOCUMENT_INVALID, PROFILE_IMPORT_VALIDATION_FAILED, BUILT_IN_PROFILE_INVALID, PROFILE_VERSION_CONFLICT,
        PROFILE_KIND_CONFLICT, PROFILE_VERSION_CORRUPT, PROFILE_ACTIVE_POINTER_CORRUPT, PROFILE_HASH_MISMATCH,
        PROFILE_STORE_FAILURE, PROFILE_DURABILITY_UNCONFIRMED, PROFILE_IMPORT_FAILED, PROFILE_STATE_CORRUPT,
        PROFILE_VERSION_NOT_FOUND, PROFILE_ACTIVATION_FAILED, PROFILE_NOT_ACTIVE,
        // Stable public code is intentionally longer than PMD's naming threshold.
        @SuppressWarnings("PMD.LongVariable")
        PROFILE_ACTIVATION_HISTORY_UNAVAILABLE
    }

    private final Code code;

    /** Creates one cause-free failure with a stable code. */
    public ProfileLifecycleFailure(Code code) {
        super("Profile lifecycle operation failed: code=" + code);
        this.code = code;
    }

    /** @return stable failure classification */
    public Code code() {
        return code;
    }
}
