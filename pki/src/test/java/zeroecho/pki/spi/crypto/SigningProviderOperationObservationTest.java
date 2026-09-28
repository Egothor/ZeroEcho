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

package zeroecho.pki.spi.crypto;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SigningProvider.DetailCode;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;
import zeroecho.pki.spi.crypto.SigningProvider.OperationObservation;

final class SigningProviderOperationObservationTest {
    private static final PkiId OPERATION_ID = new PkiId("observation-operation");
    private static final Instant UPDATED_AT = Instant.parse("2026-09-10T08:00:00Z");
    private static final Optional<EncodedObject> SIGNATURE =
            Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 1 }));

    @Test
    void acceptsOnlyCoherentStateAndDetailPairs() {
        for (ObservationState state : ObservationState.values()) {
            for (DetailCode detail : DetailCode.values()) {
                Optional<EncodedObject> signature = state == ObservationState.SUCCEEDED
                        ? SIGNATURE : Optional.empty();
                if (matches(state, detail)) {
                    assertDoesNotThrow(() -> new OperationObservation(
                            OPERATION_ID, state, UPDATED_AT, detail, signature));
                } else {
                    assertThrows(IllegalArgumentException.class, () -> new OperationObservation(
                            OPERATION_ID, state, UPDATED_AT, detail, signature));
                }
            }
        }
    }

    @Test
    void signaturePresenceMustExactlyMatchSuccess() {
        assertThrows(IllegalArgumentException.class, () -> new OperationObservation(OPERATION_ID,
                ObservationState.SUCCEEDED, UPDATED_AT, DetailCode.SIGNED, Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new OperationObservation(OPERATION_ID,
                ObservationState.FAILED, UPDATED_AT, DetailCode.DENIED, SIGNATURE));
    }

    private static boolean matches(ObservationState state, DetailCode detail) {
        return switch (state) {
            case PENDING -> detail == DetailCode.PENDING;
            case RETRYABLE_UNKNOWN -> detail == DetailCode.RETRYABLE_UNKNOWN;
            case SUCCEEDED -> detail == DetailCode.SIGNED;
            case CANCELLED -> detail == DetailCode.CANCELLED;
            case UNRECOVERABLE -> detail == DetailCode.LOCAL_RESTART_UNRECOVERABLE
                    || detail == DetailCode.PROVIDER_RESULT_INVALID;
            case FAILED -> detail == DetailCode.DENIED
                    || detail == DetailCode.PROVIDER_RESULT_INVALID
                    || detail == DetailCode.INVALID_KEY_REFERENCE
                    || detail == DetailCode.INVALID_ALGORITHM
                    || detail == DetailCode.ALGORITHM_MISMATCH
                    || detail == DetailCode.KEY_NOT_FOUND
                    || detail == DetailCode.CONTENT_INTEGRITY_FAILURE
                    || detail == DetailCode.UNSUPPORTED_SIGNATURE_ENCODING
                    || detail == DetailCode.KEYRING_IO_FAILURE
                    || detail == DetailCode.CRYPTO_FAILURE
                    || detail == DetailCode.DEADLINE_EXPIRED;
        };
    }
}
