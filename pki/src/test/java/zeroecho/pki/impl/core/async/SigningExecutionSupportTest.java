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
package zeroecho.pki.impl.core.async;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;

final class SigningExecutionSupportTest {

    @Test
    void rethrowsStoreWideDurabilityFailureFromTheTypedReason() {
        PkiException failure = new PkiException("Store durability unconfirmed",
                PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);

        PkiException rethrown = assertThrows(PkiException.class,
                () -> SigningExecutionSupport.rethrowStoreWideFailure(failure));
        assertSame(failure, rethrown);
    }

    @Test
    void rethrowsWhenTheTypedReasonIsCarriedByACause() {
        PkiException durable = new PkiException("Store durability unconfirmed",
                PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
        IllegalStateException wrapped = new IllegalStateException("wrapped", durable);

        IllegalStateException rethrown = assertThrows(IllegalStateException.class,
                () -> SigningExecutionSupport.rethrowStoreWideFailure(wrapped));
        assertSame(wrapped, rethrown);
    }

    @Test
    void doesNotRethrowFromDiagnosticMessageTextAlone() {
        // The failure carries the durability code only in its message, not as a typed
        // reason; the structural check must ignore it and let it be reclassified.
        PkiException textOnly = new PkiException(
                "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");

        assertDoesNotThrow(() -> SigningExecutionSupport.rethrowStoreWideFailure(textOnly));
    }
}
