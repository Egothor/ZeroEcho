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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class PkiFailureTest {

    @Test
    void retainsValidClassificationAndCodeWithValueEquality() {
        PkiFailure failure = new PkiFailure(PkiFailureClassification.VALIDATION_FAILURE,
                PkiFailureCode.VALIDATION_FAILURE);

        assertEquals(PkiFailureClassification.VALIDATION_FAILURE, failure.classification());
        assertEquals(PkiFailureCode.VALIDATION_FAILURE, failure.code());
        assertEquals(failure,
                new PkiFailure(PkiFailureClassification.VALIDATION_FAILURE,
                        PkiFailureCode.VALIDATION_FAILURE));
        assertEquals(failure.hashCode(),
                new PkiFailure(PkiFailureClassification.VALIDATION_FAILURE,
                        PkiFailureCode.VALIDATION_FAILURE).hashCode());
        assertNotEquals(failure,
                new PkiFailure(PkiFailureClassification.VALIDATION_FAILURE,
                        PkiFailureCode.CAPABILITY_NOT_CONFIGURED));
    }

    @Test
    void everyCanonicalCodeDeclaresItsOnlyValidClassification() {
        for (PkiFailureCode code : PkiFailureCode.values()) {
            PkiFailure failure = new PkiFailure(code.classification(), code);
            assertEquals(code.classification(), failure.classification());
            assertEquals(code, failure.code());
        }
    }

    @Test
    void rejectsNullAndInconsistentFailureComponents() {
        assertThrows(NullPointerException.class,
                () -> new PkiFailure(null, PkiFailureCode.INTERNAL_FAILURE));
        assertThrows(NullPointerException.class,
                () -> new PkiFailure(PkiFailureClassification.INTERNAL_FAILURE, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PkiFailure(PkiFailureClassification.INTERNAL_FAILURE,
                        PkiFailureCode.NOT_FOUND));
    }

    @Test
    void arbitraryWellFormedTokenCannotBecomeFailureCode() {
        assertThrows(IllegalArgumentException.class,
                () -> PkiFailureCode.valueOf("PRIVATE_KEY_0123456789ABCDEF"));
    }

    @Test
    void exceptionRetainsFailureAndBuildsOnlySafeMessage() {
        PkiFailure failure = new PkiFailure(PkiFailureClassification.NOT_FOUND,
                PkiFailureCode.NOT_FOUND);
        PkiFailureException exception = new PkiFailureException(failure);

        assertSame(failure, exception.failure());
        assertEquals("PKI failure: classification=NOT_FOUND, code=NOT_FOUND", exception.getMessage());
        assertTrue(exception.toString().contains("classification=NOT_FOUND, code=NOT_FOUND"));
    }

    @Test
    void directExceptionTextIsSafeWhileThrowableGraphRemainsSensitive() {
        String hostileText = "hostile-input-private-key-material";
        String suppressedText = "suppressed-provider-private-detail";
        IllegalStateException cause = new IllegalStateException(hostileText);
        cause.setStackTrace(new StackTraceElement[] {
                new StackTraceElement("ProviderInternal", "privateKeyOperation", "ProviderInternal.java", 41)
        });
        PkiFailure failure = new PkiFailure(PkiFailureClassification.INTERNAL_FAILURE,
                PkiFailureCode.INTERNAL_FAILURE);
        PkiFailureException exception = new PkiFailureException(failure, cause);
        exception.addSuppressed(new IllegalArgumentException(suppressedText));

        assertSame(failure, exception.failure());
        assertSame(cause, exception.getCause());
        assertFalse(exception.getMessage().contains(hostileText));
        assertFalse(exception.toString().contains(hostileText));
        assertFalse(exception.getMessage().contains(suppressedText));
        assertFalse(exception.toString().contains(suppressedText));
        assertEquals(hostileText, exception.getCause().getMessage());
        assertEquals("privateKeyOperation", exception.getCause().getStackTrace()[0].getMethodName());
        assertEquals(suppressedText, exception.getSuppressed()[0].getMessage());
        assertEquals("PKI failure: classification=INTERNAL_FAILURE, code=INTERNAL_FAILURE",
                exception.getMessage());
    }

    @Test
    void exceptionRejectsNullFailureAndCause() {
        PkiFailure failure = new PkiFailure(PkiFailureClassification.INTERNAL_FAILURE,
                PkiFailureCode.INTERNAL_FAILURE);

        assertThrows(NullPointerException.class, () -> new PkiFailureException(null));
        assertThrows(NullPointerException.class, () -> new PkiFailureException(null,
                new IllegalStateException("ignored")));
        assertThrows(NullPointerException.class, () -> new PkiFailureException(failure, null));
    }
}
