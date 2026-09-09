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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

final class FsPkiStoreOptionsTest {

    @Test
    void residentIndexBudgetAcceptsValuesAboveDefault() {
        long configured = 768L * 1024L * 1024L;
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults()
                .withSigningResidentIndexBudgetBytes(configured);
        assertEquals(configured, options.signingResidentIndexBudgetBytes());
        assertEquals(512L * 1024L * 1024L,
                FsPkiStoreOptions.defaults().signingResidentIndexBudgetBytes());
        assertEquals(512L * 1024L * 1024L,
                FsPkiStoreOptions.defaults().signingCompactionTransientBudgetBytes());
        assertEquals(1024L * 1024L * 1024L, Math.addExact(
                FsPkiStoreOptions.defaults().signingResidentIndexBudgetBytes(),
                FsPkiStoreOptions.defaults().signingCompactionTransientBudgetBytes()));
    }

    @Test
    void residentIndexBudgetMustBePositive() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningResidentIndexBudgetBytes(0L));
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningResidentIndexBudgetBytes(-1L));
    }

    @Test
    void compactionTransientBudgetMustBePositiveAndCombinedEnvelopeMustNotOverflow() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningCompactionTransientBudgetBytes(0L));
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningCompactionTransientBudgetBytes(-1L));
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningResidentIndexBudgetBytes(Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningCompactionTransientBudgetBytes(Long.MAX_VALUE));
    }
}
