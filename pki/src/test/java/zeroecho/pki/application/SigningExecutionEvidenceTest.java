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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/** Closed round-trip of the terminal signing (key-usage) evidence vocabulary (Task 8a signing slice). */
class SigningExecutionEvidenceTest {

    @Test
    void roundTripsSigned() {
        SigningExecutionEvidence evidence = SigningExecutionEvidence.terminal("realm.ca-a", "ab".repeat(32),
                "COMPONENT", "issuance-bus", Optional.of("SIGNED"), SigningExecutionEvidence.Outcome.SIGNED);
        SigningExecutionEvidence decoded = SigningExecutionEvidence.decode(evidence.attributes()).orElseThrow();
        assertEquals(evidence, decoded);
        assertEquals("realm.ca-a", decoded.namespace());
        assertEquals(SigningExecutionEvidence.Outcome.SIGNED, decoded.outcome());
    }

    @Test
    void roundTripsFailedWithoutDetail() {
        SigningExecutionEvidence evidence = SigningExecutionEvidence.terminal("realm.ca-a", "ab".repeat(32),
                "COMPONENT", "issuance-bus", Optional.empty(), SigningExecutionEvidence.Outcome.FAILED);
        SigningExecutionEvidence decoded = SigningExecutionEvidence.decode(evidence.attributes()).orElseThrow();
        assertEquals(evidence, decoded);
        assertEquals(Optional.empty(), decoded.detailCode());
    }

    @Test
    void decodeReturnsEmptyWhenNoEvidencePresent() {
        assertTrue(SigningExecutionEvidence.decode(SimpleAttributeSet.builder().build()).isEmpty());
    }

    @Test
    void decodeRejectsPartialEvidence() {
        zeroecho.pki.api.attr.AttributeSet partial = SimpleAttributeSet.builder()
                .put(SigningExecutionEvidence.NAMESPACE,
                        new zeroecho.pki.api.attr.AttributeValue.StringValue("realm.ca-a"))
                .build();
        assertThrows(IllegalArgumentException.class, () -> SigningExecutionEvidence.decode(partial));
    }
}
