/*
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

package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import org.junit.jupiter.api.Test;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Local CLI parsing preserves distinct role overrides and strictly rejects forged head fields.
 */
class CliLifecycleArgumentsTest {
    /**
     * Checks lifecycle role overrides and rejects malformed command inputs.
     */
    @Test void parsesRoleOverridesAndRejectsInvalidInputs() {
        var parsed=CliLifecycleArguments.selection(Map.of("newAlternativeKeyRef",new PkiOperationValue.Text("managed:alt")));
        assertTrue(parsed.primary().isEmpty());assertEquals("managed:alt",parsed.alternative().orElseThrow().keyRef().orElseThrow().value());
        assertTrue(CliLifecycleArguments.head(Map.of()).isEmpty());
        assertThrows(IllegalArgumentException.class,()->CliLifecycleArguments.selection(Map.of("newKeyRef",new PkiOperationValue.IntegerValue(1))));
        assertThrows(IllegalArgumentException.class,()->CliLifecycleArguments.head(Map.of("expectedHead",new PkiOperationValue.ObjectValue(Map.of("actorId",new PkiOperationValue.Text("forged"))))));
        assertThrows(IllegalArgumentException.class,()->CliLifecycleArguments.text(Map.of(),"missing"));
    }
}
