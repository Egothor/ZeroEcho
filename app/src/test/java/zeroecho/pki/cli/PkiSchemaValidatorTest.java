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
package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonParser;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.JsonToken;
import tools.jackson.core.json.JsonFactory;
import zeroecho.pki.application.PkiOperationValue;

class PkiSchemaValidatorTest {
    @Test void bundledRootArrayLoadsEveryIdentityAndEnforcesRequiredFields() throws Exception {
        Method load = PkiSchemaValidator.class.getDeclaredMethod("loadSchema");
        load.setAccessible(true);
        Map<?, ?> index = (Map<?, ?>) load.invoke(null);
        Set<String> resourceIds = new java.util.HashSet<>();
        try (InputStream resource = PkiSchemaValidator.class.getClassLoader().getResourceAsStream("schema/operationSchema.json")) {
            assertNotNull(resource);
            try (JsonParser parser = new JsonFactory().createParser(ObjectReadContext.empty(), resource)) {
                assertEquals(JsonToken.START_ARRAY, parser.nextToken());
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    assertEquals(JsonToken.START_OBJECT, parser.currentToken());
                    while (parser.nextToken() != JsonToken.END_OBJECT) {
                        String name = parser.currentName(); parser.nextToken();
                        if (name.equals("operationId")) assertTrue(resourceIds.add(parser.getString()));
                        else parser.skipChildren();
                    }
                }
            }
        }
        assertEquals(resourceIds, index.keySet());
        assertTrue(resourceIds.containsAll(Set.of("backup.export", "backup.verify", "backup.restore", "inventory.status")));
        PkiOperationValue.ObjectValue empty = new PkiOperationValue.ObjectValue(Map.of());
        assertThrows(IllegalArgumentException.class, () -> PkiSchemaValidator.validateIfKnown("backup.verify", empty));
        assertThrows(IllegalArgumentException.class, () -> PkiSchemaValidator.validateIfKnown("security.approval.request", empty));
        assertDoesNotThrow(() -> PkiSchemaValidator.validateIfKnown("dashboard.server", empty));
        assertDoesNotThrow(() -> PkiSchemaValidator.validateIfKnown("future.operation", empty));
    }
}
