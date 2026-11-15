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
package zeroecho.pki.api.hybrid.sdk;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HybridSdkValueTest {

    @Test void typedReadsPreserveCanonicalBytesAndRejectWrongKinds() {
        var value=HybridSdkValue.object(java.util.Map.of("dates",HybridSdkValue.object(java.util.Map.of(
                "notBefore",HybridSdkValue.text("2026-11-14T12:00:00Z"),"version",HybridSdkValue.integer(Long.MAX_VALUE))),
                "label",HybridSdkValue.text(" Alice ")));
        byte[] encoded=value.encode();
        var fields=HybridSdkValue.decode(encoded).objectFields();
        assertEquals(" Alice ",fields.get("label").textValue());
        assertEquals("2026-11-14T12:00:00Z",fields.get("dates").objectFields().get("notBefore").textValue());
        assertEquals(Long.MAX_VALUE,fields.get("dates").objectFields().get("version").integerValue());
        assertArrayEquals(encoded,value.encode());
        assertThrows(UnsupportedOperationException.class,()->fields.put("extra",HybridSdkValue.integer(1)));
        assertThrows(IllegalArgumentException.class,()->value.textValue());
        assertThrows(IllegalArgumentException.class,()->value.integerValue());
        assertThrows(IllegalArgumentException.class,()->HybridSdkValue.text("no").objectFields());
        assertThrows(IllegalArgumentException.class,()->fields.get("label").integerValue());
        assertThrows(IllegalArgumentException.class,()->HybridSdkValue.integer(1).textValue());
    }
    @Test void canonicalizesEveryClosedValueTypeAndObjectKeyOrder() {
        var value = HybridSdkValue.object(Map.of("z", HybridSdkValue.bytes(new byte[] {1, 2}), "a",
                HybridSdkValue.list(List.of(HybridSdkValue.text("name"), HybridSdkValue.integer(-4), HybridSdkValue.bool(true)))));
        assertArrayEquals(value.encode(), HybridSdkValue.decode(value.encode()).encode());
        assertEquals(6, value.encode()[0]);
        assertThrows(IllegalArgumentException.class, () -> HybridSdkValue.text("bad\u0000text"));
        assertThrows(IllegalArgumentException.class, () -> HybridSdkValue.object(Map.of("non ascii é", value)));
        assertThrows(IllegalArgumentException.class, () -> HybridSdkValue.decode(new byte[] {3, 2}));
    }
    @Test void rejectsTrailingAndOversizedValuesAndExcessiveDepth() {
        assertThrows(IllegalArgumentException.class, () -> HybridSdkValue.decode(new byte[] {3, 1, 0}));
        assertThrows(IllegalArgumentException.class, () -> HybridSdkValue.bytes(new byte[262145]));
        var value = HybridSdkValue.text("");
        for (int i = 0; i < 7; i++) value = HybridSdkValue.list(List.of(value));
        var tooDeep = value;
        assertThrows(IllegalArgumentException.class, () -> HybridSdkValue.list(List.of(tooDeep)));
    }
}
