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
package zeroecho.pki.cli;

import java.util.Map;

import tools.jackson.core.JsonGenerator;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Deterministic writer for the closed {@link PkiOperationValue} model.
 *
 * <p>The model is restricted to text, integer, boolean, object, and list nodes
 * (no floats, no {@code null}), which matches the strict JSON contract shared by
 * the CLI and the {@code pki-server} admin API.</p>
 */
final class PkiCliValueJson {

    private PkiCliValueJson() {
    }

    /**
     * Writes one value node using the supplied generator.
     *
     * @param generator active JSON generator
     * @param value closed value node
     */
    /* default */ static void writeValue(JsonGenerator generator, PkiOperationValue value) {
        switch (value) {
            case PkiOperationValue.Text text -> generator.writeString(text.value());
            case PkiOperationValue.IntegerValue integer -> generator.writeNumber(integer.value());
            case PkiOperationValue.BooleanValue bool -> generator.writeBoolean(bool.value());
            case PkiOperationValue.ObjectValue object -> {
                generator.writeStartObject();
                for (Map.Entry<String, PkiOperationValue> entry : object.fields().entrySet()) {
                    generator.writeName(entry.getKey());
                    writeValue(generator, entry.getValue());
                }
                generator.writeEndObject();
            }
            case PkiOperationValue.ListValue list -> {
                generator.writeStartArray();
                for (PkiOperationValue entry : list.values()) {
                    writeValue(generator, entry);
                }
                generator.writeEndArray();
            }
        }
    }

    /**
     * Renders one value node as a single safe human-readable scalar line.
     *
     * @param value closed value node
     * @return short deterministic human representation
     */
    /* default */ static String human(PkiOperationValue value) {
        return switch (value) {
            case PkiOperationValue.Text text -> text.value();
            case PkiOperationValue.IntegerValue integer -> Long.toString(integer.value());
            case PkiOperationValue.BooleanValue bool -> Boolean.toString(bool.value());
            case PkiOperationValue.ObjectValue object -> "object(" + object.fields().size() + ")";
            case PkiOperationValue.ListValue list -> "list(" + list.values().size() + ")";
        };
    }
}
