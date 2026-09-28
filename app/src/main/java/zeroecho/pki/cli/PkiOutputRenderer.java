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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.json.JsonFactory;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;

/** Deterministic safe human and versioned machine result renderer. */
final class PkiOutputRenderer {

    private static final JsonFactory JSON_FACTORY = JsonFactory.builder().build();

    /* default */ void render(PkiPlanExecution execution, PkiOutputMode mode, boolean batch, OutputStream output)
            throws IOException {
        if (mode == PkiOutputMode.JSON) {
            renderJson(execution, batch, output);
        } else {
            renderHuman(execution, output);
        }
    }

    /* default */ void renderFailure(PkiOutputMode mode, String category, String code, OutputStream output)
            throws IOException {
        if (mode == PkiOutputMode.HUMAN) {
            PrintWriter writer = new PrintWriter(output, false, StandardCharsets.UTF_8);
            writer.println("PKI command: FAILED");
            writer.println("category: " + category);
            writer.println("code: " + code);
            writer.flush();
            return;
        }
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (JsonGenerator generator = JSON_FACTORY.createGenerator(ObjectWriteContext.empty(), encoded)) {
            generator.writeStartObject();
            generator.writeNumberProperty("version", 1);
            generator.writeStringProperty("status", "FAILED");
            generator.writeStringProperty("category", category);
            generator.writeStringProperty("code", code);
            generator.writeEndObject();
        } catch (JacksonException failure) {
            throw new IOException("Machine output generation failed", failure);
        }
        output.write(encoded.toByteArray());
        output.write('\n');
        output.flush();
    }

    private static void renderHuman(PkiPlanExecution execution, OutputStream output) {
        PrintWriter writer = new PrintWriter(output, false, StandardCharsets.UTF_8);
        writer.println("PKI plan: " + (execution.succeeded() ? "SUCCEEDED" : "FAILED"));
        if (execution.planFailure().isPresent()) {
            writer.println("code: " + execution.planCode().orElseThrow());
        }
        for (PkiPlanExecution.StepResult step : execution.steps()) {
            writer.println(step.id() + " " + step.operation() + " " + step.status());
            step.operationId().ifPresent(identity -> writer.println("  operationId: " + identity.value()));
            if (step.output().isPresent()) {
                for (Map.Entry<String, PkiOperationValue> field : step.output().orElseThrow().fields().entrySet()) {
                    writer.println("  " + field.getKey() + ": " + human(field.getValue()));
                }
            } else {
                step.code().ifPresent(code -> writer.println("  code: " + code));
            }
        }
        writer.flush();
    }

    private static void renderJson(PkiPlanExecution execution, boolean batch, OutputStream output) throws IOException {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (JsonGenerator generator = JSON_FACTORY.createGenerator(ObjectWriteContext.empty(), encoded)) {
            generator.writeStartObject();
            generator.writeNumberProperty("version", 1);
            generator.writeStringProperty("mode", batch ? "batch" : "single");
            generator.writeStringProperty("status", execution.succeeded() ? "SUCCEEDED" : "FAILED");
            if (execution.planFailure().isPresent()) {
                generator.writeStringProperty("failure", execution.planFailure().orElseThrow().name());
                generator.writeStringProperty("code", execution.planCode().orElseThrow());
            }
            generator.writeArrayPropertyStart("steps");
            for (PkiPlanExecution.StepResult step : execution.steps()) {
                writeStep(generator, step);
            }
            generator.writeEndArray();
            generator.writeEndObject();
        } catch (JacksonException failure) {
            throw new IOException("Machine output generation failed", failure);
        }
        output.write(encoded.toByteArray());
        output.write('\n');
        output.flush();
    }

    private static void writeStep(JsonGenerator generator, PkiPlanExecution.StepResult step) {
        generator.writeStartObject();
        generator.writeStringProperty("id", step.id());
        generator.writeStringProperty("operation", step.operation());
        generator.writeStringProperty("status", step.status().name());
        if (step.operationId().isPresent()) {
            generator.writeStringProperty("operationId", step.operationId().orElseThrow().value());
        }
        if (step.output().isPresent()) {
            generator.writeObjectPropertyStart("output");
            PkiOperationResult result = step.output().orElseThrow();
            for (Map.Entry<String, PkiOperationValue> field : result.fields().entrySet()) {
                generator.writeName(field.getKey());
                writeValue(generator, field.getValue());
            }
            generator.writeEndObject();
        } else {
            if (step.failure().isPresent()) {
                generator.writeStringProperty("failure", step.failure().orElseThrow().name());
            }
            generator.writeStringProperty("code", step.code().orElseThrow());
        }
        generator.writeEndObject();
    }

    private static void writeValue(JsonGenerator generator, PkiOperationValue value) {
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

    private static String human(PkiOperationValue value) {
        return switch (value) {
            case PkiOperationValue.Text text -> text.value();
            case PkiOperationValue.IntegerValue integer -> Long.toString(integer.value());
            case PkiOperationValue.BooleanValue bool -> Boolean.toString(bool.value());
            case PkiOperationValue.ObjectValue object -> "object(" + object.fields().size() + ")";
            case PkiOperationValue.ListValue list -> "list(" + list.values().size() + ")";
        };
    }
}
