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
import zeroecho.pki.application.PkiOperationValue;

/** Deterministic safe renderer for a remote admin-API operation outcome. */
final class PkiRemoteReporter {

    private static final JsonFactory JSON_FACTORY = JsonFactory.builder().build();

    /**
     * Renders one terminal (or wait-exhausted) remote result.
     *
     * @param result remote result
     * @param mode selected output representation
     * @param output exclusive result output stream
     * @throws IOException if machine output generation fails
     */
    /* default */ void render(PkiRemoteResult result, PkiOutputMode mode, OutputStream output) throws IOException {
        if (mode == PkiOutputMode.JSON) {
            renderJson(result, output);
        } else {
            renderHuman(result, output);
        }
    }

    private static void renderHuman(PkiRemoteResult result, OutputStream output) {
        PrintWriter writer = new PrintWriter(output, false, StandardCharsets.UTF_8);
        writer.println("PKI operation: " + status(result));
        writer.println("operation: " + result.operation());
        switch (result) {
            case PkiRemoteResult.Succeeded success -> {
                success.operationId().ifPresent(id -> writer.println("  operationId: " + id));
                for (Map.Entry<String, PkiOperationValue> field : success.result().fields().entrySet()) {
                    writer.println("  " + field.getKey() + ": " + PkiCliValueJson.human(field.getValue()));
                }
            }
            case PkiRemoteResult.Pending pending -> {
                writer.println("  code: OPERATION_PENDING");
                writer.println("  operationId: " + pending.operationId());
                pending.observationFailure().ifPresent(failure -> {
                    writer.println("  observationFailure: " + failure.classification());
                    writer.println("  observationCode: " + failure.code());
                });
            }
            case PkiRemoteResult.ApprovalRequired approval -> {
                writer.println("  code: APPROVAL_REQUIRED");
                writer.println("  operationCommitment: " + approval.operationCommitment());
            }
            case PkiRemoteResult.Failed failure -> {
                failure.operationId().ifPresent(id -> writer.println("  operationId: " + id));
                writer.println("  classification: " + failure.classification());
                writer.println("  code: " + failure.code());
                writer.println("  recoveryRequired: " + failure.recoveryRequired());
                writer.println("  reconciliationRequired: " + failure.reconciliationRequired());
            }
        }
        writer.flush();
    }

    private static void renderJson(PkiRemoteResult result, OutputStream output) throws IOException {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (JsonGenerator generator = JSON_FACTORY.createGenerator(ObjectWriteContext.empty(), encoded)) {
            generator.writeStartObject();
            generator.writeNumberProperty("version", 1);
            generator.writeStringProperty("mode", "remote");
            generator.writeStringProperty("status", status(result));
            generator.writeStringProperty("operation", result.operation());
            switch (result) {
                case PkiRemoteResult.Succeeded success -> {
                    success.operationId().ifPresent(id -> generator.writeStringProperty("operationId", id));
                    generator.writeName("result");
                    PkiCliValueJson.writeValue(generator, success.result());
                }
                case PkiRemoteResult.Pending pending -> {
                    generator.writeStringProperty("operationId", pending.operationId());
                    pending.observationFailure().ifPresent(failure -> {
                        generator.writeObjectPropertyStart("observationFailure");
                        generator.writeStringProperty("classification", failure.classification());
                        generator.writeStringProperty("code", failure.code());
                        generator.writeEndObject();
                    });
                }
                case PkiRemoteResult.ApprovalRequired approval ->
                    generator.writeStringProperty("operationCommitment", approval.operationCommitment());
                case PkiRemoteResult.Failed failure -> {
                    failure.operationId().ifPresent(id -> generator.writeStringProperty("operationId", id));
                    generator.writeStringProperty("failure", failure.classification());
                    generator.writeStringProperty("code", failure.code());
                    generator.writeBooleanProperty("recoveryRequired", failure.recoveryRequired());
                    generator.writeBooleanProperty("reconciliationRequired", failure.reconciliationRequired());
                }
            }
            generator.writeEndObject();
        } catch (JacksonException failure) {
            throw new IOException("Machine output generation failed", failure);
        }
        output.write(encoded.toByteArray());
        output.write('\n');
        output.flush();
    }

    private static String status(PkiRemoteResult result) {
        return switch (result) {
            case PkiRemoteResult.Succeeded ignored -> "SUCCEEDED";
            case PkiRemoteResult.Pending ignored -> "PENDING";
            case PkiRemoteResult.ApprovalRequired ignored -> "APPROVAL_REQUIRED";
            case PkiRemoteResult.Failed ignored -> "FAILED";
        };
    }
}
