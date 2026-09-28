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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.spi.ProviderConfig;

final class PkiOperationExecutorTest {

    @Test
    void executesRetainedConfigurationProfileAndBindingOperations(@TempDir Path temporary) throws Exception {
        try (PkiSession session = PkiSession.open(configuration(temporary))) {
            PkiOperationExecutor executor = session.operations();
            assertInstanceOf(PkiOperationOutcome.Completed.class,
                    executor.execute(new PkiOperation.ValidateConfiguration(), CancellationSignal.NONE));

            byte[] profile = BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())
                    .getFirst().canonicalJson();
            PkiOperationOutcome profileOutcome = executor.execute(
                    new PkiOperation.ValidateProfile(profile), CancellationSignal.NONE);
            assertEquals(new PkiOperationValue.BooleanValue(true),
                    assertInstanceOf(PkiOperationOutcome.Completed.class, profileOutcome)
                            .result().field("valid").orElseThrow());

            PkiOperationOutcome bindings = executor.execute(
                    new PkiOperation.ListAlgorithmBindings(Optional.empty(), Optional.empty(), 100),
                    CancellationSignal.NONE);
            assertTrue(assertInstanceOf(PkiOperationOutcome.Completed.class, bindings)
                    .result().field("bindings").isPresent());
        }
    }

    @Test
    void classifiesMissingPublicationAndCancellationWithoutThrowableDetails(@TempDir Path temporary)
            throws Exception {
        try (PkiSession session = PkiSession.open(configuration(temporary))) {
            PkiOperationOutcome missing = session.operations().execute(
                    new PkiOperation.InspectPublication(new PkiId("missing")), CancellationSignal.NONE);
            PkiOperationOutcome.Failed missingFailure = assertInstanceOf(PkiOperationOutcome.Failed.class, missing);
            assertEquals(PkiOperationFailure.NOT_FOUND, missingFailure.classification());

            PkiOperationOutcome cancelled = session.operations().execute(
                    new PkiOperation.ValidateConfiguration(), () -> true);
            PkiOperationOutcome.Failed cancelledFailure = assertInstanceOf(PkiOperationOutcome.Failed.class,
                    cancelled);
            assertEquals(PkiOperationFailure.CANCELLED, cancelledFailure.classification());
            assertEquals("OPERATION_CANCELLED", cancelledFailure.code());
        }
    }

    @Test
    void validatesAndDefensivelyCopiesOperationInput() {
        byte[] document = new byte[] { 1, 2, 3 };
        PkiOperation.ValidateProfile operation = new PkiOperation.ValidateProfile(document);
        document[0] = 9;
        assertEquals(1, operation.document()[0]);
        byte[] returned = operation.document();
        returned[0] = 8;
        assertEquals(1, operation.document()[0]);

        assertThrows(IllegalArgumentException.class,
                () -> new PkiOperation.ListAlgorithmBindings(Optional.empty(), Optional.empty(), 0));
        assertThrows(IllegalArgumentException.class,
                () -> new PkiOperation.ValidateAlgorithmBindings(Optional.of("binding"), Optional.empty()));
    }

    private static PkiSessionConfiguration configuration(Path temporary) {
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporary.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());
    }
}
