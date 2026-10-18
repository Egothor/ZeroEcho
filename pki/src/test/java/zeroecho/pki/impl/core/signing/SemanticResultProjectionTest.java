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

package zeroecho.pki.impl.core.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.ACCESS;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.NOW;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.open;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.semantic;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.signing;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningScope;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.spi.store.PkiStore;

final class SemanticResultProjectionTest {
    @Test
    void statusIdentityProjectionIsPureExactAndFailsClosedForMalformedCrl(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root);
                DefaultSemanticSigningServiceTest.TestProvider provider = new DefaultSemanticSigningServiceTest.TestProvider()) {
            AtomicInteger reads = new AtomicInteger();
            PkiStore observed = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        reads.incrementAndGet();
                        try { return method.invoke(store, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            DefaultSemanticSigningService service = semantic(observed, signing(observed, provider,
                    (command, custody) -> { throw new AssertionError("Projection must not admit signing"); }));
            int initialReads = reads.get();
            String id = "crl:" + "1".repeat(64);
            EncodedObject result = new EncodedObject(Encoding.BINARY, id.getBytes(StandardCharsets.US_ASCII));
            assertEquals(Optional.of(new PkiId(id)), service.completedStatusObjectId(operation(
                    SemanticSigningKind.STATUS, "GENERATE_FULL_CRL", SemanticSigningState.COMPLETED, result)));
            for (SemanticSigningState state : SemanticSigningState.values()) {
                if (state != SemanticSigningState.COMPLETED) {
                    assertTrue(service.completedStatusObjectId(operation(SemanticSigningKind.STATUS,
                            "GENERATE_FULL_CRL", state, null)).isEmpty());
                }
            }
            for (SemanticSigningKind kind : List.of(SemanticSigningKind.CA, SemanticSigningKind.ISSUANCE)) {
                assertTrue(service.completedStatusObjectId(operation(kind, "GENERATE_FULL_CRL",
                        SemanticSigningState.COMPLETED, result)).isEmpty());
            }
            assertTrue(service.completedStatusObjectId(operation(SemanticSigningKind.STATUS, "OTHER_STATUS",
                    SemanticSigningState.COMPLETED, result)).isEmpty());
            for (EncodedObject malformed : List.of(new EncodedObject(Encoding.DER, result.bytes()),
                    new EncodedObject(Encoding.BINARY, new byte[] { 1 }),
                    new EncodedObject(Encoding.BINARY, ("crl:" + "A".repeat(64)).getBytes(StandardCharsets.US_ASCII)),
                    new EncodedObject(Encoding.BINARY, (id + "\n").getBytes(StandardCharsets.US_ASCII)))) {
                assertThrows(IllegalStateException.class, () -> service.completedStatusObjectId(operation(
                        SemanticSigningKind.STATUS, "GENERATE_FULL_CRL", SemanticSigningState.COMPLETED, malformed)));
            }
            assertThrows(NullPointerException.class, () -> service.completedStatusObjectId(null));
            assertEquals(initialReads, reads.get());
            assertEquals(0, provider.calls.get());
        }
    }

    @Test
    void credentialIdentityRequiresCaOrIssuanceCompletionWithDer() throws Exception {
        byte[] bytes = { 1, 2, 3 };
        PkiId expected = new PkiId("x509:" + zeroecho.pki.testkit.SemanticIssuanceFixture.digest(bytes));
        for (SemanticSigningKind kind : List.of(SemanticSigningKind.CA, SemanticSigningKind.ISSUANCE)) {
            assertEquals(Optional.of(expected), operation(kind, "CERTIFICATE", SemanticSigningState.COMPLETED,
                    new EncodedObject(Encoding.DER, bytes)).completedCredentialId());
            assertTrue(operation(kind, "CERTIFICATE", SemanticSigningState.COMPLETED,
                    new EncodedObject(Encoding.BINARY, bytes)).completedCredentialId().isEmpty());
            for (SemanticSigningState state : SemanticSigningState.values()) {
                if (state != SemanticSigningState.COMPLETED) {
                    assertTrue(operation(kind, "CERTIFICATE", state, null).completedCredentialId().isEmpty());
                }
            }
        }
        assertTrue(operation(SemanticSigningKind.STATUS, "GENERATE_FULL_CRL", SemanticSigningState.COMPLETED,
                new EncodedObject(Encoding.DER, bytes)).completedCredentialId().isEmpty());
    }

    private static SemanticSigningOperation operation(SemanticSigningKind kind, String operation,
            SemanticSigningState state, EncodedObject result) {
        SemanticSigningScope scope = new SemanticSigningScope(kind, operation, ACCESS, new KeyRef("key"),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        return new SemanticSigningOperation(new SigningSubmissionId(new PkiId("projection"), "projection", NOW),
                scope, SigningOperationState.SUCCEEDED, state, 1, 1, NOW, NOW.plusSeconds(60),
                Optional.empty(), Optional.ofNullable(result));
    }
}
