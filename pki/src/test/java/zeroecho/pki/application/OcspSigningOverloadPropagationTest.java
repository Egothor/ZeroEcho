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

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

/** Real durable-work saturation through both OCSP signing entry paths. */
final class OcspSigningOverloadPropagationTest {

    @Test
    void responseAndBindingPreserveTypedAdmissionOverload(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:test:ocsp-overload");
        try (PkiTestRuntime runtime = PkiTestRuntime.createWithMaximumSigningWork(root, root.resolve("bus.log"),
                Map.of(rootRef, rootKey), 1)) {
            PkiId caId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=OCSP Overload Root"), "root-ca", Optional.of(rootRef),
                    new SimpleAttributeSet()));
            Credential responder = runtime.caCredential(runtime.caService().getCa(caId), 0);
            PkiId issuerId = runtime.caService().getCa(caId).currentIssuanceIssuerId();
            DefaultOcspResponseService service = new DefaultOcspResponseService(runtime.store(),
                    runtime.signingBus(), Duration.ofSeconds(2), () -> { });
            Instant producedAt = responder.validity().notBefore().plusSeconds(1);
            OcspResponseService.Command command = new OcspResponseService.Command(caId, issuerId,
                    responder.credentialId(), responder.credentialId(), rootRef, List.of(responder.credentialId()),
                    "SHA256withRSA", Optional.empty(), OcspResponseService.ResponderId.BY_NAME, producedAt,
                    producedAt, producedAt.plusSeconds(60), Optional.empty(), List.of(new OcspResponseService.CertId(
                            OcspResponseService.CertIdHash.SHA1, new byte[20], new byte[20], BigInteger.ONE)));
            int providerCalls = runtime.submittedSignCount();
            int records = runtime.store().listSignRecords().size();

            try (SignWorkflowStore.SignAdmission ignored = runtime.store().reserveSignAdmission()) {
                assertOverloaded(() -> service.respond(command));
                assertOverloaded(() -> service.validateSigningBinding(responder.credentialId(), rootRef,
                        "SHA256withRSA", Optional.empty()));
                assertEquals(providerCalls, runtime.submittedSignCount());
                assertEquals(records, runtime.store().listSignRecords().size());
            }
        }
    }

    private static void assertOverloaded(ThrowingAction action) {
        SigningExecutionException failure = assertThrows(SigningExecutionException.class, action::run);
        assertEquals(SigningExecutionException.Classification.OVERLOADED, failure.classification());
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
