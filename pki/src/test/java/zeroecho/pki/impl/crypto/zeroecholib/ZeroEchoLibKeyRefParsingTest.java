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
package zeroecho.pki.impl.crypto.zeroecholib;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.core.io.ImmutableByteContent;

public final class ZeroEchoLibKeyRefParsingTest {

    private static final String NAMESPACE = "0123456789abcdef0123456789abcdef.zeroecho-lib";

    @TempDir
    Path tempDir;

    @Test
    void signing_requires_prv_suffix_in_strict_mode_ok() {
        System.out.println("signing_requires_prv_suffix_in_strict_mode_ok");

        try (ZeroEchoLibSignatureWorkflow wf = new ZeroEchoLibSignatureWorkflow("zeroecho-lib", Path.of("nonexistent"),
                tempDir.resolve("operations-1"), Clock.systemUTC(), Duration.ofDays(90), "zeroecho-lib:", true,
                TestKeyringUnlocks.provider())) {

            AccessContext ctx = new AccessContext(new Principal("TEST", "unit"), new Purpose("UNIT_TEST"),
                    Optional.empty(), Optional.empty());

            PkiId submissionId = SigningSubmissionId.create(NAMESPACE, Instant.now(), new SecureRandom()).id();
            SignatureWorkflow.SignRequest req = SignatureWorkflow.SignRequest.create(submissionId, NAMESPACE, 1L, ctx,
                    new KeyRef("zeroecho-lib:abc"), "ECDSA", new ImmutableByteContent(new byte[] { 0x01 }),
                    Optional.of(Encoding.BINARY), Optional.of(Instant.now()));

            PkiId opId = wf.submitSign(req);
            SignatureWorkflow.OperationStatus st = wf.status(opId);

            System.out.println("...state=" + st.state());
            System.out.println("...detailCode=" + st.detailCode().orElse("<none>"));

            assertEquals(SignatureWorkflow.State.FAILED, st.state());
            assertEquals(ZeroEchoLibSignatureWorkflow.DC_INVALID_KEYREF_SUFFIX, st.detailCode().orElse(""));
        }
        System.out.println("...ok");
    }

    @Test
    void verify_with_publicKeyEncoded_invalid_spki_fails_with_crypto_failure_ok() {
        System.out.println("verify_with_publicKeyEncoded_invalid_spki_fails_with_crypto_failure_ok");

        try (ZeroEchoLibSignatureWorkflow wf = new ZeroEchoLibSignatureWorkflow("zeroecho-lib", Path.of("nonexistent"),
                tempDir.resolve("operations-2"), Clock.systemUTC(), Duration.ofDays(90), "zeroecho-lib:", true,
                TestKeyringUnlocks.provider())) {

            AccessContext ctx = new AccessContext(new Principal("TEST", "unit"), new Purpose("UNIT_TEST"),
                    Optional.empty(), Optional.empty());

            SignatureWorkflow.VerifyRequest req = new SignatureWorkflow.VerifyRequest(ctx, "ECDSA",
                    new ImmutableByteContent(new byte[] { 0x01 }),
                    new EncodedObject(Encoding.BINARY, new byte[] { 0x02 }), Optional.empty(),
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 0x03 })), // unsupported form
                    Optional.of(Instant.now()), CancellationSignal.NONE);

            PkiId opId = wf.submitVerify(req);
            SignatureWorkflow.OperationStatus st = wf.status(opId);

            System.out.println("...state=" + st.state());
            System.out.println("...detailCode=" + st.detailCode().orElse("<none>"));

            assertEquals(SignatureWorkflow.State.FAILED, st.state());
            assertEquals(ZeroEchoLibSignatureWorkflow.DC_CRYPTO_FAILURE, st.detailCode().orElse(""));
        }
        System.out.println("...ok");
    }

    @Test
    void status_unknown_operation_is_deterministic_ok() {
        System.out.println("status_unknown_operation_is_deterministic_ok");

        try (ZeroEchoLibSignatureWorkflow wf = new ZeroEchoLibSignatureWorkflow("zeroecho-lib", Path.of("nonexistent"),
                tempDir.resolve("operations-3"), Clock.systemUTC(), Duration.ofDays(90), "zeroecho-lib:", true,
                TestKeyringUnlocks.provider())) {

            PkiId unknown = new PkiId("00000000-0000-0000-0000-000000000000");
            SignatureWorkflow.OperationStatus st = wf.status(unknown);

            System.out.println("...state=" + st.state());
            System.out.println("...detailCode=" + st.detailCode().orElse("<none>"));
            System.out.println("...updatedAt=" + st.updatedAt());

            assertEquals(SignatureWorkflow.State.FAILED, st.state());
            assertEquals(ZeroEchoLibSignatureWorkflow.DC_UNKNOWN_OPERATION, st.detailCode().orElse(""));
            assertEquals(Instant.EPOCH, st.updatedAt());
        }
        System.out.println("...ok");
    }
}
