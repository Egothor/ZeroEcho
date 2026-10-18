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

package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.Util;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class ManagedKeyProofCodecTest {
    private static final List<DomainContinuationStore.Kind> KINDS = List.of(DomainContinuationStore.Kind.CA,
            DomainContinuationStore.Kind.ISSUANCE, DomainContinuationStore.Kind.STATUS, DomainContinuationStore.Kind.KEY_PROOF);
    private static final String DIGEST = "1".repeat(64);

    @Test void domainKindCodesRemainStableAndUnknownCodesAreRejected() throws Exception {
        byte[] original = FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, record(DomainContinuationStore.Kind.CA));
        int offset;
        try (ByteArrayInputStream input = new ByteArrayInputStream(original)) {
            input.skipNBytes(6); // Existing codec magic, version and top-level schema.
            input.skipNBytes(2); // PKI ID and its nested string type.
            assertEquals("operation", Util.readUTF8(input, 4096));
            input.skipNBytes(1); // Version integer type.
            assertEquals(2L, Util.readLong(input));
            input.skipNBytes(1); // Domain kind type.
            offset = original.length - input.available();
        }
        for (int index = 0; index < KINDS.size(); index++) {
            DomainContinuationStore.Kind kind = KINDS.get(index);
            byte[] encoded = FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, record(kind));
            byte[] expected = original.clone();
            expected[offset] = (byte) (index + 1);
            assertArrayEquals(expected, encoded);
            DomainContinuationStore.Record restored = FsCodec.decode(FsCodec.DOMAIN_CONTINUATION, encoded);
            assertEquals(kind, restored.kind());
            assertArrayEquals(encoded, FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, restored));
        }
        for (int unknown : new int[] { 0, 5, 255 }) {
            byte[] invalid = original.clone();
            invalid[offset] = (byte) unknown;
            assertThrows(IllegalStateException.class, () -> FsCodec.decode(FsCodec.DOMAIN_CONTINUATION, invalid));
        }
    }

    @Test void acceptanceCommitmentUsesStableDomainCodes() {
        List<String> expected = List.of(
                "8c94e4892ad0119dcd58850bc22fb3523f57d8e8de232cd984d26244e467eb0f",
                "d3a1270a87060add681927d229d6f0f2af5dae7ffff60c6e35f0d5e7db55c90f",
                "1c30e0e9c8ddfb2bd721802da6104f0214d51fbdd344c62aa37a458c27932865",
                "18c7b1882f3b8b4b16601f7d90447dbd45774bdec37688df5c2b43f1cb2cade2");
        DurableContentReference content = new TestReference("store", "content", Encoding.BINARY, 3L,
                DIGEST, DurableContentReference.Lifecycle.OPERATION);
        for (int index = 0; index < KINDS.size(); index++) {
            assertEquals("accept-sign:v3:" + expected.get(index), command(KINDS.get(index), content).commitment().encoded());
        }
    }

    @Test void acceptanceEnvelopeRoundTripsEveryDomainIncludingProof(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            DurableContentReference content = PkiTestRuntime.operationReference(store.stagedContent(),
                    Encoding.BINARY, new byte[] { 1, 2, 3 });
            for (DomainContinuationStore.Kind kind : KINDS) {
                SignWorkflowStore.AcceptanceEnvelope envelope = SignWorkflowStore.AcceptanceEnvelope.from(command(kind, content));
                byte[] encoded = FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, envelope);
                SignWorkflowStore.AcceptanceEnvelope restored = FsCodec.decode(
                        FsCodec.SIGN_ACCEPTANCE_ENVELOPE, encoded, store.stagedContent());
                assertEquals(kind, restored.outer().orElseThrow().kind());
                assertEquals(envelope.acceptanceCommitment(), restored.acceptanceCommitment());
                assertArrayEquals(encoded, FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, restored));
            }
        }
    }

    @Test void proofKindNeverDerivesCertificateReservationsOrReadsCandidate() throws Exception {
        DurableContentReference candidate = new TestReference("store", "content", Encoding.BINARY, 3L,
                DIGEST, DurableContentReference.Lifecycle.OPERATION);
        // Neither the store nor the content is needed: proof is excluded before certificate parsing.
        assertTrue(SignAcceptanceCrlScope.derive(null, command(DomainContinuationStore.Kind.KEY_PROOF, candidate), null).isEmpty());
    }

    private static DomainContinuationStore.Record record(DomainContinuationStore.Kind kind) {
        return new DomainContinuationStore.Record(new PkiId("operation"), 2, kind, Optional.of("correlation"),
                DomainContinuationStore.State.FAILED, 0L, Instant.EPOCH, Instant.EPOCH.plusSeconds(60),
                new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3 }), "domain:v1:" + "2".repeat(64),
                Optional.empty(), Optional.empty(), Optional.of("FAILED"));
    }

    private static SignWorkflowStore.AcceptanceCommand command(DomainContinuationStore.Kind kind,
            DurableContentReference content) {
        return new SignWorkflowStore.AcceptanceCommand(new PkiId("operation"), "namespace",
                new ConfigurationCommitment(new byte[32]), new AccessContext(new Principal("TEST", "actor"),
                        new Purpose("PROVE"), Optional.empty(), Optional.empty()),
                new KeyRef("key"), new PkiId("authority"), "algorithm", Encoding.BINARY,
                Instant.EPOCH, Instant.EPOCH.plusSeconds(60), content, Optional.of(new SignWorkflowStore.OuterCommand(
                        kind, "correlation", new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3 }),
                        "domain:v1:" + "2".repeat(64))), SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
    }

    private record TestReference(String storeId, String contentId, Encoding encoding, long length,
            String sha256, DurableContentReference.Lifecycle lifecycle) implements DurableContentReference { }
}
