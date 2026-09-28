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

package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.InterruptedIOException;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofChallenge;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.testkit.IntermediateCreationFixture;

/** Shared planning freezes keys without consuming any separately accepted proof. */
final class ManagedKeyProofPlanningTest {
    @Test void exportsOnceAndBindsFreshInternalChallengeToParentAndDeadline(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = open(root)) {
            ManagedKeyProofPreparation preparation = fixture.proofPreparation(store);
            ManagedKeyProofRequest request = request();
            ManagedKeyProofPreparation.ProofPlan plan = preparation.plan(request, CancellationSignal.NONE);
            SigningSubmissionId parent = fixture.submission(store);
            SigningSubmissionId step = preparation.newStep(parent);
            ManagedKeyProofChallenge.CaContext context = new ManagedKeyProofChallenge.CaContext(parent.id(),
                    "ca-intent:v1:" + "12".repeat(32));
            ManagedKeyProofPreparation.FrozenChallenge frozen = preparation.challenge(plan, step,
                    parent.createdAt().plus(IntermediateCreationFixture.TTL), Optional.of(context), CancellationSignal.NONE);
            ManagedKeyProofChallenge.Decoded decoded = ManagedKeyProofChallenge.decode(frozen.content().bytes());
            assertNotEquals(parent.id(), step.id());
            assertEquals(parent.namespace(), step.namespace());
            assertEquals(parent.createdAt(), step.createdAt());
            assertEquals(step.id(), decoded.operationId());
            assertEquals(parent.createdAt().plus(IntermediateCreationFixture.TTL), decoded.deadline());
            assertEquals(Optional.of(context), decoded.context());
            assertEquals(request, zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand.decodePrefix(decoded.command()));
            assertArrayEquals(fixture.childKey.getPublic().getEncoded(), decoded.spki());
            assertEquals(1, fixture.provider.lookups);
            assertEquals(0, fixture.provider.dispatches);
            assertTrue(store.getSignWorkflow(parent.id()).isEmpty());
            assertTrue(store.getSignWorkflow(step.id()).isEmpty());
        }
    }

    @Test void cancellationBeforePlanningOrChallengeNeverDispatchesOrAdmits(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = open(root)) {
            ManagedKeyProofPreparation preparation = fixture.proofPreparation(store);
            assertThrows(InterruptedIOException.class, () -> preparation.plan(request(), () -> true));
            assertEquals(0, fixture.provider.lookups);
            ManagedKeyProofPreparation.ProofPlan plan = preparation.plan(request(), CancellationSignal.NONE);
            SigningSubmissionId step = fixture.submission(store);
            assertThrows(InterruptedIOException.class, () -> preparation.challenge(plan, step,
                    step.createdAt().plus(IntermediateCreationFixture.TTL), Optional.empty(), () -> true));
            assertEquals(1, fixture.provider.lookups);
            assertEquals(0, fixture.provider.dispatches);
            assertTrue(store.getSignWorkflow(step.id()).isEmpty());
        }
    }

    private static ManagedKeyProofRequest request() {
        return new ManagedKeyProofRequest.CaSubject(IntermediateCreationFixture.CA,
                Optional.of(new PkiId("existing-child")), "intermediate-ca", IntermediateCreationFixture.CHILD_KEY);
    }

    private static FilesystemPkiStore open(Path root) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK);
    }
}
