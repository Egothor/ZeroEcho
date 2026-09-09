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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Fast contract tests for the controlled production-ledger recovery artifact. */
final class SigningRecoveryBenchmarkTest {
    private static final Instant CREATED_AT = Instant.ofEpochMilli(1_800_000_000_000L);

    @Test
    void configurationEnforcesFixedSegmentAndSuffixBounds(@TempDir Path temporary) {
        SigningRecoveryBenchmark.Configuration maximum = configuration(temporary.resolve("max"),
                temporary.resolve("max.json"), 1_000_000L, 10L, 4096, 1_000_000L);
        assertEquals(4096, maximum.sealedSegments());
        assertEquals(1_000_000L, maximum.suffixFrames());
        SigningRecoveryBenchmark.Configuration defaults = SigningRecoveryBenchmark.Configuration
                .parse(new String[] { "--mode=prepare-only",
                    "--workRoot=" + temporary.resolve("default"),
                    "--output=" + temporary.resolve("default.json") });
        assertEquals(defaults.sealedSegments(), defaults.suffixFrames());
        assertEquals("CONFIGURATION_INVALID", rejected(temporary, 0, 1));
        assertEquals("CONFIGURATION_INVALID", rejected(temporary, 4097, 4097));
        assertEquals("CONFIGURATION_INVALID", rejected(temporary, 4, 3));
        assertEquals("CONFIGURATION_INVALID", rejected(temporary, 4, 1_000_001));
    }

    @Test
    void tinyControlledImageRecoversExactProductionState(@TempDir Path temporary)
            throws Exception {
        Path workRoot = temporary.resolve("image");
        SigningControlledRecoveryImage.Descriptor descriptor =
                SigningControlledRecoveryImage.prepare(workRoot, 9L, 2L, 2, 2L, CREATED_AT);
        assertFalse(descriptor.synthetic());
        assertEquals(64, descriptor.descriptorFingerprint().length());

        SigningRecoveryBenchmark.Configuration configuration = configuration(workRoot,
                temporary.resolve("report.json"), 9L, 2L, 2, 2L);
        SigningRecoveryBenchmark.Result result = SigningRecoveryBenchmark.recover(configuration,
                sequenceClock(100L, 150L));

        assertEquals(50L, result.openNanos());
        assertEquals(9, result.capacity().currentKeys());
        assertEquals(2, result.capacity().dueWork());
        assertEquals(2, result.capacity().ownerWork());
        assertEquals(2, result.capacity().projectedIdentities());
        assertEquals(0, result.capacity().retentionRecords());
        assertEquals(13L, result.capacity().generationCurrentReferences());
        assertEquals(0L, result.capacity().generationSnapshotPins());
        assertEquals(9, result.recovery().checkpointEntries());
        assertEquals(2, result.recovery().sealedSegments());
        assertEquals(2L, result.recovery().sealedFrames());
        assertEquals(0L, result.recovery().activeFrames());
        assertEquals(0L, result.recovery().unreferencedArtifacts());
        assertEquals(SigningWalContainerCodec.HEADER_BYTES, result.artifacts().activeBytes());
        String json = result.toJson(configuration);
        assertTrue(json.contains("\"schema\":\"zeroecho-signing-production-recovery-v1\""));
        assertTrue(json.contains("\"synthetic\":false"));
        assertTrue(json.contains("\"timedOperation\":"
                + "\"SegmentedTransactionalMetadataStore.open\""));
        assertTrue(json.contains("\"fullFilesystemPkiStoreReopenMeasured\":false"));
        assertTrue(json.contains("\"primaryMvccReferences\":9"));
        assertTrue(json.contains("\"dueReferences\":2"));
        assertTrue(json.contains("\"ownerReferences\":2"));
        assertTrue(json.contains("\"expectedRegistryTotal\":13"));
        assertTrue(json.contains("\"timeComplexity\":"
                + "\"O(M log M + W log W + F + S)\""));
        assertTrue(json.contains("\"usedHeapDeltaIsRetainedAttribution\":false"));
        assertTrue(json.contains("\"allocationScope\":\"CALLER_THREAD_ONLY\""));
        assertTrue(json.contains("\"allocationExcludesOtherThreads\":true"));
        assertTrue(json.contains("\"gcScope\":\"PROCESS_GLOBAL\""));
        assertFalse(json.contains("threshold"));
    }

    @Test
    void existingImageAndTamperedDescriptorFailClosed(@TempDir Path temporary) throws Exception {
        Path workRoot = temporary.resolve("image");
        SigningControlledRecoveryImage.prepare(workRoot, 7L, 1L, 1, 1L, CREATED_AT);
        SigningControlledRecoveryImage.ImageException existing = assertThrows(
                SigningControlledRecoveryImage.ImageException.class,
                () -> SigningControlledRecoveryImage.prepare(
                        workRoot, 7L, 1L, 1, 1L, CREATED_AT));
        assertEquals("WORK_ROOT_NOT_FRESH", existing.reasonCode());
        Files.writeString(workRoot.resolve(SigningControlledRecoveryImage.DESCRIPTOR_FILE),
                "tampered");

        SigningControlledRecoveryImage.ImageException tampered = assertThrows(
                SigningControlledRecoveryImage.ImageException.class,
                () -> SigningControlledRecoveryImage.validate(workRoot, 7L, 1L, 1, 1L));
        assertEquals("DESCRIPTOR_INVALID", tampered.reasonCode());
    }

    @Test
    void missingOrEmptyDescriptorFieldFailsWithStableReason(@TempDir Path temporary)
            throws Exception {
        Path workRoot = temporary.resolve("image");
        SigningControlledRecoveryImage.prepare(workRoot, 7L, 1L, 1, 1L, CREATED_AT);
        Path descriptor = workRoot.resolve(SigningControlledRecoveryImage.DESCRIPTOR_FILE);
        String valid = Files.readString(descriptor);

        Files.writeString(descriptor,
                valid.replace("activePopulation=1", "missingActivePopulation=1"));
        assertDescriptorInvalid(workRoot);

        Files.writeString(descriptor,
                valid.replace("activePopulation=1", "activePopulation="));
        assertDescriptorInvalid(workRoot);
    }

    @Test
    void oversizedDescriptorAndMalformedManifestFailBeforeUnboundedAllocation(
            @TempDir Path temporary) throws Exception {
        assertEquals(334, SigningControlledRecoveryImage.MAXIMUM_DESCRIPTOR_BYTES);
        Path oversizedRoot = temporary.resolve("oversized-descriptor");
        SigningControlledRecoveryImage.prepare(oversizedRoot, 7L, 1L, 1, 1L, CREATED_AT);
        Files.write(oversizedRoot.resolve(SigningControlledRecoveryImage.DESCRIPTOR_FILE),
                new byte[SigningControlledRecoveryImage.MAXIMUM_DESCRIPTOR_BYTES + 1]);
        SigningControlledRecoveryImage.ImageException oversized = assertThrows(
                SigningControlledRecoveryImage.ImageException.class,
                () -> SigningControlledRecoveryImage.validate(
                        oversizedRoot, 7L, 1L, 1, 1L));
        assertEquals("DESCRIPTOR_INVALID", oversized.reasonCode());

        Path malformedRoot = temporary.resolve("malformed-manifest");
        SigningControlledRecoveryImage.prepare(malformedRoot, 7L, 1L, 1, 1L, CREATED_AT);
        Path manifest = SigningControlledRecoveryImage.metadataRoot(malformedRoot)
                .resolve(SigningLedgerRecovery.MANIFEST_FILE);
        Files.write(manifest, new byte[] { 1 });
        SigningControlledRecoveryImage.ImageException malformed = assertThrows(
                SigningControlledRecoveryImage.ImageException.class,
                () -> SigningControlledRecoveryImage.validate(
                        malformedRoot, 7L, 1L, 1, 1L));
        assertEquals("IMAGE_UNAVAILABLE_OR_INVALID", malformed.reasonCode());
        assertFalse(malformed.getMessage().contains(manifest.toString()));
    }

    private static SigningRecoveryBenchmark.Configuration configuration(Path workRoot, Path output,
            long retained, long active, int segments, long frames) {
        return new SigningRecoveryBenchmark.Configuration(SigningRecoveryBenchmark.Mode.RECOVER_ONLY,
                retained, active, segments, frames, CREATED_AT, output, workRoot);
    }

    private static String rejected(Path temporary, int segments, long frames) {
        SigningRecoveryBenchmark.ContractException failure = assertThrows(
                SigningRecoveryBenchmark.ContractException.class,
                () -> configuration(temporary.resolve("invalid-" + segments + '-' + frames),
                        temporary.resolve("invalid.json"), 100L, 1L, segments, frames));
        return failure.reasonCode();
    }

    private static LongSupplier sequenceClock(long... values) {
        AtomicInteger index = new AtomicInteger();
        return () -> values[index.getAndIncrement()];
    }

    private static void assertDescriptorInvalid(Path workRoot) {
        SigningControlledRecoveryImage.ImageException failure = assertThrows(
                SigningControlledRecoveryImage.ImageException.class,
                () -> SigningControlledRecoveryImage.validate(workRoot, 7L, 1L, 1, 1L));
        assertEquals("DESCRIPTOR_INVALID", failure.reasonCode());
        assertTrue(failure.getCause() instanceof IllegalArgumentException);
        assertFalse(failure.getMessage().contains("activePopulation"));
    }
}
