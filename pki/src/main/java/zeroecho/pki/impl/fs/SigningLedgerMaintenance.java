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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Package-owned sealing, checkpoint compaction, and bounded durable reclamation.
 * Instances are thread-confined by the ledger lifecycle owner.
 */
// Rotation and compaction collaborators share the manifest publication transaction owned here.
@SuppressWarnings({ "PMD.AvoidSynchronizedStatement", "PMD.AvoidUsingVolatile",
        "PMD.CyclomaticComplexity", "PMD.CouplingBetweenObjects" })
final class SigningLedgerMaintenance implements AutoCloseable {
    private static final FaultInjector NO_FAULTS = stage -> { };
    private static final PressureProbe NO_PRESSURE = () -> null;

    private final Path root;
    private final SigningActiveWal.Configuration activeConfiguration;
    private final SigningGenerationRegistry generations;
    private final SigningMvccIndex index;
    private final SigningArtifactCatalog artifacts;
    private final FaultInjector faults;
    private final Configuration configuration;
    private final AtomicBoolean recoveryRequired = new AtomicBoolean();
    private SigningManifestCodec.Manifest manifest;
    private volatile SigningActiveWal activeWal;
    private long sourceChannelsOpened;
    private boolean closed;

    /* default */ SigningLedgerMaintenance(Path root, SigningManifestCodec.Manifest manifest,
            SigningActiveWal activeWal, SigningActiveWal.Configuration activeConfiguration,
            SigningGenerationRegistry generations, SigningMvccIndex index,
            SigningArtifactCatalog artifacts) {
        this(root, manifest, activeWal, activeConfiguration, generations, index, artifacts,
                Configuration.defaults(), NO_FAULTS);
    }

    /* default */ SigningLedgerMaintenance(Path root, SigningManifestCodec.Manifest manifest,
            SigningActiveWal activeWal, SigningActiveWal.Configuration activeConfiguration,
            SigningGenerationRegistry generations, SigningMvccIndex index,
            SigningArtifactCatalog artifacts, FaultInjector faults) {
        this(root, manifest, activeWal, activeConfiguration, generations, index, artifacts,
                Configuration.defaults(), faults);
    }

    /* default */ SigningLedgerMaintenance(Path root, SigningManifestCodec.Manifest manifest,
            SigningActiveWal activeWal, SigningActiveWal.Configuration activeConfiguration,
            SigningGenerationRegistry generations, SigningMvccIndex index,
            SigningArtifactCatalog artifacts, Configuration configuration, FaultInjector faults) {
        this.root = Objects.requireNonNull(root, "root");
        this.manifest = Objects.requireNonNull(manifest, "manifest");
        this.activeWal = Objects.requireNonNull(activeWal, "activeWal");
        this.activeConfiguration = Objects.requireNonNull(activeConfiguration,
                "activeConfiguration");
        this.generations = Objects.requireNonNull(generations, "generations");
        this.index = Objects.requireNonNull(index, "index");
        this.artifacts = Objects.requireNonNull(artifacts, "artifacts");
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.faults = Objects.requireNonNull(faults, "faults");
    }

    /** Stops admission, seals a copied immutable segment, and publishes a new active WAL. */
    /* default */ Rotation rotate(long nextActiveIdentity) throws IOException {
        requireUsable();
        requireAvailableIdentity(nextActiveIdentity);
        return rotateInternal(nextActiveIdentity, false, null);
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidLiteralsInIfCondition",
            "PMD.CloseResource", "PMD.ExceptionAsFlowControl" })
    private Rotation rotateInternal(long nextActiveIdentity, boolean captureBoundary,
            SigningMvccIndex.Snapshot suppliedBoundary)
            throws IOException {
        if (captureBoundary && suppliedBoundary != null) {
            throw new IllegalArgumentException("signing rotation boundary ownership is ambiguous");
        }
        SigningManifestCodec.ActiveWal prior = manifest.activeWal();
        SigningActiveWal next = null;
        SigningMvccIndex.Snapshot boundary = suppliedBoundary;
        try {
            SigningActiveWal.Seal sealed = activeWal.orderlySeal();
            faults.at(Stage.ACTIVE_DRAINED);
            if (sealed.frameCount() == 0L) {
                throw new IllegalStateException("empty signing WAL rotation is not useful");
            }
            if (sealed.length() > configuration.maximumActiveSegmentBytes()) {
                throw new IOException("closed signing WAL exceeds the configured segment bound");
            }
            Path sealedPath = root.resolve(SigningManifestCodec.segmentName(
                    prior.firstSequence(), sealed.lastSequence()));
            publishSealedOrAdopt(root.resolve(prior.name()), sealedPath, sealed);
            faults.at(Stage.SEALED_PUBLISHED);

            SigningActiveWal.Descriptor nextDescriptor = new SigningActiveWal.Descriptor(
                    nextActiveIdentity, Math.incrementExact(sealed.lastSequence()),
                    sealed.committedRevision());
            next = SigningActiveWal.open(
                    root.resolve(SigningManifestCodec.activeName(nextActiveIdentity)),
                    nextDescriptor, activeConfiguration);
            faults.at(Stage.NEXT_ACTIVE_PUBLISHED);
            SigningManifestCodec.Segment segment = new SigningManifestCodec.Segment(
                    prior.identity(), prior.firstSequence(), sealed.frameCount(),
                    sealed.length(), sealed.fileCommitment(),
                    sealedPath.getFileName().toString());
            List<SigningManifestCodec.Segment> segments = new ArrayList<>(
                    manifest.sealedSegments());
            segments.add(segment);
            SigningManifestCodec.ActiveWal nextManifestActive = activeDescriptor(nextDescriptor);
            SigningManifestCodec.Manifest candidate = new SigningManifestCodec.Manifest(
                    sealed.committedRevision(), sealed.lastSequence(), manifest.checkpoint(),
                    segments, nextManifestActive);
            publishManifest(candidate);
            faults.at(Stage.MANIFEST_PUBLISHED);

            generations.create(nextActiveIdentity);
            generations.publish(nextActiveIdentity);
            artifacts.register(new SigningArtifactCatalog.Artifact(prior.identity(),
                    sealedPath.getFileName().toString(), SigningArtifactCatalog.Kind.SEALED_WAL));
            artifacts.register(new SigningArtifactCatalog.Artifact(nextActiveIdentity,
                    nextManifestActive.name(), SigningArtifactCatalog.Kind.ACTIVE_WAL));
            if (captureBoundary) {
                boundary = index.snapshot();
            }
            if (boundary != null && (boundary.revision() != sealed.committedRevision()
                    || boundary.committedSequence() != sealed.lastSequence())) {
                throw new IllegalStateException(
                        "signing compaction boundary is not the rotated WAL boundary");
            }
            manifest = candidate;
            activeWal = next;
            faults.at(Stage.MEMORY_PUBLISHED);
            return new Rotation(segment, nextManifestActive, boundary);
        } catch (IOException | RuntimeException failure) {
            recoveryRequired.set(true);
            closeAfterFailure(boundary, failure);
            closeAfterFailure(next, failure);
            throw new MaintenanceException(MaintenanceStage.ROTATE, failure);
        }
    }

    /**
     * Publishes a self-contained live-record checkpoint and relocates only
     * current pointers that still equal the pinned snapshot values.
     */
    /* default */ Compaction compact(long checkpointIdentity, long nextActiveIdentity)
            throws IOException {
        return compact(checkpointIdentity, nextActiveIdentity, () -> { }, this);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ Compaction compact(long checkpointIdentity, long nextActiveIdentity,
            Runnable boundaryPublished, Object relocationPublicationLock) throws IOException {
        requireUsable();
        Objects.requireNonNull(boundaryPublished, "boundaryPublished");
        Objects.requireNonNull(relocationPublicationLock, "relocationPublicationLock");
        if (checkpointIdentity == nextActiveIdentity) {
            throw new IllegalArgumentException("signing checkpoint identity is invalid");
        }
        requireAvailableIdentity(checkpointIdentity);
        requireAvailableIdentity(nextActiveIdentity);
        if (generationIds(manifest).size() > configuration.maximumSourceGenerations()) {
            throw new IllegalStateException(
                    "signing checkpoint source-generation bound requires earlier compaction");
        }
        Rotation rotation = rotateInternal(nextActiveIdentity, true, null);
        boundaryPublished.run();
        sourceChannelsOpened = 0L;
        try (SigningMvccIndex.Snapshot snapshot = rotation.boundary()) {
            SigningCheckpointCodec.Header header = new SigningCheckpointCodec.Header(
                    checkpointIdentity, snapshot.revision(), snapshot.committedSequence(),
                    snapshot.size(), snapshot.checkpointDataOffset());
            String checkpointName = SigningManifestCodec.checkpointName(snapshot.revision(),
                    snapshot.committedSequence());
            Path checkpointPath = root.resolve(checkpointName);
            if (Files.exists(checkpointPath, LinkOption.NOFOLLOW_LINKS)) {
                validateExistingCheckpoint(checkpointPath, header, snapshot);
            } else {
                SigningFilePublisher.publishImmutable(checkpointPath,
                        channel -> writeCheckpoint(channel, header, snapshot));
            }
            faults.at(Stage.CHECKPOINT_PUBLISHED);

            SigningManifestCodec.Checkpoint descriptor = new SigningManifestCodec.Checkpoint(
                    checkpointIdentity, snapshot.revision(), snapshot.committedSequence(),
                    Files.size(checkpointPath), fileCommitment(checkpointPath), checkpointName);
            List<SigningManifestCodec.Segment> suffix = suffixAfter(
                    snapshot.committedSequence(), manifest.sealedSegments());
            SigningManifestCodec.Manifest candidate = new SigningManifestCodec.Manifest(
                    manifest.committedRevision(), manifest.committedSequence(),
                    Optional.of(descriptor), suffix, manifest.activeWal());
            publishManifest(candidate);
            faults.at(Stage.COMPACTION_MANIFEST_READY);

            generations.create(checkpointIdentity);
            generations.publish(checkpointIdentity);
            artifacts.register(new SigningArtifactCatalog.Artifact(checkpointIdentity,
                    checkpointName, SigningArtifactCatalog.Kind.CHECKPOINT));
            synchronized (relocationPublicationLock) {
                relocateSnapshot(snapshot, checkpointIdentity, header.dataOffset());
            }
            Set<Long> retained = generationIds(candidate);
            for (Long identity : generationIds(manifest)) {
                if (!retained.contains(identity)) {
                    generations.supersede(identity);
                }
            }
            manifest = candidate;
            faults.at(Stage.COMPACTION_MEMORY_PUBLISHED);
            return new Compaction(rotation, descriptor, snapshot.size());
        } catch (IOException | RuntimeException failure) {
            recoveryRequired.set(true);
            throw new MaintenanceException(MaintenanceStage.CHECKPOINT, failure);
        }
    }

    /** Performs online candidate construction, bounded catch-up, and durable cutover. */
    /* default */ Compaction compactOnline(long checkpointIdentity, long nextActiveIdentity,
            Runnable boundaryPublished, FinalGate finalGate,
            Object relocationPublicationLock,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder) throws IOException {
        return compactOnline(checkpointIdentity, nextActiveIdentity, boundaryPublished,
                finalGate, relocationPublicationLock, decoder, NO_PRESSURE);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ Compaction compactOnline(long checkpointIdentity, long nextActiveIdentity,
            Runnable boundaryPublished, FinalGate finalGate,
            Object relocationPublicationLock,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder,
            PressureProbe pressureProbe) throws IOException {
        validateOnlineCompaction(checkpointIdentity, nextActiveIdentity, boundaryPublished,
                finalGate, relocationPublicationLock, decoder);
        Objects.requireNonNull(pressureProbe, "pressureProbe");
        checkProtectedProgressPressure(pressureProbe);
        try (OnlinePreflight preflight = prepareOnlinePreflight()) {
            checkProtectedProgressPressure(pressureProbe);
            Rotation rotation = rotateInternal(nextActiveIdentity, false, preflight.snapshot);
            boundaryPublished.run();
            sourceChannelsOpened = 0L;
            try {
                return executeOnlineCompaction(checkpointIdentity, rotation,
                        preflight.capacityClaim, finalGate, relocationPublicationLock, decoder,
                        pressureProbe);
            } catch (CompactionDeferredException deferred) {
                throw deferred;
            } catch (IOException | RuntimeException failure) {
                recoveryRequired.set(true);
                throw new MaintenanceException(MaintenanceStage.CHECKPOINT, failure);
            }
        }
    }

    @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
    private OnlinePreflight prepareOnlinePreflight() throws CompactionDeferredException {
        SigningMvccIndex.Snapshot snapshot;
        try {
            snapshot = index.snapshot();
        } catch (SigningIndexCapacityBudget.CapacityExceededException exhausted) {
            throw new CompactionDeferredException(DeferralReason.STEADY_CAPACITY, exhausted);
        }
        boolean handedOff = false;
        try {
            OnlinePreflight result = new OnlinePreflight(
                    snapshot, index.prepareRelocationCapacity(snapshot));
            handedOff = true;
            return result;
        } catch (SigningIndexCapacityBudget.CapacityExceededException exhausted) {
            throw new CompactionDeferredException(DeferralReason.TRANSIENT_CAPACITY, exhausted);
        } finally {
            if (!handedOff) {
                snapshot.close();
            }
        }
    }

    private void validateOnlineCompaction(long checkpointIdentity, long nextActiveIdentity,
            Runnable boundaryPublished, FinalGate finalGate,
            Object relocationPublicationLock,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder) {
        requireUsable();
        Objects.requireNonNull(boundaryPublished, "boundaryPublished");
        Objects.requireNonNull(finalGate, "finalGate");
        Objects.requireNonNull(relocationPublicationLock, "relocationPublicationLock");
        Objects.requireNonNull(decoder, "decoder");
        if (checkpointIdentity == nextActiveIdentity) {
            throw new IllegalArgumentException("signing checkpoint identity is invalid");
        }
        requireAvailableIdentity(checkpointIdentity);
        requireAvailableIdentity(nextActiveIdentity);
        if (generationIds(manifest).size() > configuration.maximumSourceGenerations()) {
            throw new IllegalStateException(
                    "signing checkpoint source-generation bound requires earlier compaction");
        }
    }

    private Compaction executeOnlineCompaction(long checkpointIdentity, Rotation rotation,
            SigningMvccIndex.RelocationCapacity capacityClaim, FinalGate finalGate,
            Object relocationPublicationLock,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder,
            PressureProbe pressureProbe) throws IOException {
        SigningMvccIndex.Snapshot snapshot = rotation.boundary();
        try (snapshot) {
            try (capacityClaim) {
                checkProtectedProgressPressure(pressureProbe);
                CandidateCheckpoint checkpoint = createCandidateCheckpoint(
                        checkpointIdentity, snapshot);
                boolean ownershipPublished = false;
                try {
                    publishCandidateOwnership(checkpointIdentity, checkpoint);
                    ownershipPublished = true;
                    try (SigningMvccRelocationCandidate candidate = index.buildRelocationCandidate(
                            snapshot, checkpointIdentity, checkpoint.header.dataOffset(),
                            activeWalBaseline(), capacityClaim)) {
                        faults.at(Stage.CANDIDATE_BUILT);
                        checkProtectedProgressPressure(pressureProbe);
                        int liveRecords = snapshot.size();
                        long boundarySequence = snapshot.committedSequence();
                        snapshot.close();
                        CommittedPrefixDescriptor finalPrefix = drainCandidateControlled(
                                candidate, finalGate, decoder);
                        SigningManifestCodec.Manifest durable = compactedManifest(
                                boundarySequence, checkpoint.descriptor);
                        publishOnlineCutoverControlled(candidate, finalPrefix, durable,
                                relocationPublicationLock);
                        return new Compaction(rotation, checkpoint.descriptor, liveRecords);
                    }
                } catch (CompactionDeferredException deferred) {
                    if (ownershipPublished) {
                        discardCandidate(checkpointIdentity, checkpoint, deferred);
                    }
                    throw deferred;
                }
            }
        }
    }

    private static void checkProtectedProgressPressure(PressureProbe pressureProbe)
            throws CompactionDeferredException {
        SigningIndexCapacityBudget.CapacityExceededException pressure =
                pressureProbe.current();
        if (pressure != null) {
            throw new CompactionDeferredException(DeferralReason.PROTECTED_PROGRESS, pressure);
        }
    }

    private CommittedPrefixDescriptor drainCandidateControlled(
            SigningMvccRelocationCandidate candidate, FinalGate finalGate,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder) throws IOException {
        try {
            return drainCandidate(candidate, finalGate, decoder);
        } catch (SigningIndexCapacityBudget.CapacityExceededException exhausted) {
            throw new CompactionDeferredException(
                    DeferralReason.TRANSIENT_CAPACITY, exhausted);
        }
    }

    private CandidateCheckpoint createCandidateCheckpoint(long checkpointIdentity,
            SigningMvccIndex.Snapshot snapshot) throws IOException {
        SigningCheckpointCodec.Header header = new SigningCheckpointCodec.Header(
                checkpointIdentity, snapshot.revision(), snapshot.committedSequence(),
                snapshot.size(), snapshot.checkpointDataOffset());
        String name = SigningManifestCodec.checkpointName(snapshot.revision(),
                snapshot.committedSequence());
        Path path = root.resolve(name);
        boolean created = !Files.exists(path, LinkOption.NOFOLLOW_LINKS);
        if (created) {
            SigningFilePublisher.publishImmutable(path,
                    channel -> writeCheckpoint(channel, header, snapshot));
        } else {
            validateExistingCheckpoint(path, header, snapshot);
        }
        faults.at(Stage.CHECKPOINT_PUBLISHED);
        SigningManifestCodec.Checkpoint descriptor = new SigningManifestCodec.Checkpoint(
                checkpointIdentity, snapshot.revision(), snapshot.committedSequence(),
                Files.size(path), fileCommitment(path), name);
        return new CandidateCheckpoint(header, descriptor, created);
    }

    private void publishCandidateOwnership(long checkpointIdentity,
            CandidateCheckpoint checkpoint) {
        generations.create(checkpointIdentity);
        generations.publish(checkpointIdentity);
        artifacts.register(new SigningArtifactCatalog.Artifact(checkpointIdentity,
                checkpoint.descriptor.name(), SigningArtifactCatalog.Kind.CHECKPOINT));
    }

    private CommittedPrefixDescriptor activeWalBaseline() {
        CommittedPrefixDescriptor forced = activeWal.committedPrefix();
        return new CommittedPrefixDescriptor(forced.generationId(),
                forced.exclusiveStartOffset(), forced.exclusiveStartSequence(),
                forced.exclusiveStartRevision(), forced.exclusiveStartCommitment(),
                forced.exclusiveStartOffset(), forced.exclusiveStartSequence(),
                forced.exclusiveStartRevision(), forced.exclusiveStartCommitment());
    }

    private CommittedPrefixDescriptor drainCandidate(SigningMvccRelocationCandidate candidate,
            FinalGate finalGate,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder) throws IOException {
        catchUpOnline(candidate, decoder);
        finalGate.closeAndDrain();
        faults.at(Stage.FINAL_GATE_DRAINED);
        CommittedPrefixDescriptor finalPrefix = activeWal.committedPrefixAfter(
                candidate.acceptedPrefix());
        long finalTail = finalPrefix.inclusiveForcedEndSequence() - candidate.lastSequence();
        long maximumTail = Math.multiplyExact(2L, activeConfiguration.queueCapacity());
        if (finalTail < 0L || finalTail > maximumTail) {
            throw new IllegalStateException(
                    "signing compaction final tail exceeds its lifecycle bound");
        }
        replay(candidate, finalPrefix, decoder);
        requireDrainedEndpoint(candidate, finalPrefix);
        return finalPrefix;
    }

    private SigningManifestCodec.Manifest compactedManifest(
            long boundarySequence,
            SigningManifestCodec.Checkpoint checkpoint) {
        List<SigningManifestCodec.Segment> suffix = suffixAfter(
                boundarySequence, manifest.sealedSegments());
        return new SigningManifestCodec.Manifest(
                manifest.committedRevision(), manifest.committedSequence(),
                Optional.of(checkpoint), suffix, manifest.activeWal());
    }

    private void publishOnlineCutover(SigningMvccRelocationCandidate candidate,
            CommittedPrefixDescriptor finalPrefix, SigningManifestCodec.Manifest durable,
            Object relocationPublicationLock) throws IOException {
        SigningMvccRelocationCandidate.PreparedRootSwap swap;
        synchronized (relocationPublicationLock) {
            if (index.hasPreparedApplies()) {
                throw new IllegalStateException(
                        "signing compaction retained a prepared publication");
            }
            swap = index.prepareRelocationSwap(candidate, index.currentRevision(),
                    index.lastSequence(), finalPrefix.inclusiveForcedEndCommitment());
        }
        try (swap) {
            publishManifest(durable);
            faults.at(Stage.COMPACTION_MANIFEST_READY);
            synchronized (relocationPublicationLock) {
                swap.publish();
            }
            faults.at(Stage.COMPACTION_ROOT_SWAPPED);
        }
        supersedeRemovedGenerations(durable);
        faults.at(Stage.COMPACTION_GENS_SUPERSEDED);
        manifest = durable;
        faults.at(Stage.COMPACTION_MEMORY_PUBLISHED);
    }

    private void publishOnlineCutoverControlled(SigningMvccRelocationCandidate candidate,
            CommittedPrefixDescriptor finalPrefix, SigningManifestCodec.Manifest durable,
            Object relocationPublicationLock) throws IOException {
        try {
            publishOnlineCutover(candidate, finalPrefix, durable, relocationPublicationLock);
        } catch (SigningMvccIndex.RelocationDeferredException deferred) {
            throw new CompactionDeferredException(DeferralReason.SNAPSHOT, deferred);
        } catch (SigningIndexCapacityBudget.CapacityExceededException exhausted) {
            throw new CompactionDeferredException(DeferralReason.STEADY_CAPACITY, exhausted);
        }
    }

    private void discardCandidate(long checkpointIdentity,
            CandidateCheckpoint checkpoint, CompactionDeferredException deferred) {
        artifacts.remove(checkpointIdentity);
        generations.discardPublished(checkpointIdentity);
        if (!checkpoint.created) {
            return;
        }
        try {
            Files.deleteIfExists(root.resolve(checkpoint.descriptor.name()));
            forceDirectory(root);
        } catch (IOException cleanupFailure) {
            deferred.addSuppressed(cleanupFailure);
        }
    }

    private void supersedeRemovedGenerations(SigningManifestCodec.Manifest durable) {
        Set<Long> retained = generationIds(durable);
        for (Long identity : generationIds(manifest)) {
            if (!retained.contains(identity)) {
                generations.supersede(identity);
            }
        }
    }

    private void catchUpOnline(SigningMvccRelocationCandidate candidate,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder) throws IOException {
        try (FileChannel channel = FileChannel.open(
                root.resolve(manifest.activeWal().name()), StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            while (true) {
                CommittedPrefixDescriptor prefix = activeWal.committedPrefixAfter(
                        candidate.acceptedPrefix());
                long tail = prefix.inclusiveForcedEndSequence() - candidate.lastSequence();
                if (tail <= activeConfiguration.queueCapacity()) {
                    return;
                }
                long before = candidate.lastSequence();
                replay(channel, candidate, prefix, decoder);
                if (candidate.lastSequence() == before) {
                    throw new IllegalStateException(
                            "signing compaction catch-up made no projected progress");
                }
            }
        }
    }

    private void replay(SigningMvccRelocationCandidate candidate,
            CommittedPrefixDescriptor prefix,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder) throws IOException {
        try (FileChannel channel = FileChannel.open(
                root.resolve(manifest.activeWal().name()), StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            replay(channel, candidate, prefix, decoder);
        }
    }

    private void replay(FileChannel channel, SigningMvccRelocationCandidate candidate,
            CommittedPrefixDescriptor prefix,
            SigningMvccRelocationCandidate.FrameMutationDecoder decoder) throws IOException {
        candidate.catchUp(channel, prefix, index.currentRevision(), decoder);
    }

    private void requireDrainedEndpoint(SigningMvccRelocationCandidate candidate,
            CommittedPrefixDescriptor forced) {
        if (candidate.revision() != index.currentRevision()
                || candidate.lastSequence() != index.lastSequence()
                || candidate.revision() != forced.inclusiveForcedEndRevision()
                || candidate.lastSequence() != forced.inclusiveForcedEndSequence()
                || !forced.matchesInclusiveForcedEndCommitment(candidate.commitment())
                || index.hasPreparedApplies()) {
            throw new IllegalStateException(
                    "signing compaction drained endpoint is inconsistent");
        }
    }

    private void requireAvailableIdentity(long identity) {
        if (identity <= 0L || generations.contains(identity) || artifacts.contains(identity)
                || generationIds(manifest).contains(identity)) {
            throw new IllegalArgumentException("signing maintenance identity is unavailable");
        }
    }

    /** Deletes at most the claimed bound and durably records directory absence. */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ int reclaim(int maximumActions) throws IOException {
        requireUsable();
        List<SigningGenerationRegistry.ReclaimAction> claims =
                generations.claimReclaimable(maximumActions);
        if (claims.isEmpty()) {
            return 0;
        }
        try {
            for (SigningGenerationRegistry.ReclaimAction claim : claims) {
                for (SigningArtifactCatalog.Artifact artifact
                        : artifacts.artifacts(claim.generationId())) {
                    Path path = root.resolve(artifact.name());
                    validateOwnedArtifact(path, artifact);
                    faults.at(Stage.BEFORE_DELETE);
                    Files.deleteIfExists(path);
                    faults.at(Stage.AFTER_DELETE);
                }
            }
            forceDirectory(root);
            faults.at(Stage.DELETE_DIRECTORY_FORCED);
            for (SigningGenerationRegistry.ReclaimAction claim : claims) {
                artifacts.remove(claim.generationId());
                generations.reclaimCompleted(claim);
            }
            return claims.size();
        } catch (IOException | RuntimeException failure) {
            for (SigningGenerationRegistry.ReclaimAction claim : claims) {
                generations.reclaimFailed(claim);
            }
            throw new MaintenanceException(MaintenanceStage.RECLAIM, failure);
        }
    }

    /** Durably removes recovery-classified artifacts excluded by the authoritative manifest. */
    /* default */ static int cleanupDeferredArtifacts(Path root,
            SigningManifestCodec.Manifest manifest, SigningLedgerRecovery.CleanupPlan plan)
            throws IOException {
        Objects.requireNonNull(root, "root");
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(plan, "plan");
        Set<String> referenced = referencedNames(manifest);
        List<Path> deletions = new ArrayList<>();
        for (SigningLedgerRecovery.CleanupEntry entry : plan.entries()) {
            if (entry.category() != SigningLedgerRecovery.Category.ORPHAN_ARTIFACT_DEFERRED) {
                continue;
            }
            if (referenced.contains(entry.name())) {
                throw new IOException("signing cleanup artifact became authoritative");
            }
            Path path = root.resolve(entry.name());
            validateDeferredArtifact(path, entry.name());
            deletions.add(path);
        }
        if (deletions.isEmpty()) {
            return 0;
        }
        for (Path path : deletions) {
            Files.deleteIfExists(path);
        }
        forceDirectory(root);
        return deletions.size();
    }

    private static Set<String> referencedNames(SigningManifestCodec.Manifest manifest) {
        Set<String> names = new HashSet<>();
        manifest.checkpoint().ifPresent(checkpoint -> names.add(checkpoint.name()));
        manifest.sealedSegments().forEach(segment -> names.add(segment.name()));
        names.add(manifest.activeWal().name());
        return Set.copyOf(names);
    }

    private static void validateDeferredArtifact(Path path, String name) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new IOException("signing cleanup artifact type changed");
        }
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            long identity;
            SigningArtifactCatalog.Kind kind;
            if (name.startsWith("checkpoint-")) {
                identity = SigningCheckpointCodec.reader(channel).header().generationIdentity();
                kind = SigningArtifactCatalog.Kind.CHECKPOINT;
            } else {
                ByteBuffer header = ByteBuffer.allocate(SigningWalContainerCodec.HEADER_BYTES);
                SigningFormatSupport.readFully(channel, header,
                        "signing cleanup WAL header is truncated");
                identity = SigningWalContainerCodec.decode(header.array()).identity();
                kind = name.startsWith("wal-active-") ? SigningArtifactCatalog.Kind.ACTIVE_WAL
                        : SigningArtifactCatalog.Kind.SEALED_WAL;
            }
            new SigningArtifactCatalog.Artifact(identity, name, kind);
        }
    }

    /* default */ SigningManifestCodec.Manifest manifest() {
        return manifest;
    }

    /* default */ SigningActiveWal activeWal() {
        return activeWal;
    }

    /* default */ boolean recoveryRequired() {
        return recoveryRequired.get();
    }

    /* default */ long sourceChannelsOpened() {
        return sourceChannelsOpened;
    }

    private void writeCheckpoint(FileChannel channel, SigningCheckpointCodec.Header header,
            SigningMvccIndex.Snapshot snapshot) throws IOException {
        SigningCheckpointCodec.Writer writer = SigningCheckpointCodec.writer(channel, header);
        long[] offset = { header.dataOffset() };
        snapshot.visit(record -> {
            SigningMvccIndex.RecordPointer pointer = record.pointer();
            writer.writeIndex(new SigningCheckpointCodec.EntryDescriptor(
                    record.key().canonical(), pointer.recordType(), offset[0],
                    pointer.frameLength(), record.revision(), pointer.sequence()));
            offset[0] = Math.addExact(offset[0], pointer.frameLength());
        });
        writer.beginData();
        offset[0] = header.dataOffset();
        try (FrameBatch batch = new FrameBatch(writer)) {
            snapshot.visit(record -> {
                SigningMvccIndex.RecordPointer pointer = record.pointer();
                SigningCheckpointCodec.EntryDescriptor entry =
                        new SigningCheckpointCodec.EntryDescriptor(record.key().canonical(),
                                pointer.recordType(), offset[0], pointer.frameLength(),
                                record.revision(), pointer.sequence());
                batch.add(entry, pointer);
                offset[0] = Math.addExact(offset[0], pointer.frameLength());
            });
            batch.flush();
        }
        writer.finish();
    }

    private void validateExistingCheckpoint(Path path, SigningCheckpointCodec.Header expected,
            SigningMvccIndex.Snapshot snapshot) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS); FrameBatch sources = new FrameBatch(null)) {
            SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
            if (!reader.header().equals(expected)) {
                throw new IOException("existing signing checkpoint is not the retried image");
            }
            snapshot.visit(record -> {
                SigningCheckpointCodec.EntryDescriptor entry = reader.next().orElseThrow(
                        () -> new IOException("existing signing checkpoint is incomplete"));
                SigningMvccIndex.RecordPointer pointer = record.pointer();
                if (!entry.key().equals(record.key().canonical())
                        || entry.recordType() != pointer.recordType()
                        || entry.revision() != record.revision()
                        || entry.sequence() != pointer.sequence()
                        || !java.util.Arrays.equals(SigningWalFrameCodec.encode(
                                reader.readFrame(entry)), sources.readOne(pointer))) {
                    throw new IOException("existing signing checkpoint is not the retried image");
                }
            });
            if (reader.next().isPresent()) {
                throw new IOException("existing signing checkpoint has unexpected entries");
            }
            reader.verifyComplete();
        }
    }

    private void relocateSnapshot(SigningMvccIndex.Snapshot snapshot,
            long checkpointIdentity, long firstFrameOffset) throws IOException {
        index.relocateSnapshot(snapshot, checkpointIdentity, firstFrameOffset);
    }

    private void publishSealedOrAdopt(Path source, Path target, SigningActiveWal.Seal sealed)
            throws IOException {
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(target) != sealed.length()
                    || !java.security.MessageDigest.isEqual(fileCommitment(target),
                            sealed.fileCommitment())) {
                throw new IOException("existing signing segment is not the retried image");
            }
            return;
        }
        Files.createLink(target, source);
        faults.at(Stage.SEALED_LINK_CREATED);
        forceDirectory(target.getParent());
    }

    private void publishManifest(SigningManifestCodec.Manifest candidate) throws IOException {
        byte[] encoded = SigningManifestCodec.encode(candidate);
        SigningFilePublisher.publishManifest(root.resolve(SigningLedgerRecovery.MANIFEST_FILE),
                channel -> SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(encoded)));
    }

    private static byte[] fileCommitment(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            return SigningFileCommitment.sha256(channel);
        }
    }

    private static SigningManifestCodec.ActiveWal activeDescriptor(
            SigningActiveWal.Descriptor descriptor) {
        byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                descriptor.identity(), descriptor.firstSequence(), descriptor.baselineRevision()));
        return new SigningManifestCodec.ActiveWal(descriptor.identity(),
                descriptor.firstSequence(), descriptor.baselineRevision(), header.length,
                SigningFormatSupport.sha256().digest(header),
                SigningManifestCodec.activeName(descriptor.identity()));
    }

    private static List<SigningManifestCodec.Segment> suffixAfter(long sequence,
            List<SigningManifestCodec.Segment> segments) {
        List<SigningManifestCodec.Segment> result = new ArrayList<>();
        for (SigningManifestCodec.Segment segment : segments) {
            if (segment.firstSequence() > sequence) {
                result.add(segment);
            }
        }
        return List.copyOf(result);
    }

    private static Set<Long> generationIds(SigningManifestCodec.Manifest value) {
        Set<Long> result = new HashSet<>();
        value.checkpoint().ifPresent(checkpoint -> result.add(checkpoint.generationIdentity()));
        for (SigningManifestCodec.Segment segment : value.sealedSegments()) {
            result.add(segment.generationIdentity());
        }
        result.add(value.activeWal().identity());
        return Set.copyOf(result);
    }

    @SuppressWarnings("PMD.EmptyCatchBlock")
    private static void validateOwnedArtifact(Path path,
            SigningArtifactCatalog.Artifact artifact) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new IOException("signing reclaim artifact type changed");
        }
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            long embedded;
            if (artifact.kind() == SigningArtifactCatalog.Kind.CHECKPOINT) {
                embedded = SigningCheckpointCodec.reader(channel).header().generationIdentity();
            } else {
                ByteBuffer header = ByteBuffer.allocate(SigningWalContainerCodec.HEADER_BYTES);
                SigningFormatSupport.readFully(channel, header,
                        "signing reclaim WAL header is truncated");
                embedded = SigningWalContainerCodec.decode(header.array()).identity();
            }
            if (embedded != artifact.generationIdentity()) {
                throw new IOException("signing reclaim artifact identity changed");
            }
        } catch (NoSuchFileException absent) {
            // Durable absence is established by the following directory force.
        }
    }

    private static void forceDirectory(Path directory) throws IOException {
        SigningFormatSupport.forceDirectory(directory);
    }

    private void requireUsable() {
        if (closed || recoveryRequired.get()) {
            throw new IllegalStateException("signing ledger maintenance requires recovery");
        }
    }

    /** Stable externally safe maintenance failure stages. */
    /* default */ enum MaintenanceStage {
        /** Active-WAL rotation or segment publication. */
        ROTATE,
        /** Checkpoint construction or adoption. */
        CHECKPOINT,
        /** Manifest publication. */
        MANIFEST,
        /** In-memory ownership publication. */
        MEMORY,
        /** Durable artifact reclamation. */
        RECLAIM
    }

    /** Stable path-free maintenance failure; the cause remains internal. */
    /* default */ static final class MaintenanceException extends IOException {
        private static final long serialVersionUID = -2454842338520977330L;
        private final MaintenanceStage stage;

        private MaintenanceException(MaintenanceStage stage, Throwable cause) {
            super("signing ledger maintenance failed: " + stage.name(), cause);
            this.stage = stage;
        }

        /* default */ MaintenanceStage stage() { return stage; }
    }

    /** Controlled online-compaction deferral that leaves the rotated store usable. */
    /* default */ static final class CompactionDeferredException extends IOException {
        private static final long serialVersionUID = 1L;
        private final DeferralReason reason;

        private CompactionDeferredException(DeferralReason reason, Throwable cause) {
            super("signing online compaction is deferred: " + reason.name(), cause);
            this.reason = Objects.requireNonNull(reason, "reason");
        }

        /* default */ DeferralReason reason() {
            return reason;
        }
    }

    /** Internal resource condition that may safely defer online compaction. */
    /* default */ enum DeferralReason {
        /** Accepted signing progress needs the steady workspace released first. */
        PROTECTED_PROGRESS,
        /** Detached candidate cannot reserve its transient memory envelope. */
        TRANSIENT_CAPACITY,
        /** Candidate cannot be transferred into the steady memory envelope. */
        STEADY_CAPACITY,
        /** An external live snapshot still depends on the displaced root. */
        SNAPSHOT
    }

    private static void closeAfterFailure(SigningActiveWal wal, Throwable failure) {
        if (wal != null) {
            try {
                wal.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
        }
    }

    private static void closeAfterFailure(AutoCloseable closeable, Throwable failure) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception closeFailure) {
                failure.addSuppressed(closeFailure);
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
            activeWal.close();
        }
    }

    /** Deterministic package-local maintenance crash-boundary seam. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface FaultInjector {
        /** Called immediately after the named durable or in-memory boundary. */
        void at(Stage stage) throws IOException;
    }

    /** Closes ordinary admission and drains all preexisting lifecycle slots. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface FinalGate {
        /** Returns only after preparation and admitted-projection ownership is empty. */
        void closeAndDrain() throws IOException;
    }

    /** Lock-free per-call observation of newly raised protected-progress pressure. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface PressureProbe {
        /** Returns the current pressure cause, or {@code null} when compaction may continue. */
        SigningIndexCapacityBudget.CapacityExceededException current();
    }

    /** Stable boundaries available to deterministic fault tests. */
    /* default */ enum Stage {
        /** The old writer is drained and closed. */
        ACTIVE_DRAINED,
        /** The immutable-segment hard link exists but its directory is not yet forced. */
        SEALED_LINK_CREATED,
        /** The immutable copied segment is durable. */
        SEALED_PUBLISHED,
        /** The next empty active WAL is durable. */
        NEXT_ACTIVE_PUBLISHED,
        /** The rotation manifest is durable. */
        MANIFEST_PUBLISHED,
        /** Rotation memory ownership is published. */
        MEMORY_PUBLISHED,
        /** The self-contained checkpoint is durable. */
        CHECKPOINT_PUBLISHED,
        /** The detached checkpoint candidate is complete but not manifest-authoritative. */
        CANDIDATE_BUILT,
        /** Admission is closed and all lifecycle slots are drained. */
        FINAL_GATE_DRAINED,
        /** The compacted manifest is durable. */
        COMPACTION_MANIFEST_READY,
        /** The prevalidated detached MVCC root is live. */
        COMPACTION_ROOT_SWAPPED,
        /** Manifest-removed generations were superseded after the root swap. */
        COMPACTION_GENS_SUPERSEDED,
        /** Compaction memory ownership and relocation are published. */
        COMPACTION_MEMORY_PUBLISHED,
        /** An exact artifact is about to be deleted. */
        BEFORE_DELETE,
        /** An exact artifact deletion has returned. */
        AFTER_DELETE,
        /** The artifact directory has been forced after deletion. */
        DELETE_DIRECTORY_FORCED
    }

    /* default */ record Rotation(SigningManifestCodec.Segment sealed,
            SigningManifestCodec.ActiveWal active, SigningMvccIndex.Snapshot boundary) {
    }

    /* default */ record Compaction(Rotation rotation,
            SigningManifestCodec.Checkpoint checkpoint, int liveRecords) {
    }

    /** Unreferenced durable checkpoint and its validated construction header. */
    private record CandidateCheckpoint(SigningCheckpointCodec.Header header,
            SigningManifestCodec.Checkpoint descriptor, boolean created) {
    }

    /** In-memory preflight ownership established before rotation or topology changes. */
    private record OnlinePreflight(SigningMvccIndex.Snapshot snapshot,
            SigningMvccIndex.RelocationCapacity capacityClaim) implements AutoCloseable {
        private OnlinePreflight {
            Objects.requireNonNull(snapshot, "snapshot");
            Objects.requireNonNull(capacityClaim, "capacityClaim");
        }

        @Override
        public void close() {
            capacityClaim.close();
            snapshot.close();
        }
    }

    /* default */ record Configuration(long maximumActiveSegmentBytes,
            int maximumSourceGenerations) {
        private static final long DEFAULT_SEGMENT_BYTES = 256L * 1024L * 1024L;
        private static final int DEFAULT_SOURCE_GENERATIONS = 64;

        /* default */ Configuration(long maximumActiveSegmentBytes) {
            this(maximumActiveSegmentBytes, DEFAULT_SOURCE_GENERATIONS);
        }

        Configuration {
            if (maximumActiveSegmentBytes < SigningWalContainerCodec.HEADER_BYTES
                    || maximumActiveSegmentBytes > SigningManifestCodec.MAX_FILE_BYTES
                    || maximumSourceGenerations <= 0 || maximumSourceGenerations > 256) {
                throw new IllegalArgumentException("signing maintenance configuration is invalid");
            }
        }

        private static Configuration defaults() {
            return new Configuration(DEFAULT_SEGMENT_BYTES, DEFAULT_SOURCE_GENERATIONS);
        }
    }

    /** Bounded generation-local source batch that prevents adversarial channel thrashing. */
    private final class FrameBatch implements AutoCloseable {
        private static final int MAXIMUM_ENTRIES = 4_096;
        private static final long MAXIMUM_BYTES = 64L * 1024L * 1024L;
        private final SigningCheckpointCodec.Writer writer;
        private final List<BatchEntry> ordered = new ArrayList<>(MAXIMUM_ENTRIES);
        private final Map<Long, List<BatchEntry>> byGeneration = new LinkedHashMap<>();
        private final Map<Long, FileChannel> channels = new LinkedHashMap<>();
        private long bytes;

        private FrameBatch(SigningCheckpointCodec.Writer writer) {
            this.writer = writer;
        }

        private void add(SigningCheckpointCodec.EntryDescriptor descriptor,
                SigningMvccIndex.RecordPointer pointer) throws IOException {
            if (!ordered.isEmpty() && (ordered.size() == MAXIMUM_ENTRIES
                    || Math.addExact(bytes, pointer.frameLength()) > MAXIMUM_BYTES)) {
                flush();
            }
            BatchEntry entry = new BatchEntry(descriptor, pointer);
            ordered.add(entry);
            byGeneration.computeIfAbsent(pointer.generationId(), ignored -> new ArrayList<>())
                    .add(entry);
            bytes = Math.addExact(bytes, pointer.frameLength());
        }

        @SuppressWarnings("PMD.CloseResource")
        private void flush() throws IOException {
            for (Map.Entry<Long, List<BatchEntry>> generation : byGeneration.entrySet()) {
                FileChannel channel = sourceChannel(generation.getKey());
                for (BatchEntry entry : generation.getValue()) {
                    entry.encoded = readValidated(channel, entry.pointer);
                }
            }
            if (writer != null) {
                for (BatchEntry entry : ordered) {
                    writer.writeValidatedFrame(entry.descriptor, entry.encoded);
                }
            }
            ordered.clear();
            byGeneration.clear();
            bytes = 0L;
        }

        private byte[] readOne(SigningMvccIndex.RecordPointer pointer) throws IOException {
            return readValidated(sourceChannel(pointer.generationId()), pointer);
        }

        private FileChannel sourceChannel(long generationIdentity) throws IOException {
            FileChannel existing = channels.get(generationIdentity);
            if (existing != null) {
                return existing;
            }
            if (channels.size() >= configuration.maximumSourceGenerations()) {
                throw new IOException("signing checkpoint source-generation bound is exhausted");
            }
            SigningArtifactCatalog.Artifact artifact = artifacts.readable(generationIdentity);
            FileChannel opened = FileChannel.open(root.resolve(artifact.name()),
                    StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
            channels.put(generationIdentity, opened);
            sourceChannelsOpened++;
            return opened;
        }

        private byte[] readValidated(FileChannel channel,
                SigningMvccIndex.RecordPointer pointer) throws IOException {
            ByteBuffer encoded = ByteBuffer.allocate(pointer.frameLength());
            channel.position(pointer.frameOffset());
            SigningFormatSupport.readFully(channel, encoded, "signing source frame is truncated");
            byte[] bytes = encoded.array();
            SigningWalFrameCodec.Frame frame = SigningWalFrameCodec.decode(bytes);
            if (frame.sequence() != pointer.sequence()
                    || frame.recordType() != pointer.recordType()) {
                throw new IOException("signing source frame pointer is inconsistent");
            }
            return bytes;
        }

        @Override
        @SuppressWarnings("PMD.CloseResource")
        public void close() throws IOException {
            IOException failure = null;
            for (FileChannel channel : channels.values()) {
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    if (failure == null) {
                        failure = closeFailure;
                    } else {
                        failure.addSuppressed(closeFailure);
                    }
                }
            }
            channels.clear();
            ordered.clear();
            byGeneration.clear();
            if (failure != null) {
                throw failure;
            }
        }
    }

    /** One semantic-order output and its generation-grouped source pointer. */
    private static final class BatchEntry {
        private final SigningCheckpointCodec.EntryDescriptor descriptor;
        private final SigningMvccIndex.RecordPointer pointer;
        private byte[] encoded;

        private BatchEntry(SigningCheckpointCodec.EntryDescriptor descriptor,
                SigningMvccIndex.RecordPointer pointer) {
            this.descriptor = descriptor;
            this.pointer = pointer;
        }
    }
}
