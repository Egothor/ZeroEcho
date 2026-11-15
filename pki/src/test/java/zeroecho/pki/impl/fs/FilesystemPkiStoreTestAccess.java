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

import java.nio.file.Path;
import java.time.Clock;

/** Narrow test access to the package-private signing-capacity constructor. */
public final class FilesystemPkiStoreTestAccess {
    private FilesystemPkiStoreTestAccess() { }

    /** Opens a filesystem store with a deterministic small signing-work bound. */
    public static FilesystemPkiStore open(Path root, int maximumSigningWork) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), Clock.systemUTC(),
                maximumSigningWork, null);
    }

    /** Opens a filesystem store with deterministic time and signing-work bound. */
    public static FilesystemPkiStore open(Path root, int maximumSigningWork, Clock clock) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock,
                maximumSigningWork, null);
    }
    /** Opens the actual store with configured public verifier callbacks and a test-only work bound. */
    public static FilesystemPkiStore open(Path root, int maximumSigningWork,
            zeroecho.pki.spi.store.PkiStoreRuntimeDependencies dependencies, AdoptionForceFault fault) {
        return open(root, maximumSigningWork, dependencies, fault, 512L * 1024 * 1024);
    }

    /** Opens the actual store with a test-selected resident budget. */
    public static FilesystemPkiStore open(Path root, int maximumSigningWork,
            zeroecho.pki.spi.store.PkiStoreRuntimeDependencies dependencies, AdoptionForceFault fault, long residentBytes) {
        var options = FsPkiStoreOptions.defaults().withSigningResidentIndexBudgetBytes(residentBytes);
        if (dependencies.issuerAlgorithmEvidenceVerifier().isPresent()) {
            options = options.withIssuerAlgorithmEvidenceVerifier(dependencies.issuerAlgorithmEvidenceVerifier().orElseThrow());
        }
        if (dependencies.crlHybridNativeChildVerifier().isPresent()) {
            options = options.withCrlHybridNativeChildVerifier(dependencies.crlHybridNativeChildVerifier().orElseThrow());
        }
        return new FilesystemPkiStore(root, options, dependencies.clock(), maximumSigningWork,
                fault == null ? null : new AdoptionOperations(fault));
    }

    /** Returns the original failure retained by a fenced local signing ledger. */
    public static Throwable firstRecoveryFailure(FilesystemPkiStore store) {
        return store.firstLocalSigningRecoveryFailure();
    }

    /** Quiescent real-store resident-budget observation; no production quota is changed. */
    public static ResidentBudget residentBudget(FilesystemPkiStore store) {
        var observation = store.metadataStore().capacitySnapshot().steady();
        return new ResidentBudget(observation.reservedBytes(), observation.highWaterReservedBytes(), observation.maximumBytes());
    }
    /** Actual steady ledger budget values. */
    public record ResidentBudget(long reserved, long highWater, long maximum) { }

    /** One-shot loss of acknowledgement after the actual native-child adoption group is forced. */
    public static final class AdoptionForceFault {
        private final java.util.concurrent.atomic.AtomicBoolean armed = new java.util.concurrent.atomic.AtomicBoolean();
        private final java.util.concurrent.atomic.AtomicBoolean fired = new java.util.concurrent.atomic.AtomicBoolean();
        /** Arms the next semantic adoption transaction, independently of unrelated WAL writes. */
        public void arm() { armed.set(true); }
        /** @return whether a real adoption force was followed by the injected IOException */
        public boolean fired() { return fired.get(); }
    }

    private static final class AdoptionOperations implements SigningActiveWal.Operations {
        private final AdoptionForceFault fault;
        private AdoptionOperations(AdoptionForceFault fault) { this.fault = fault; }
        @Override public boolean exists(Path path) { return java.nio.file.Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) { return java.nio.file.Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS); }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws java.io.IOException {
            return channel(java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.CREATE_NEW,
                    java.nio.file.StandardOpenOption.READ, java.nio.file.StandardOpenOption.WRITE));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws java.io.IOException {
            return channel(java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.READ,
                    java.nio.file.StandardOpenOption.WRITE));
        }
        @Override public void forceDirectory(Path directory) throws java.io.IOException { SigningFormatSupport.forceDirectory(directory); }
        private SigningActiveWal.WalChannel channel(java.nio.channels.FileChannel delegate) {
            return new SigningActiveWal.WalChannel() {
                private boolean adoptionWritten;
                @Override public int write(java.nio.ByteBuffer source) throws java.io.IOException {
                    var observed = source.duplicate();
                    int written = delegate.write(source);
                    observed.limit(observed.position() + written);
                    // The actual writer submits complete encoded groups. Match the reverse-link mutation,
                    // not a write count, so certificate creation and checkpoint traffic cannot trigger it.
                    while (observed.remaining() >= SigningWalFrameCodec.HEADER_BYTES) {
                        int length = observed.getInt(observed.position() + 8);
                        if (length < SigningWalFrameCodec.HEADER_BYTES || length > observed.remaining()) break;
                        byte[] frame = new byte[length]; observed.get(frame);
                        try {
                            var decoded = SigningWalFrameCodec.decode(frame);
                            var payload = SigningTransactionPayloadCodec.decode(decoded.payload());
                            adoptionWritten |= payload.mutations().stream().anyMatch(mutation ->
                                    CrlHybridMetadata.REVERSE_NAMESPACE.equals(mutation.key().namespace())
                                            && mutation.kind() == SigningTransactionPayloadCodec.MutationKind.CREATE);
                        } catch (java.io.IOException ignored) { /* Container/commit marker or non-metadata frame. */ }
                    }
                    return written;
                }
                @Override public void force(boolean metadata) throws java.io.IOException {
                    delegate.force(metadata);
                    if (adoptionWritten && fault.armed.compareAndSet(true, false)) {
                        fault.fired.set(true);
                        throw new java.io.IOException("Injected lost acknowledgement after durable hybrid CRL adoption");
                    }
                    adoptionWritten = false;
                }
                @Override public int read(java.nio.ByteBuffer target) throws java.io.IOException { return delegate.read(target); }
                @Override public long position() throws java.io.IOException { return delegate.position(); }
                @Override public SigningActiveWal.WalChannel position(long value) throws java.io.IOException { delegate.position(value); return this; }
                @Override public long size() throws java.io.IOException { return delegate.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long value) throws java.io.IOException { delegate.truncate(value); return this; }
                @Override public boolean isOpen() { return delegate.isOpen(); }
                @Override public void close() throws java.io.IOException { delegate.close(); }
            };
        }
    }
}
