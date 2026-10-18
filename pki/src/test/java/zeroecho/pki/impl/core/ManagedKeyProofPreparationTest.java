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

package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofChallenge;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class ManagedKeyProofPreparationTest {
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Duration TTL = Duration.ofMinutes(5);
    private static final String SIGNATURE = BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm();
    private static final KeyRef KEY = new KeyRef("managed-key");
    private static final PkiId AUTHORITY = new PkiId("logical-authority");
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "actor"),
            new Purpose("PROVE"), Optional.empty(), Optional.empty());
    private static final byte[] SPKI = HexFormat.of().parseHex("302a300506032b6570032100" + "00".repeat(32));

    @Test void preparesBothPurposesWithExactProviderAndFreshNonceSubmissionAndCommitments() throws Exception {
        Fixture fixture = new Fixture();
        ManagedKeyProofPreparation preparation = fixture.preparer();
        byte[] previousNonce = null;
        PkiId previousId = null;
        for (ManagedKeyProofRequest request : List.of(ca(), new ManagedKeyProofRequest.OcspResponder(
                AUTHORITY, new PkiId("responder"), KEY))) {
            SigningSubmissionId submission = fixture.submission();
            DomainSigningRequest prepared = preparation.prepare(ACCESS, request, submission, TTL, CancellationSignal.NONE);
            assertEquals(submission.id(), prepared.operationId());
            assertNotEquals(previousId, prepared.operationId());
            assertSame(ACCESS, prepared.accessContext());
            assertEquals(KEY, prepared.keyRef());
            assertEquals(TTL, prepared.ttl());
            assertEquals(SIGNATURE, prepared.algorithmId());
            assertEquals(Encoding.BINARY, prepared.signatureEncoding());
            assertEquals(Encoding.BINARY, prepared.content().encoding());
            assertEquals(DurableContentReference.Lifecycle.OPERATION, prepared.content().lifecycle());
            assertEquals(DomainContinuationStore.Kind.KEY_PROOF, prepared.domainTemplate().kind());
            byte[] staged = fixture.stagedBytes.toByteArray();
            ManagedKeyProofChallenge.Decoded challenge = ManagedKeyProofChallenge.decode(staged);
            assertEquals(prepared.operationId(), challenge.operationId());
            assertArrayEquals(SPKI, challenge.spki());
            assertFalse(java.util.Arrays.equals(previousNonce, challenge.nonce()));
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(prepared.domainTemplate().command());
            assertEquals(challenge.command(), command);
            ManagedKeyProofCommand.validateComplete(command);
            assertEquals(Integer.toString(staged.length), command.field(12));
            assertEquals(prepared.content().sha256(), command.field(13));
            assertEquals("11".repeat(32), command.field(7));
            assertEquals("store.provider", command.field(6));
            assertEquals("300506032b6570", command.field(9));
            assertEquals(Optional.of("key-proof." + ContentCommitment.sha256(prepared.operationId().value()
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8)).sha256()), prepared.domainTemplate().correlationId());
            assertEquals(request, ManagedKeyProofCommand.decodePrefix(command));
            assertEquals(AUTHORITY, ManagedKeyProofCommand.authorityId(request));
            assertEquals(SemanticSigningKind.KEY_PROOF, ManagedKeyProofCommand.scope(command, ACCESS, KEY).kind());
            assertEquals(Optional.of(AUTHORITY), ManagedKeyProofCommand.scope(command, ACCESS, KEY).authorityId());
            assertEquals(command, DomainContinuationValidation.validate(prepared.domainTemplate()));
            previousNonce = challenge.nonce();
            previousId = prepared.operationId();
        }
        assertEquals(2, fixture.lookups);
        assertEquals(2, fixture.begins);
        assertEquals(2, fixture.completes);
        assertEquals(2, fixture.closes);
        assertEquals(0, fixture.retirements);
    }

    @Test void rejectsMissingSourceWrongExecutorUnsupportedAndMismatchedAlgorithmsBeforeStaging() {
        Fixture missing = new Fixture();
        SigningProvider noSource = missing.provider(false);
        ManagedKeyProofPreparation absent = missing.preparer(noSource, PkiTestRuntime.signingAuthority(noSource));
        assertThrows(IllegalArgumentException.class, () -> absent.prepare(ACCESS, ca(), missing.submission(), TTL,
                CancellationSignal.NONE));
        assertEquals(0, missing.lookups);
        assertEquals(0, missing.begins);

        Fixture foreign = new Fixture();
        ManagedKeyProofPreparation wrong = foreign.preparer(foreign.provider,
                PkiTestRuntime.signingAuthority(foreign.provider(true)));
        assertThrows(IllegalArgumentException.class, () -> wrong.prepare(ACCESS, ca(), foreign.submission(), TTL,
                CancellationSignal.NONE));
        assertEquals(1, foreign.lookups);
        assertEquals(0, foreign.begins);

        Fixture unsupported = new Fixture();
        ManagedKeyProofPreparation selected = unsupported.preparer();
        unsupported.supported = Set.of();
        assertThrows(IllegalArgumentException.class, () -> selected.prepare(ACCESS, ca(), unsupported.submission(), TTL,
                CancellationSignal.NONE));
        assertEquals(0, unsupported.lookups);
        assertEquals(0, unsupported.begins);

        Fixture mismatch = new Fixture();
        mismatch.exported = new EncodedObject(Encoding.DER,
                HexFormat.of().parseHex("3043300506032b6571033a00" + "00".repeat(57)));
        assertThrows(IllegalArgumentException.class, () -> mismatch.run());
        assertEquals(0, mismatch.begins);

        Fixture wrongVerifier = new Fixture();
        ManagedKeyProofPreparation unbound = new ManagedKeyProofPreparation(wrongVerifier.store, wrongVerifier.provider,
                PkiTestRuntime.signingAuthority(wrongVerifier.provider), wrongVerifier.verificationAuthority,
                new BcX509VerificationExecutor(), SIGNATURE, wrongVerifier.random, Integer.MAX_VALUE - 8L);
        assertThrows(IllegalArgumentException.class, () -> unbound.prepare(ACCESS, ca(), wrongVerifier.submission(), TTL,
                CancellationSignal.NONE));
        assertEquals(0, wrongVerifier.begins);
    }

    @Test void rejectsProviderContentAndInputBoundsWithoutAnyStaging() {
        for (EncodedObject invalid : List.of(new EncodedObject(Encoding.BINARY, SPKI),
                new EncodedObject(Encoding.DER, new byte[] {0x30, 0}))) {
            Fixture fixture = new Fixture();
            fixture.exported = invalid;
            assertThrows(Exception.class, fixture::run);
            assertEquals(0, fixture.begins);
        }
        Fixture raw = new Fixture();
        raw.rawMaximum = 1;
        assertThrows(IllegalArgumentException.class, raw::run);
        assertEquals(0, raw.begins);
        Fixture pure = new Fixture();
        pure.pureMaximum = 1;
        assertThrows(IllegalArgumentException.class, pure::run);
        assertEquals(0, pure.begins);
        Fixture metadata = new Fixture();
        assertThrows(IllegalArgumentException.class, () -> metadata.preparer().prepare(ACCESS, ca(),
                metadata.submission(), Duration.ZERO, CancellationSignal.NONE));
        assertThrows(ArithmeticException.class, () -> metadata.preparer().prepare(ACCESS, ca(),
                metadata.submission(), Duration.ofSeconds(Long.MAX_VALUE), CancellationSignal.NONE));
        assertEquals(0, metadata.lookups);
        assertEquals(0, metadata.begins);
    }

    @Test void rejectsOversizedExportAtMetadataBoundaryWithoutStaging() {
        Fixture fixture = new Fixture();
        fixture.exported = new EncodedObject(Encoding.DER, new byte[ManagedKeyProofCommand.MAX_SPKI_BYTES + 1]);
        assertEquals(ManagedKeyProofCommand.MAX_SPKI_BYTES + 1, fixture.exported.byteLength());
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, fixture::run);
        assertEquals("Managed public key exceeds its finite byte bound", failure.getMessage());
        assertEquals(1, fixture.lookups);
        assertEquals(0, fixture.begins);
        assertEquals(0, fixture.retirements);
    }

    @Test void cancellationBeforeAndAfterLookupNeverStages() {
        Fixture before = new Fixture();
        before.cancelled = true;
        assertThrows(InterruptedIOException.class, before::run);
        assertEquals(0, before.lookups);
        assertEquals(0, before.begins);
        Fixture after = new Fixture();
        after.cancelOnLookup = true;
        assertThrows(InterruptedIOException.class, after::run);
        assertEquals(1, after.lookups);
        assertEquals(0, after.begins);
    }

    @Test void stagingFailuresClosePartialSinksAndRetireOnlyCompletedUnownedContent() {
        for (Cut cut : List.of(Cut.OPEN, Cut.WRITE, Cut.COMPLETE, Cut.CLOSE, Cut.CANCEL_WRITE, Cut.CANCEL_COMPLETE)) {
            Fixture fixture = new Fixture();
            fixture.cut = cut;
            assertThrows(IOException.class, fixture::run);
            assertEquals(1, fixture.begins);
            assertEquals(cut == Cut.OPEN ? 0 : 1, fixture.closes);
            assertEquals(cut == Cut.CLOSE || cut == Cut.CANCEL_COMPLETE ? 1 : 0, fixture.retirements);
            assertEquals(cut == Cut.OPEN || cut == Cut.CLOSE || cut == Cut.CANCEL_COMPLETE ? 0 : 1, fixture.aborts);
        }
        Fixture suppressed = new Fixture();
        suppressed.cut = Cut.CANCEL_COMPLETE;
        suppressed.retireFailure = true;
        InterruptedIOException failure = assertThrows(InterruptedIOException.class, suppressed::run);
        assertEquals(1, failure.getSuppressed().length);
        assertEquals("retirement failed", failure.getSuppressed()[0].getMessage());
        assertEquals(1, suppressed.retirements);
    }

    private static ManagedKeyProofRequest ca() {
        return new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.of(new PkiId("subject")), "profile", KEY);
    }

    private enum Cut { NONE, OPEN, WRITE, COMPLETE, CLOSE, CANCEL_WRITE, CANCEL_COMPLETE }

    private static final class Fixture {
        private final SecureRandom random = new SecureRandom() {
            private int invocation;
            @Override public void nextBytes(byte[] bytes) { java.util.Arrays.fill(bytes, (byte) ++invocation); }
        };
        private final BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
        private final X509AuthoritySnapshot verificationAuthority = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        Direction.VERIFY, verifier)), (suite, direction) -> direction == Direction.VERIFY);
        private Set<String> supported = Set.of(SIGNATURE);
        private EncodedObject exported = new EncodedObject(Encoding.DER, SPKI);
        private long rawMaximum = ManagedKeyProofCommand.MAX_CHALLENGE_BYTES;
        private long pureMaximum = ManagedKeyProofCommand.MAX_CHALLENGE_BYTES;
        private boolean cancelled;
        private boolean cancelOnLookup;
        private boolean retireFailure;
        private Cut cut = Cut.NONE;
        private int lookups;
        private int begins;
        private int completes;
        private int closes;
        private int aborts;
        private int retirements;
        private ByteArrayOutputStream stagedBytes;
        private final SigningProvider provider = provider(true);
        private final StagedContentStore staging = (StagedContentStore) Proxy.newProxyInstance(
                StagedContentStore.class.getClassLoader(), new Class<?>[] {StagedContentStore.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "beginContent" -> {
                        assertEquals(Encoding.BINARY, args[0]);
                        assertEquals(DurableContentReference.Lifecycle.OPERATION, args[1]);
                        begins++;
                        if (cut == Cut.OPEN) { throw new IOException("open failed"); }
                        yield sink();
                    }
                    case "retireUnownedContent" -> {
                        retirements++;
                        assertEquals("candidate", ((DurableContentReference) args[0]).contentId());
                        if (retireFailure) { throw new IOException("retirement failed"); }
                        yield null;
                    }
                    default -> throw new AssertionError("No acceptance or ownership writes: " + method.getName());
                });
        private final PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] {PkiStore.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "signingNamespace" -> "store";
                    case "signingNow" -> NOW;
                    case "signingHorizon" -> Duration.ofDays(90);
                    case "signingPermittedSkew" -> Duration.ZERO;
                    case "stagedContent" -> staging;
                    default -> throw new AssertionError("No acceptance, reservation or business lookup: " + method.getName());
                });

        private SigningProvider provider(boolean source) {
            return (SigningProvider) Proxy.newProxyInstance(SigningProvider.class.getClassLoader(),
                    source ? new Class<?>[] {SigningProvider.class, PublicKeyInfoSource.class}
                            : new Class<?>[] {SigningProvider.class}, (proxy, method, args) -> switch (method.getName()) {
                        case "id" -> "provider";
                        case "supportedAlgorithms" -> supported;
                        case "configurationCommitment" -> new SigningProvider.ConfigurationCommitment(
                                HexFormat.of().parseHex("11".repeat(32)));
                        case "inputCapabilities" -> new SigningInputCapabilities(rawMaximum, Map.of());
                        case "resolvePublicKeyInfo" -> {
                            assertEquals(KEY, args[0]);
                            lookups++;
                            if (cancelOnLookup) { cancelled = true; }
                            yield exported;
                        }
                        default -> throw new AssertionError("No provider execution or fallback: " + method.getName());
                    });
        }

        private SigningSubmissionId submission() { return SigningSubmissionId.create("store.provider", NOW, random); }
        private ManagedKeyProofPreparation preparer() { return preparer(provider, PkiTestRuntime.signingAuthority(provider)); }
        private ManagedKeyProofPreparation preparer(SigningProvider selected, X509AuthoritySnapshot signing) {
            return new ManagedKeyProofPreparation(store, selected, signing, verificationAuthority, verifier, SIGNATURE,
                    random, pureMaximum);
        }
        private DomainSigningRequest run() throws IOException {
            return preparer().prepare(ACCESS, ca(), submission(), TTL, () -> cancelled);
        }

        private ContentSink sink() {
            stagedBytes = new ByteArrayOutputStream();
            return new ContentSink() {
                private boolean complete;
                @Override public OutputStream outputStream() {
                    return new OutputStream() {
                        @Override public void write(int value) throws IOException {
                            if (cut == Cut.WRITE) { throw new IOException("write failed"); }
                            stagedBytes.write(value);
                            if (cut == Cut.CANCEL_WRITE) { cancelled = true; }
                        }
                    };
                }
                @Override public long length() { return stagedBytes.size(); }
                @Override public DurableContentReference complete() throws IOException {
                    if (cut == Cut.COMPLETE) { throw new IOException("complete failed"); }
                    complete = true;
                    completes++;
                    if (cut == Cut.CANCEL_COMPLETE) { cancelled = true; }
                    return new Content(stagedBytes.size(), ContentCommitment.sha256(stagedBytes.toByteArray()).sha256());
                }
                @Override public void abort() { aborts++; }
                @Override public void close() throws IOException {
                    closes++;
                    if (!complete) { abort(); }
                    if (cut == Cut.CLOSE) { throw new IOException("close failed"); }
                }
            };
        }
    }

    private record Content(long length, String sha256) implements DurableContentReference {
        @Override public String storeId() { return "store"; }
        @Override public String contentId() { return "candidate"; }
        @Override public Encoding encoding() { return Encoding.BINARY; }
        @Override public Lifecycle lifecycle() { return Lifecycle.OPERATION; }
    }
}
