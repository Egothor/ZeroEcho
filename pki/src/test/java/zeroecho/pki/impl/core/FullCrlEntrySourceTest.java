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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.PkiTestRuntime;

class FullCrlEntrySourceTest {
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00.750Z");
    private static final Instant TRANSITION = NOW.minusSeconds(10);
    private static final Instant BEFORE = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant AFTER = Instant.parse("2030-01-01T00:00:00Z");
    private static final CertificateProfileRef PROFILE = new CertificateProfileRef("root", 1, new byte[32]);
    private static KeyPair key;
    private static KeyPair foreignKey;
    private static byte[] firstDer;
    private static byte[] rolloverDer;
    private static byte[] foreignNameDer;
    private static byte[] foreignKeyDer;

    @BeforeAll static void certificates() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        foreignKey = generator.generateKeyPair();
        firstDer = certificate("CN=Issuer", 1, key, true);
        rolloverDer = certificate("CN=Issuer", 2, key, true);
        foreignNameDer = certificate("CN=Other", 3, key, true);
        foreignKeyDer = certificate("CN=Issuer", 4, foreignKey, true);
    }

    @Test void twoIndependentPassesShareOneSnapshotDespiteLaterMutationAndFilterByNameAndSpki() throws Exception {
        Fixture fixture = new Fixture();
        fixture.record("first", "10", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
        fixture.record("rollover", "20", fixture.rollover, RevocationState.PERMANENTLY_REVOKED,
                Optional.of(RevocationReason.KEY_COMPROMISE), NOW);
        fixture.record("foreign-name", "30", fixture.foreignName, RevocationState.HELD, Optional.empty(), TRANSITION);
        fixture.record("foreign-key", "40", fixture.foreign, RevocationState.HELD, Optional.empty(), TRANSITION);
        try (FullCrlEntrySource source = fixture.source(CancellationSignal.NONE)) {
            assertEquals(1, fixture.snapshots.size());
            assertEquals("snapshot-4", source.snapshotId());
            assertEquals(4, source.revision());
            assertEquals(400, source.boundary());
            assertEquals("ab".repeat(32), source.commitment());
            assertTrue(source.count().isEmpty());
            fixture.record("later", "50", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
            fixture.records.set(0, record(new PkiId("first"), RevocationState.CLEAR, Optional.empty(), TRANSITION));
            try (CrlEntrySource.Cursor first = source.openCursor(); CrlEntrySource.Cursor second = source.openCursor()) {
                assertThrows(IllegalStateException.class, first::current);
                assertThrows(IllegalStateException.class, first::ordinal);
                assertTrue(first.next());
                assertEquals(new CrlEntry(BigInteger.TEN, TRANSITION, RevocationReason.CERTIFICATE_HOLD), first.current());
                assertEquals(0, first.ordinal());
                assertTrue(first.next());
                assertEquals(BigInteger.valueOf(20), first.current().serialNumber());
                assertEquals(NOW, first.current().transitionTime());
                assertEquals(RevocationReason.KEY_COMPROMISE, first.current().reason());
                assertEquals(1, first.ordinal());
                assertTrue(second.next());
                assertEquals(BigInteger.TEN, second.current().serialNumber());
                assertEquals(0, second.ordinal());
                assertFalse(first.next());
                assertFalse(first.next());
                assertThrows(IllegalStateException.class, first::current);
                assertThrows(IllegalStateException.class, first::ordinal);
                assertTrue(second.next());
                assertEquals(BigInteger.valueOf(20), second.current().serialNumber());
                assertFalse(second.next());
            }
            assertEquals(2, fixture.snapshots.getFirst().cursorCloses);
            assertEquals(1, fixture.snapshots.size());
        }
        assertEquals(1, fixture.snapshots.getFirst().closes);
    }

    @Test void clearIsOmittedWhilePermanentReasonsAndFullPositiveSerialArePreserved() throws Exception {
        Fixture fixture = new Fixture();
        fixture.record("clear", "1", fixture.first, RevocationState.CLEAR, Optional.empty(), TRANSITION);
        BigInteger largest = BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE);
        fixture.record("large", largest.toString(), fixture.rollover, RevocationState.PERMANENTLY_REVOKED,
                Optional.of(RevocationReason.UNSPECIFIED), TRANSITION);
        // Historical generation availability is not a filter on its existing revocations.
        IssuerGeneration original = fixture.generations.get(fixture.rollover);
        fixture.generations.put(fixture.rollover, new IssuerGeneration(original.issuerId(), original.authorityId(),
                original.credentialId(), original.signingKeyRef(), IssuerGenerationState.COMPROMISED,
                original.profilePolicyCommitment(), original.x509BindingCommitment()));
        try (FullCrlEntrySource source = fixture.source(CancellationSignal.NONE); CrlEntrySource.Cursor cursor = source.openCursor()) {
            assertTrue(cursor.next());
            assertEquals(new CrlEntry(largest, TRANSITION, RevocationReason.UNSPECIFIED), cursor.current());
            assertEquals(0, cursor.ordinal());
            assertFalse(cursor.next());
        }
    }

    @Test void deltaUsesGlobalCutoffIncludesClearAndFreezesLaterAppends() throws Exception {
        Fixture fixture = new Fixture();
        fixture.record("old-held", "1", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
        fixture.record("old-clear", "2", fixture.first, RevocationState.CLEAR, Optional.empty(), TRANSITION);
        fixture.record("released", "3", fixture.first, RevocationState.CLEAR, Optional.empty(), TRANSITION);
        fixture.record("new-held", "4", fixture.rollover, RevocationState.HELD, Optional.empty(), TRANSITION);
        fixture.deltaBase = Optional.of(new DeltaCrlBase(new PkiId("crl:" + "aa".repeat(32)), BigInteger.ONE,
                new zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance(
                        new zeroecho.pki.spi.store.MetadataStoreId("102030405060708090a0b0c0d0e0f001"), 2, 200, "ab".repeat(32))));
        try (FullCrlEntrySource source = fixture.source(CancellationSignal.NONE)) {
            fixture.record("later", "5", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
            for (int pass = 0; pass < 2; pass++) {
                try (CrlEntrySource.Cursor cursor = source.openCursor()) {
                    assertTrue(cursor.next());
                    assertEquals(BigInteger.valueOf(3), cursor.current().serialNumber());
                    assertEquals(RevocationReason.REMOVE_FROM_CRL, cursor.current().reason());
                    assertEquals(TRANSITION, cursor.current().transitionTime());
                    assertTrue(cursor.next());
                    assertEquals(BigInteger.valueOf(4), cursor.current().serialNumber());
                    assertEquals(RevocationReason.CERTIFICATE_HOLD, cursor.current().reason());
                    assertFalse(cursor.next());
                }
            }
        }
        assertEquals(1, fixture.prefixChecks);
        assertEquals(1, fixture.snapshots.getFirst().closes);
    }

    @Test void deltaStillValidatesMalformedRowsBeforeItsCutoff() throws Exception {
        Fixture fixture = new Fixture();
        fixture.record("old-malformed", "not-a-serial", fixture.first, RevocationState.CLEAR, Optional.empty(), TRANSITION);
        fixture.deltaBase = Optional.of(new DeltaCrlBase(new PkiId("crl:" + "aa".repeat(32)), BigInteger.ONE,
                new zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance(
                        new zeroecho.pki.spi.store.MetadataStoreId("102030405060708090a0b0c0d0e0f001"), 1, 100, "ab".repeat(32))));
        assertRejected(fixture);
        assertEquals(1, fixture.prefixChecks);
    }

    @Test void removeReasonIsCorruptionInEveryCurrentState() throws Exception {
        for (RevocationState state : RevocationState.values()) {
            Fixture fixture = new Fixture();
            fixture.record("remove", "2", fixture.first, state, Optional.of(RevocationReason.REMOVE_FROM_CRL), TRANSITION);
            assertRejected(fixture);
        }
    }

    @Test void orphanSameScopeGenerationAbsentFromFrozenAuthorityIsRejected() throws Exception {
        Fixture fixture = new Fixture();
        PkiId orphan = fixture.issuer("orphan", "CN=Issuer", 2, rolloverDer, fixture.prepared.authorityId());
        fixture.record("leaf", "7", orphan, RevocationState.HELD, Optional.empty(), TRANSITION);
        assertFalse(fixture.prepared.authority().issuerIds().contains(orphan));
        assertRejected(fixture);
        assertEquals(0, fixture.authorityReads);
    }

    @Test void liveAuthorityRemovalDoesNotChangeEitherFrozenPass() throws Exception {
        Fixture fixture = new Fixture();
        fixture.record("leaf", "7", fixture.rollover, RevocationState.HELD, Optional.empty(), TRANSITION);
        CaRecord frozen = fixture.prepared.authority();
        try (FullCrlEntrySource source = fixture.source(CancellationSignal.NONE); CrlEntrySource.Cursor first = source.openCursor()) {
            assertTrue(first.next());
            fixture.liveAuthority = new CaRecord(frozen.caId(), frozen.kind(), frozen.state(), frozen.issuerKeyRef(),
                    frozen.subjectRef(), List.of(fixture.first), fixture.first, frozen.issuanceChainPathId());
            try (CrlEntrySource.Cursor second = source.openCursor()) {
                assertTrue(second.next());
                assertEquals(first.current(), second.current());
                assertEquals(0, first.ordinal());
                assertEquals(0, second.ordinal());
                assertFalse(first.next());
                assertFalse(second.next());
            }
        }
        assertSame(frozen, fixture.prepared.authority());
        assertFalse(fixture.liveAuthority.issuerIds().contains(fixture.rollover));
        assertEquals(0, fixture.authorityReads);
    }

    @Test void newlyAddedLiveGenerationCannotEnterFrozenMembership() throws Exception {
        Fixture fixture = new Fixture();
        CaRecord frozen = fixture.prepared.authority();
        PkiId added = fixture.issuer("added", "CN=Issuer", 2, rolloverDer, frozen.caId());
        List<PkiId> liveMembers = new ArrayList<>(frozen.issuerIds());
        liveMembers.add(added);
        fixture.liveAuthority = new CaRecord(frozen.caId(), frozen.kind(), frozen.state(), frozen.issuerKeyRef(),
                frozen.subjectRef(), liveMembers, frozen.currentIssuanceIssuerId(), frozen.issuanceChainPathId());
        fixture.record("leaf", "7", added, RevocationState.HELD, Optional.empty(), TRANSITION);
        assertTrue(fixture.liveAuthority.issuerIds().contains(added));
        assertFalse(frozen.issuerIds().contains(added));
        try (FullCrlEntrySource source = fixture.source(CancellationSignal.NONE);
                CrlEntrySource.Cursor first = source.openCursor(); CrlEntrySource.Cursor second = source.openCursor()) {
            assertThrows(IOException.class, first::next);
            assertThrows(IOException.class, second::next);
        }
        assertEquals(0, fixture.authorityReads);
    }

    @Test void invalidReasonsAndFutureTransitionsFailClosedBeforeAnyEntry() throws Exception {
        for (RevocationTransition transition : List.of(
                new RevocationTransition(1, RevocationState.PERMANENTLY_REVOKED, TRANSITION, Optional.empty(), new SimpleAttributeSet()),
                new RevocationTransition(1, RevocationState.PERMANENTLY_REVOKED, TRANSITION,
                        Optional.of(RevocationReason.CERTIFICATE_HOLD), new SimpleAttributeSet()),
                new RevocationTransition(1, RevocationState.HELD, TRANSITION,
                        Optional.of(RevocationReason.KEY_COMPROMISE), new SimpleAttributeSet()),
                new RevocationTransition(1, RevocationState.CLEAR, NOW.plusNanos(1), Optional.empty(), new SimpleAttributeSet()))) {
            Fixture fixture = new Fixture();
            fixture.record("leaf", "7", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
            fixture.records.set(0, new RevocationRecord(new PkiId("leaf"), transition));
            assertRejected(fixture);
        }
    }

    @Test void noncanonicalAndOutOfRangeSerialsFailClosed() throws Exception {
        for (String invalid : List.of("0", "-1", "+1", "01", "1.0", "1 ", "١", "9".repeat(49),
                BigInteger.ONE.shiftLeft(159).toString())) {
            Fixture fixture = new Fixture();
            fixture.record("leaf", invalid, fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
            assertRejected(fixture);
        }
    }

    @Test void missingOrMismatchedCredentialGenerationAndIssuerAreRejected() throws Exception {
        for (int fault = 0; fault < 6; fault++) {
            Fixture fixture = new Fixture();
            fixture.record("leaf", "7", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
            PkiId leaf = new PkiId("leaf");
            PkiId issuer = fixture.generations.get(fixture.first).credentialId();
            switch (fault) {
                case 0 -> fixture.credentials.remove(leaf);
                case 1 -> fixture.generations.remove(fixture.first);
                case 2 -> fixture.credentials.remove(issuer);
                case 3 -> fixture.credentials.put(leaf, fixture.credentials.get(issuer));
                case 4 -> fixture.generations.put(fixture.first, fixture.generations.get(fixture.rollover));
                case 5 -> fixture.credentials.put(issuer, fixture.credentials.get(leaf));
                default -> throw new AssertionError();
            }
            assertRejected(fixture);
        }
    }

    @Test void corruptIssuerContentMetadataAndGenerationCommitmentAreRejected() throws Exception {
        for (int fault = 0; fault < 5; fault++) {
            Fixture fixture = new Fixture();
            fixture.record("leaf", "7", fixture.rollover, RevocationState.HELD, Optional.empty(), TRANSITION);
            IssuerGeneration generation = fixture.generations.get(fixture.rollover);
            Credential issuer = fixture.credentials.get(generation.credentialId());
            switch (fault) {
                case 0 -> {
                    byte[] altered = rolloverDer.clone(); altered[altered.length - 1] ^= 1;
                    fixture.content.put(issuer.content().contentId(), altered);
                }
                case 1 -> fixture.replaceIssuerContent(issuer, new byte[] {1});
                case 2 -> fixture.replaceIssuerContent(issuer, certificate("CN=Wrong", 2, key, true));
                case 3 -> fixture.replaceIssuerContent(issuer, certificate("CN=Issuer", 2, key, false));
                case 4 -> fixture.generations.put(fixture.rollover, new IssuerGeneration(generation.issuerId(),
                        generation.authorityId(), generation.credentialId(), generation.signingKeyRef(), generation.state(),
                        "01".repeat(32), generation.x509BindingCommitment()));
                default -> throw new AssertionError();
            }
            assertRejected(fixture);
        }
    }

    @Test void sameScopeCannotMoveToAnotherAuthorityAndPreparedIssuerCannotChange() throws Exception {
        Fixture fixture = new Fixture();
        PkiId alien = fixture.issuer("alien", "CN=Issuer", 2, rolloverDer, new PkiId("ca:alien"));
        fixture.record("leaf", "7", alien, RevocationState.HELD, Optional.empty(), TRANSITION);
        assertRejected(fixture);
        Fixture changed = new Fixture();
        changed.record("leaf", "7", changed.first, RevocationState.HELD, Optional.empty(), TRANSITION);
        IssuerGeneration generation = changed.generations.get(changed.first);
        changed.generations.put(changed.first, new IssuerGeneration(generation.issuerId(), generation.authorityId(),
                generation.credentialId(), new KeyRef("changed"), generation.state(), generation.profilePolicyCommitment(),
                generation.x509BindingCommitment()));
        assertRejected(changed);
    }

    @Test void cancellationPropagatesToUnderlyingCursorAndInvalidatesThePass() throws Exception {
        Fixture fixture = new Fixture();
        fixture.record("leaf", "7", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
        AtomicBoolean cancelled = new AtomicBoolean();
        CancellationSignal signal = cancelled::get;
        try (FullCrlEntrySource source = fixture.source(signal); CrlEntrySource.Cursor cursor = source.openCursor()) {
            assertTrue(cursor.next());
            assertSame(signal, fixture.snapshots.getFirst().lastCancellation);
            cancelled.set(true);
            assertThrows(IOException.class, cursor::next);
            assertThrows(IllegalStateException.class, cursor::current);
            assertThrows(IllegalStateException.class, cursor::next);
            assertThrows(IOException.class, source::openCursor);
        }
        assertEquals(1, fixture.snapshots.getFirst().cursorCloses);
        Fixture beforeOpen = new Fixture();
        assertThrows(IOException.class, () -> beforeOpen.source(() -> true));
        assertTrue(beforeOpen.snapshots.isEmpty());
    }

    @Test void sourceAndCursorCloseAreIdempotentAndRejectFurtherUse() throws Exception {
        Fixture fixture = new Fixture();
        fixture.record("leaf", "7", fixture.first, RevocationState.HELD, Optional.empty(), TRANSITION);
        FullCrlEntrySource source = fixture.source(CancellationSignal.NONE);
        CrlEntrySource.Cursor first = source.openCursor();
        CrlEntrySource.Cursor second = source.openCursor();
        assertTrue(first.next());
        first.close(); first.close();
        assertThrows(IllegalStateException.class, first::next);
        assertThrows(IllegalStateException.class, first::current);
        source.close(); source.close();
        assertThrows(IllegalStateException.class, source::openCursor);
        assertThrows(IllegalStateException.class, source::count);
        assertThrows(IllegalStateException.class, source::snapshotId);
        assertThrows(IllegalStateException.class, second::next);
        assertThrows(IllegalStateException.class, second::current);
        second.close();
        assertEquals(1, fixture.snapshots.getFirst().closes);
        assertEquals(2, fixture.snapshots.getFirst().cursorCloses);
    }

    private static void assertRejected(Fixture fixture) throws Exception {
        try (FullCrlEntrySource source = fixture.source(CancellationSignal.NONE); CrlEntrySource.Cursor cursor = source.openCursor()) {
            assertThrows(IOException.class, cursor::next);
            assertThrows(IllegalStateException.class, cursor::current);
            assertThrows(IllegalStateException.class, cursor::ordinal);
            assertThrows(IllegalStateException.class, cursor::next);
        }
    }

    private static RevocationRecord record(PkiId id, RevocationState state, Optional<RevocationReason> reason, Instant time) {
        return new RevocationRecord(id, new RevocationTransition(1, state, time, reason, new SimpleAttributeSet()));
    }

    private static byte[] certificate(String dn, int serial, KeyPair pair, boolean ca) throws Exception {
        X500Name name = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(serial),
                Date.from(BEFORE), Date.from(AFTER), name, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())).getEncoded();
    }

    private static Content content(String id, byte[] bytes) throws Exception {
        return new Content("store", id, Encoding.DER, bytes.length,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
                DurableContentReference.Lifecycle.PERSISTED);
    }

    private static final class Fixture {
        private final Map<PkiId, Credential> credentials = new HashMap<>();
        private final Map<PkiId, IssuerGeneration> generations = new HashMap<>();
        private final Map<String, byte[]> content = new HashMap<>();
        private final List<RevocationRecord> records = new ArrayList<>();
        private final List<Snapshot> snapshots = new ArrayList<>();
        private final PkiId first;
        private final PkiId rollover;
        private final PkiId foreignName;
        private final PkiId foreign;
        private CaRecord liveAuthority;
        private int authorityReads;
        private final FullCrlPreparation.Prepared prepared;
        private Optional<DeltaCrlBase> deltaBase = Optional.empty();
        private int prefixChecks;

        private Fixture() throws Exception {
            PkiId authority = new PkiId("ca:root");
            first = issuer("first", "CN=Issuer", 1, firstDer, authority);
            rollover = issuer("rollover", "CN=Issuer", 2, rolloverDer, authority);
            foreignName = issuer("other-name", "CN=Other", 3, foreignNameDer, authority);
            foreign = issuer("other-key", "CN=Issuer", 4, foreignKeyDer, authority);
            liveAuthority = new CaRecord(authority, CaKind.ROOT, CaState.ACTIVE, new KeyRef("key:first"),
                    new SubjectRef("CN=Issuer"), List.of(first, rollover, foreignName, foreign), first, new PkiId("path:first"));
            IssuerGeneration generation = generations.get(first);
            Credential credential = credentials.get(generation.credentialId());
            X509AuthoritySnapshot runtime = PkiTestRuntime.signingAuthority(new EndEntityIssuancePreparationTest.CountingProvider());
            X509AlgorithmBinding binding = ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors())
                    .standard(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, X509AlgorithmBinding.Role.CRL_SIGNATURE).orElseThrow();
            prepared = new FullCrlPreparation.Prepared(liveAuthority, generation, credential.credentialId(), PROFILE,
                    credential.content(), CrlScope.of(new X500Name("CN=Issuer").getEncoded(), key.getPublic().getEncoded()),
                    binding, runtime.planSigning(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), SigningProvider.class).selection().binding(),
                    NOW, NOW.minusNanos(750_000_000), NOW.plusSeconds(3600).minusNanos(750_000_000), firstDer, Optional.empty());
        }

        private PkiId issuer(String name, String dn, int serial, byte[] der, PkiId authority) throws Exception {
            PkiId id = new PkiId("issuer-credential:" + name);
            PkiId generation = IssuerGeneration.idFor(authority, id);
            Content reference = content(name, der);
            content.put(name, der);
            credentials.put(id, new Credential(id, new FormatId("x509"),
                    new IssuerRef(authority, generation, new PkiId("path:" + name)), new SubjectRef(dn),
                    new Validity(BEFORE, AFTER), Integer.toString(serial), new PkiId("key:" + name),
                    new CaProfileBinding(PROFILE), CredentialStatus.ISSUED, reference, new SimpleAttributeSet()));
            generations.put(generation, new IssuerGeneration(generation, authority, id, new KeyRef("key:" + name),
                    IssuerGenerationState.ACTIVE, "00".repeat(32), "00".repeat(32)));
            return generation;
        }

        private void replaceIssuerContent(Credential issuer, byte[] der) throws Exception {
            Content reference = content(issuer.content().contentId(), der);
            content.put(reference.contentId(), der);
            credentials.put(issuer.credentialId(), new Credential(issuer.credentialId(), issuer.formatId(), issuer.issuerRef(),
                    issuer.subjectRef(), issuer.validity(), issuer.serialOrUniqueId(), issuer.publicKeyId(), issuer.profileBinding(),
                    issuer.status(), reference, issuer.attributes()));
        }

        private void record(String name, String serial, PkiId generationId, RevocationState state,
                Optional<RevocationReason> reason, Instant time) throws Exception {
            PkiId id = new PkiId(name);
            IssuerGeneration generation = generations.get(generationId);
            credentials.put(id, new Credential(id, new FormatId("x509"),
                    new IssuerRef(generation.authorityId(), generationId, new PkiId("path:" + name)),
                    new SubjectRef("CN=" + name), new Validity(BEFORE, AFTER), serial, new PkiId("leaf-key"),
                    new EndEntityProfileBinding(PROFILE), CredentialStatus.ISSUED, content("unused-leaf", new byte[0]),
                    new SimpleAttributeSet()));
            records.add(FullCrlEntrySourceTest.record(id, state, reason, time));
        }

        private FullCrlEntrySource source(CancellationSignal cancellation) throws IOException {
            StagedContentStore contentStore = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                    new Class<?>[] {StagedContentStore.class}, (proxy, method, args) -> {
                        assertEquals("openContent", method.getName(), "F2 cannot stage or mutate content");
                        DurableContentReference reference = (DurableContentReference) args[0];
                        byte[] der = content.get(reference.contentId());
                        if (der == null) { throw new IOException("Missing issuer content"); }
                        return new ImmutableByteContent(der);
                    });
            PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] {PkiStore.class},
                    (proxy, method, args) -> switch (method.getName()) {
                        case "openRevocationSnapshot" -> {
                            Snapshot snapshot = new Snapshot(List.copyOf(records)); snapshots.add(snapshot); yield snapshot;
                        }
                        case "getCredential" -> Optional.ofNullable(credentials.get(args[0]));
                        case "getIssuerGeneration" -> Optional.ofNullable(generations.get(args[0]));
                        case "getCa" -> { authorityReads++; yield Optional.of(liveAuthority); }
                        case "stagedContent" -> contentStore;
                        case "requireRevocationPrefix" -> {
                            prefixChecks++;
                            DeltaCrlBase base = deltaBase.orElseThrow();
                            zeroecho.pki.spi.store.RevocationTransitionFeed.HighWatermark prefix =
                                    (zeroecho.pki.spi.store.RevocationTransitionFeed.HighWatermark) args[0];
                            assertEquals(base.provenance().sourceStoreId(), prefix.sourceStoreId());
                            assertEquals(base.provenance().revision(), prefix.globalRevision());
                            assertEquals(base.provenance().commitment(), prefix.transitionCommitment());
                            assertEquals(base.provenance().boundary(), args[1]);
                            yield null;
                        }
                        default -> throw new AssertionError("Unexpected F2 store operation: " + method.getName());
                    });
            FullCrlPreparation.Prepared exact = new FullCrlPreparation.Prepared(prepared.authority(), prepared.generation(),
                    prepared.credentialId(), prepared.profile(), prepared.issuerContent(), prepared.scope(),
                    prepared.signatureBinding(), prepared.signatureIdentifier(), prepared.evaluationTime(), prepared.thisUpdate(),
                    prepared.nextUpdate(), prepared.issuerDer(), deltaBase);
            return new FullCrlEntrySource(store, exact, cancellation);
        }
    }

    private record Content(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference { }

    private static final class Snapshot implements RevocationSnapshot {
        private final List<RevocationRecord> entries;
        private boolean closed;
        private int closes;
        private int cursorCloses;
        private CancellationSignal lastCancellation;

        private Snapshot(List<RevocationRecord> entries) { this.entries = entries; }
        @Override public zeroecho.pki.spi.store.MetadataStoreId sourceStoreId() {
                    return new zeroecho.pki.spi.store.MetadataStoreId("102030405060708090a0b0c0d0e0f001");
                }
                @Override public String snapshotId() { return "snapshot-" + entries.size(); }
        @Override public long revision() { return entries.size(); }
        @Override public long boundary() { return entries.size() * 100L; }
        @Override public String commitment() { return "ab".repeat(32); }
        @Override public OptionalLong count() { return OptionalLong.of(entries.size()); }
        @Override public void close() { if (!closed) { closes++; closed = true; } }
        @Override public Cursor openCursor() {
            if (closed) { throw new IllegalStateException("Snapshot closed"); }
            return new Cursor() {
                private int index = -1;
                private boolean cursorClosed;
                @Override public boolean next(CancellationSignal cancellation) throws IOException {
                    if (closed || cursorClosed) { throw new IllegalStateException("Cursor closed"); }
                    lastCancellation = cancellation;
                    cancellation.throwIfCancelled();
                    index++;
                    return index < entries.size();
                }
                @Override public RevocationRecord current() { return entries.get(index); }
                @Override public long currentGlobalRevision() { return index + 1L; }
                @Override public long ordinal() { return index; }
                @Override public void close() { if (!cursorClosed) { cursorCloses++; cursorClosed = true; } }
            };
        }
    }
}
