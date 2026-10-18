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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.lang.reflect.RecordComponent;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.TBSCertList;
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
import zeroecho.pki.api.PkiException;
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
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pkix.Pkix;

class FullCrlTbsPreparationTest {
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Instant BEFORE = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant AFTER = Instant.parse("2030-01-01T00:00:00Z");
    private static final CertificateProfileRef PROFILE = new CertificateProfileRef("root", 1, new byte[32]);
    private static byte[] issuerDer;
    private static KeyPair key;

    @BeforeAll static void certificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        issuerDer = certificateWithSki(null);
    }

    private static byte[] certificateWithSki(byte[] innerDer) throws Exception {
        X500Name name = new X500Name("CN=Issuer");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(BEFORE), Date.from(AFTER), name, key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        if (innerDer != null) { builder.addExtension(Extension.subjectKeyIdentifier, false, innerDer); }
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
    }

    @Test void stagesEmptyAndNonemptyTbsAfterOneCompletePassAndReturnsOnlyFrozenResourceFreeEvidence() throws Exception {
        for (int count : new int[] {0, 2}) {
            Fixture fixture = new Fixture(count);
            PreparedFullCrlTbs result = fixture.run();
            assertEquals(new zeroecho.pki.spi.store.MetadataStoreId("102030405060708090a0b0c0d0e0f001"),
                    result.snapshotSourceStoreId());
            assertEquals(1, fixture.reservations);
            assertEquals(1, fixture.begins);
            assertEquals(1, fixture.completions);
            assertEquals(0, fixture.aborts);
            assertEquals(0, fixture.retirements);
            assertEquals(2, fixture.cursorOpens);
            assertEquals(2, fixture.cursorCloses);
            assertEquals(1, fixture.snapshotOpens);
            assertEquals(1, fixture.snapshotCloses);
            assertEquals(BigInteger.ONE, result.crlNumber());
            assertEquals(BigInteger.TWO, fixture.nextNumber);
            assertEquals(fixture.prepared.authorityId(), result.authorityId());
            assertEquals(fixture.prepared.generation().issuerId(), result.issuerGenerationId());
            assertEquals(fixture.prepared.credentialId(), result.issuerCredentialId());
            assertEquals(fixture.prepared.profile(), result.profile());
            assertEquals(fixture.prepared.issuerContent(), result.issuerContent());
            assertEquals(fixture.prepared.scope().digest(), result.scopeDigest());
            assertEquals(fixture.prepared.signatureBinding(), result.signatureBinding());
            assertSame(fixture.prepared.signatureIdentifier(), result.signatureIdentifier());
            assertEquals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), result.signatureAlgorithm());
            assertEquals("snapshot", result.snapshotId());
            assertEquals(23, result.snapshotRevision());
            assertEquals(456, result.snapshotBoundary());
            assertEquals("ab".repeat(32), result.snapshotCommitment());
            assertEquals(OptionalLong.of(count), result.rawEntryCount());
            assertEquals(count, result.emittedEntryCount());
            assertEquals(NOW.plusNanos(5), result.evaluationTime());
            assertEquals(NOW, result.thisUpdate());
            assertEquals(NOW.plusSeconds(3600), result.nextUpdate());
            assertEquals(fixture.output.size(), result.tbsContent().length());
            assertEquals(DurableContentReference.Lifecycle.OPERATION, result.tbsContent().lifecycle());
            new StreamingDerReader().validate(fixture.output.toByteArray(), fixture.output.size());
            Set<Class<?>> allowed = Set.of(PkiId.class, CertificateProfileRef.class, DurableContentReference.class,
                    String.class, KeyRef.class, X509AlgorithmBinding.class, BigInteger.class, Instant.class,
                    long.class, OptionalLong.class, Optional.class, X509AlgorithmIdentifier.class, zeroecho.pki.spi.store.MetadataStoreId.class);
            for (RecordComponent component : PreparedFullCrlTbs.class.getRecordComponents()) {
                assertTrue(allowed.contains(component.getType()), component.getName());
                if (component.getType() == Optional.class) {
                    assertEquals("java.util.Optional<zeroecho.pki.impl.core.DeltaCrlBase>", component.getGenericType().getTypeName());
                }
            }
        }
    }

    @Test void firstPassReadCloseAndCancellationFailuresDoNotReserveOrOpenSink() throws Exception {
        for (Cut cut : List.of(Cut.FIRST_READ, Cut.FIRST_CLOSE, Cut.CANCEL_FIRST)) {
            Fixture fixture = new Fixture(2);
            fixture.cut = cut;
            assertThrows(IOException.class, fixture::run);
            assertEquals(0, fixture.reservations);
            assertEquals(0, fixture.begins);
            assertEquals(BigInteger.ONE, fixture.nextNumber);
            assertEquals(1, fixture.cursorCloses);
            assertEquals(1, fixture.snapshotCloses);
        }
        Fixture cancelled = new Fixture(2);
        cancelled.cancelled.set(true);
        assertThrows(IOException.class, cancelled::run);
        assertEquals(0, cancelled.snapshotOpens);
        assertEquals(0, cancelled.reservations);
    }

    @Test void reservationFailureClosesSnapshotWithoutOpeningSink() throws Exception {
        Fixture fixture = new Fixture(2);
        fixture.cut = Cut.RESERVE;
        assertThrows(PkiException.class, fixture::run);
        assertEquals(1, fixture.reservations);
        assertEquals(0, fixture.begins);
        assertEquals(1, fixture.snapshotCloses);
    }

    @Test void postReservationFailuresLeaveGapAndAbortEveryIncompleteSink() throws Exception {
        for (Cut cut : List.of(Cut.CANCEL_RESERVED, Cut.SINK_OPEN, Cut.OUTPUT_OPEN, Cut.WRITE,
                Cut.CANCEL_WRITE, Cut.SECOND_READ, Cut.SECOND_CLOSE, Cut.COMPLETE, Cut.LENGTH,
                Cut.DIVERGENT_COUNT, Cut.DIVERGENT_LENGTH)) {
            Fixture fixture = new Fixture(2);
            fixture.cut = cut;
            assertThrows(IOException.class, fixture::run, cut.name());
            assertEquals(1, fixture.reservations, cut.name());
            assertEquals(BigInteger.TWO, fixture.nextNumber, cut.name());
            assertEquals(0, fixture.completions, cut.name());
            assertEquals(0, fixture.retirements, cut.name());
            assertEquals(1, fixture.snapshotCloses, cut.name());
            assertEquals(cut == Cut.CANCEL_RESERVED || cut == Cut.SINK_OPEN ? 0 : 1, fixture.aborts, cut.name());
        }
    }

    @Test void postCompletionFailuresRetireUnownedContentAndKeepCleanupFailuresSuppressed() throws Exception {
        for (Cut cut : List.of(Cut.CANCEL_COMPLETE, Cut.COMPLETED_LENGTH, Cut.OUTPUT_CLOSE, Cut.SINK_CLOSE, Cut.SNAPSHOT_CLOSE)) {
            Fixture fixture = new Fixture(2);
            fixture.cut = cut;
            assertThrows(IOException.class, fixture::run, cut.name());
            assertEquals(1, fixture.completions, cut.name());
            assertEquals(1, fixture.retirements, cut.name());
            assertEquals(0, fixture.aborts, cut.name());
            assertEquals(1, fixture.snapshotCloses, cut.name());
            assertEquals(BigInteger.TWO, fixture.nextNumber, cut.name());
        }
        Fixture fixture = new Fixture(2);
        fixture.cut = Cut.SNAPSHOT_CLOSE;
        fixture.retireFails = true;
        IOException failure = assertThrows(IOException.class, fixture::run);
        assertEquals("snapshot close", failure.getMessage());
        assertEquals(1, failure.getSuppressed().length);
        assertEquals("retirement", failure.getSuppressed()[0].getMessage());
    }

    @Test void completionAttributesAndAuthoritativeRestoreAreCheckedWithoutForeignCleanup() throws Exception {
        for (Cut cut : List.of(Cut.NULL_REFERENCE, Cut.FOREIGN_REFERENCE, Cut.NULL_STORE, Cut.ENCODING,
                Cut.LIFECYCLE, Cut.EMPTY_ID, Cut.NULL_ID, Cut.INVALID_ID, Cut.NULL_HASH, Cut.UPPER_HASH,
                Cut.SHORT_HASH, Cut.RESTORE_MISMATCH, Cut.RESTORE_NULL)) {
            Fixture fixture = new Fixture(0);
            fixture.cut = cut;
            assertThrows(IOException.class, fixture::run, cut.name());
            assertEquals(BigInteger.TWO, fixture.nextNumber, cut.name());
            assertEquals(1, fixture.completions, cut.name());
            assertEquals(cut == Cut.NULL_REFERENCE || cut == Cut.FOREIGN_REFERENCE || cut == Cut.NULL_STORE ? 0 : 1,
                    fixture.retirements, cut.name());
        }
        Fixture local = new Fixture(0);
        local.cut = Cut.EMPTY_ID;
        local.retireFails = true;
        IOException failure = assertThrows(IOException.class, local::run);
        assertEquals(1, failure.getSuppressed().length);
        assertEquals("retirement", failure.getSuppressed()[0].getMessage());
    }

    @Test void presentAlternateAndAbsentSkiProduceExactNoncriticalAki() throws Exception {
        byte[] defaultId = Pkix.subjectKeyIdentifier(key.getPublic());
        byte[] alternate = new byte[] {9, 8, 7, 6};
        for (byte[] identifier : new byte[][] {null, defaultId, alternate}) {
            Fixture fixture = new Fixture(0, identifier == null ? issuerDer : certificateWithSki(new DEROctetString(identifier).getEncoded()));
            fixture.run();
            TBSCertList parsed = TBSCertList.getInstance(fixture.output.toByteArray());
            Extension aki = parsed.getExtensions().getExtension(Extension.authorityKeyIdentifier);
            assertFalse(aki.isCritical());
            assertArrayEquals(identifier == null ? defaultId : identifier, AuthorityKeyIdentifier.getInstance(aki.getParsedValue()).getKeyIdentifierOctets());
            assertEquals(2, parsed.getExtensions().getExtensionOIDs().length);
        }
    }

    @Test void malformedPresentSkiHasNoFallbackAndStrictWrapperParserRejectsTrailingAndEmpty() throws Exception {
        for (byte[] malformed : new byte[][] {{0x04, 0}, {0x05, 0}, {0x04, 1}, {0x04, 1, 1, 0}, {0x04, (byte) 0x81, 1, 1}}) {
            assertThrows(IOException.class, () -> FullCrlTbsPreparation.decodeKeyIdentifier(new DEROctetString(malformed).getEncoded()));
        }
        for (byte[] malformed : new byte[][] {{0x04, 0}, {0x05, 0}, {0x04, 3, 0x04, 1, 1, 0}, {0x04, (byte) 0x80, 0, 0}}) {
            assertThrows(IOException.class, () -> FullCrlTbsPreparation.decodeKeyIdentifier(malformed));
        }
        Fixture fixture = new Fixture(0, certificateWithSki(new byte[] {0x04, 0}));
        assertThrows(IOException.class, fixture::run);
        assertEquals(0, fixture.reservations);
        assertEquals(0, fixture.begins);
        assertEquals(0, fixture.snapshotOpens);
    }

    private enum Cut {
        NONE, FIRST_READ, FIRST_CLOSE, CANCEL_FIRST, RESERVE, CANCEL_RESERVED, SINK_OPEN, OUTPUT_OPEN,
        WRITE, CANCEL_WRITE, SECOND_READ, SECOND_CLOSE, COMPLETE, LENGTH, DIVERGENT_COUNT, DIVERGENT_LENGTH,
        CANCEL_COMPLETE, COMPLETED_LENGTH, OUTPUT_CLOSE, SINK_CLOSE, SNAPSHOT_CLOSE,
        NULL_REFERENCE, FOREIGN_REFERENCE, NULL_STORE, ENCODING, LIFECYCLE, EMPTY_ID, NULL_ID, INVALID_ID,
        NULL_HASH, UPPER_HASH, SHORT_HASH, RESTORE_MISMATCH, RESTORE_NULL
    }

    private static final class Fixture {
        private final int count;
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final X509AuthoritySnapshot authority = PkiTestRuntime.signingAuthority(new EndEntityIssuancePreparationTest.CountingProvider());
        private final FullCrlPreparation.Prepared prepared;
        private final Credential issuer;
        private final PkiStore store;
        private final byte[] exactIssuerDer;
        private Cut cut = Cut.NONE;
        private boolean retireFails;
        private BigInteger nextNumber = BigInteger.ONE;
        private int reservations;
        private int begins;
        private int completions;
        private int aborts;
        private int retirements;
        private int snapshotOpens;
        private int snapshotCloses;
        private int cursorOpens;
        private int cursorCloses;

        private Fixture(int count) throws Exception {
            this(count, issuerDer);
        }

        private Fixture(int count, byte[] exactIssuerDer) throws Exception {
            this.count = count;
            this.exactIssuerDer = exactIssuerDer;
            PkiId caId = new PkiId("ca");
            PkiId credentialId = new PkiId("issuer");
            PkiId generationId = IssuerGeneration.idFor(caId, credentialId);
            IssuerGeneration generation = new IssuerGeneration(generationId, caId, credentialId, new KeyRef("key"),
                    IssuerGenerationState.ACTIVE, "00".repeat(32), "00".repeat(32));
            issuer = new Credential(credentialId, new FormatId("x509"), new IssuerRef(caId, generationId, new PkiId("path")),
                    new SubjectRef("CN=Issuer"), new Validity(BEFORE, AFTER), "1", new PkiId("key"),
                    new CaProfileBinding(PROFILE), CredentialStatus.ISSUED, content("issuer", exactIssuerDer, DurableContentReference.Lifecycle.PERSISTED),
                    new SimpleAttributeSet());
            CaRecord ca = new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, generation.signingKeyRef(), issuer.subjectRef(),
                    List.of(generationId), generationId, new PkiId("path"));
            X509AlgorithmBinding binding = ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors())
                    .standard(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, X509AlgorithmBinding.Role.CRL_SIGNATURE).orElseThrow();
            prepared = new FullCrlPreparation.Prepared(ca, generation, credentialId, PROFILE, issuer.content(),
                    CrlScope.of(new X500Name("CN=Issuer").getEncoded(), key.getPublic().getEncoded()), binding,
                    authority.planSigning(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), SigningProvider.class).selection().binding(),
                    NOW.plusNanos(5), NOW, NOW.plusSeconds(3600), exactIssuerDer, Optional.empty());
            StagedContentStore staging = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                    new Class<?>[] {StagedContentStore.class}, (proxy, method, args) -> switch (method.getName()) {
                        case "contentStoreId" -> "store";
                        case "openContent" -> new ImmutableByteContent(this.exactIssuerDer);
                        case "restoreReference" -> {
                            if (cut == Cut.INVALID_ID) { throw new IOException("Store-specific content identifier is invalid"); }
                            if (cut == Cut.RESTORE_NULL) { yield null; }
                            yield new Content((String) args[0], (String) args[1], (Encoding) args[2],
                                    (Long) args[3] + (cut == Cut.RESTORE_MISMATCH ? 1 : 0), (String) args[4],
                                    (DurableContentReference.Lifecycle) args[5]);
                        }
                        case "beginContent" -> {
                            assertEquals(1, reservations);
                            assertEquals(1, cursorCloses);
                            assertEquals(Encoding.DER, args[0]);
                            assertEquals(DurableContentReference.Lifecycle.OPERATION, args[1]);
                            begins++;
                            if (cut == Cut.SINK_OPEN) { throw new IOException("sink open"); }
                            yield sink();
                        }
                        case "retireUnownedContent" -> {
                            retirements++;
                            assertNotNull(args[0]);
                            if (retireFails) { throw new IOException("retirement"); }
                            yield null;
                        }
                        default -> throw new AssertionError(method.getName());
                    });
            store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] {PkiStore.class},
                    (proxy, method, args) -> switch (method.getName()) {
                        case "stagedContent" -> staging;
                        case "getCredential" -> Optional.of(args[0].equals(credentialId) ? issuer : leaf((PkiId) args[0]));
                        case "getIssuerGeneration" -> { assertEquals(generationId, args[0]); yield Optional.of(generation); }
                        case "openRevocationSnapshot" -> { snapshotOpens++; yield snapshot(); }
                        case "reserveCrlNumber" -> {
                            assertEquals(generationId, args[0]);
                            assertEquals(1, cursorCloses, "Pass one must close before reservation");
                            assertEquals(0, begins);
                            reservations++;
                            if (cut == Cut.RESERVE) { throw new PkiException("reserve"); }
                            BigInteger reserved = nextNumber;
                            nextNumber = nextNumber.add(BigInteger.ONE);
                            if (cut == Cut.CANCEL_RESERVED) { cancelled.set(true); }
                            yield reserved;
                        }
                        default -> throw new AssertionError("No signing, publication or other writes: " + method.getName());
                    });
        }

        private PreparedFullCrlTbs run() throws IOException {
            return new FullCrlTbsPreparation(store).prepare(prepared, cancelled::get);
        }

        private Credential leaf(PkiId id) {
            String serial = cut == Cut.DIVERGENT_LENGTH && cursorOpens == 2 ? "128" : "2";
            return new Credential(id, new FormatId("x509"), issuer.issuerRef(), new SubjectRef("CN=Leaf"),
                    issuer.validity(), serial, new PkiId("leaf-key"), new EndEntityProfileBinding(PROFILE),
                    CredentialStatus.ISSUED, issuer.content(), new SimpleAttributeSet());
        }

        private RevocationSnapshot snapshot() {
            return new RevocationSnapshot() {
                private boolean closed;
                private void check() { assertFalse(closed, "Provenance must be captured before closure"); }
                @Override public zeroecho.pki.spi.store.MetadataStoreId sourceStoreId() {
                    check();
                    return new zeroecho.pki.spi.store.MetadataStoreId("102030405060708090a0b0c0d0e0f001");
                }
                @Override public String snapshotId() { check(); return "snapshot"; }
                @Override public long revision() { check(); return 23; }
                @Override public long boundary() { check(); return 456; }
                @Override public String commitment() { check(); return "ab".repeat(32); }
                @Override public OptionalLong count() { check(); return OptionalLong.of(count); }
                @Override public void close() throws IOException {
                    closed = true;
                    snapshotCloses++;
                    if (cut == Cut.SNAPSHOT_CLOSE) { throw new IOException("snapshot close"); }
                }
                @Override public Cursor openCursor() {
                    check();
                    int pass = ++cursorOpens;
                    return new Cursor() {
                        private int index = -1;
                        @Override public boolean next(CancellationSignal cancellation) throws IOException {
                            cancellation.throwIfCancelled();
                            if (pass == 1 && cut == Cut.FIRST_READ || pass == 2 && cut == Cut.SECOND_READ) {
                                throw new IOException("read");
                            }
                            if (pass == 1 && cut == Cut.CANCEL_FIRST) { cancelled.set(true); }
                            index++;
                            return index < (pass == 2 && cut == Cut.DIVERGENT_COUNT ? 0 : count);
                        }
                        @Override public RevocationRecord current() {
                            return new RevocationRecord(new PkiId("leaf" + index), new RevocationTransition(1,
                                    RevocationState.HELD, NOW.minusSeconds(10), Optional.empty(), new SimpleAttributeSet()));
                        }
                        @Override public long currentGlobalRevision() { return index + 1L; }
                @Override public long ordinal() { return index; }
                        @Override public void close() throws IOException {
                            cursorCloses++;
                            if (pass == 1 && cut == Cut.FIRST_CLOSE || pass == 2 && cut == Cut.SECOND_CLOSE) {
                                throw new IOException("cursor close");
                            }
                        }
                    };
                }
            };
        }

        private ContentSink sink() {
            return new ContentSink() {
                private boolean completed;
                private boolean aborted;
                @Override public OutputStream outputStream() throws IOException {
                    if (cut == Cut.OUTPUT_OPEN) { throw new IOException("output open"); }
                    return new OutputStream() {
                        @Override public void write(int value) throws IOException {
                            if (cut == Cut.WRITE) { throw new IOException("write"); }
                            if (cut == Cut.CANCEL_WRITE) { cancelled.set(true); }
                            output.write(value);
                        }
                        @Override public void close() throws IOException {
                            if (cut == Cut.OUTPUT_CLOSE) { throw new IOException("output close"); }
                        }
                    };
                }
                @Override public long length() { return output.size() + (cut == Cut.LENGTH ? 1 : 0); }
                @Override public DurableContentReference complete() throws IOException {
                    if (cut == Cut.COMPLETE) { throw new IOException("complete"); }
                    completed = true;
                    completions++;
                    if (cut == Cut.CANCEL_COMPLETE) { cancelled.set(true); }
                    Content reference = content("tbs", output.toByteArray(), DurableContentReference.Lifecycle.OPERATION);
                    if (cut == Cut.NULL_REFERENCE) { return null; }
                    if (cut == Cut.FOREIGN_REFERENCE || cut == Cut.NULL_STORE) {
                        return new Content(cut == Cut.NULL_STORE ? null : "foreign", reference.contentId(), reference.encoding(),
                                reference.length(), reference.sha256(), reference.lifecycle());
                    }
                    if (cut == Cut.ENCODING) { return new Content("store", "tbs", Encoding.BINARY, reference.length(), reference.sha256(), reference.lifecycle()); }
                    if (cut == Cut.LIFECYCLE) { return new Content("store", "tbs", Encoding.DER, reference.length(), reference.sha256(), DurableContentReference.Lifecycle.PERSISTED); }
                    if (cut == Cut.EMPTY_ID || cut == Cut.NULL_ID || cut == Cut.INVALID_ID) {
                        return new Content("store", cut == Cut.NULL_ID ? null : cut == Cut.EMPTY_ID ? " " : "../bad", Encoding.DER,
                                reference.length(), reference.sha256(), reference.lifecycle());
                    }
                    if (cut == Cut.NULL_HASH || cut == Cut.UPPER_HASH || cut == Cut.SHORT_HASH) {
                        return new Content("store", "tbs", Encoding.DER, reference.length(),
                                cut == Cut.NULL_HASH ? null : cut == Cut.UPPER_HASH ? "AB".repeat(32) : "00", reference.lifecycle());
                    }
                    return cut == Cut.COMPLETED_LENGTH ? new Content(reference.storeId(), reference.contentId(), reference.encoding(),
                            reference.length() + 1, reference.sha256(), reference.lifecycle()) : reference;
                }
                @Override public void abort() { if (!aborted) { aborts++; aborted = true; } }
                @Override public void close() throws IOException {
                    if (!completed) { abort(); }
                    if (cut == Cut.SINK_CLOSE) { throw new IOException("sink close"); }
                }
            };
        }
    }

    private static Content content(String id, byte[] bytes, DurableContentReference.Lifecycle lifecycle) {
        try {
            return new Content("store", id, Encoding.DER, bytes.length,
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)), lifecycle);
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private record Content(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference { }
}
