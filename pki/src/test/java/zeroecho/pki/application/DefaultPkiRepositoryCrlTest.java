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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.Optional;
import java.util.OptionalLong;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;

class DefaultPkiRepositoryCrlTest {
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final PkiId STATUS = new PkiId("crl:repository-test");
    private static final PkiId CA = new PkiId("ca:repository-test");

    @ParameterizedTest
    @EnumSource(value = StatusObjectType.class, names = {"CRL", "DELTA_CRL"})
    void validatesBeforeReturningRepeatableCallerOwnedContent(StatusObjectType type) throws Exception {
        byte[] bytes = crl(1);
        ObservedContent source = new ObservedContent(bytes);
        PkiRepository repository = repository(type, source, bytes.length, sha256(bytes));
        try (PkiRepositoryContent result = repository.openStatusObject(STATUS)) {
            assertFalse(source.closed);
            assertEquals(source.opened, source.closedStreams);
            assertTrue(source.opened > 0);
            assertEquals(PkiRepositoryContent.Role.CRL, result.role());
            assertEquals(STATUS, result.objectId());
            assertEquals(CA, result.authorityId());
            assertEquals(bytes.length, result.length());
            assertEquals(sha256(bytes), result.sha256());
            assertEquals(sha256(bytes), consume(result));
            assertEquals(sha256(bytes), consume(result));
        }
        assertTrue(source.closed);
        assertEquals(source.opened, source.closedStreams);
    }

    @Test void opensFileCrlAboveOneMiBWithBufferedValidationAndWithoutAggregateReads(@TempDir Path directory)
            throws Exception {
        byte[] bytes = crl(40_000);
        assertTrue(bytes.length > 1_048_576);
        Path path = directory.resolve("large.crl");
        Files.write(path, bytes);
        ObservedContent source = new ObservedContent(bytes, path);
        try (PkiRepositoryContent result = repository(StatusObjectType.CRL, source, bytes.length, sha256(bytes))
                .openStatusObject(STATUS)) {
            assertEquals(0, source.singleByteReads);
            assertEquals(16 * 1024, source.minimumRead);
            assertTrue(source.bulkReads <= source.opened * ((bytes.length + 16_383) / 16_384 + 2),
                    "Validation must amortize file reads across fixed-size buffers");
            assertEquals(bytes.length, result.length());
            assertEquals(sha256(bytes), consume(result));
            assertTrue(source.maximumRead <= 16 * 1024);
        }
        assertEquals(source.opened, source.closedStreams);
        assertTrue(source.closed);
    }

    @Test void rejectsNonCanonicalTruncatedTrailingAndWrongStructureBeforeReturn() throws Exception {
        byte[] valid = crl(1);
        int lengthOctets = (valid[1] & 0x80) == 0 ? 0 : valid[1] & 0x7f;
        byte[] nonCanonical = new byte[valid.length + 1];
        nonCanonical[0] = valid[0];
        nonCanonical[1] = (byte) (0x80 | (lengthOctets == 0 ? 1 : lengthOctets + 1));
        if (lengthOctets == 0) {
            System.arraycopy(valid, 1, nonCanonical, 2, valid.length - 1);
        } else {
            System.arraycopy(valid, 2, nonCanonical, 3, valid.length - 2);
        }
        for (byte[] invalid : new byte[][] {nonCanonical, Arrays.copyOf(valid, valid.length - 1),
                Arrays.copyOf(valid, valid.length + 1), new byte[] {0x30, 0}}) {
            ObservedContent source = new ObservedContent(invalid);
            PkiException failure = assertThrows(PkiException.class, () -> repository(StatusObjectType.CRL,
                    source, invalid.length, sha256(invalid)).openStatusObject(STATUS));
            assertInstanceOf(IOException.class, failure.getCause());
            assertTrue(source.closed);
            assertEquals(source.opened, source.closedStreams);
        }
    }

    @Test void rejectsDurableLengthAndDigestMismatchWithUnknownSourceLength() throws Exception {
        byte[] bytes = crl(1);
        for (long expectedLength : new long[] {bytes.length - 1L, bytes.length + 1L, bytes.length}) {
            ObservedContent source = new ObservedContent(bytes);
            String digest = expectedLength == bytes.length ? "0".repeat(64) : sha256(bytes);
            assertThrows(PkiException.class, () -> repository(StatusObjectType.CRL, source, expectedLength, digest)
                    .openStatusObject(STATUS));
            assertTrue(source.closed);
            assertEquals(source.opened, source.closedStreams);
        }
    }

    @Test void preservesCleanupFailureAsSuppressedOnValidationFailure() throws Exception {
        ObservedContent source = new ObservedContent(new byte[] {0x30, 0});
        source.closeFailure = new IOException("test cleanup failure");
        PkiException failure = assertThrows(PkiException.class, () -> repository(StatusObjectType.CRL,
                source, 2, sha256(source.bytes)).openStatusObject(STATUS));
        assertInstanceOf(IOException.class, failure.getCause());
        assertEquals(1, failure.getCause().getSuppressed().length);
        assertSame(source.closeFailure, failure.getCause().getSuppressed()[0]);
        assertTrue(source.closed);
        assertEquals(source.opened, source.closedStreams);
    }

    @Test void leavesNonCrlStatusContentUnparsed() throws Exception {
        ObservedContent source = new ObservedContent(new byte[] {1, 2, 3});
        try (PkiRepositoryContent result = repository(StatusObjectType.OCSP, source, 3, sha256(source.bytes))
                .openStatusObject(STATUS)) {
            assertEquals(PkiRepositoryContent.Role.STATUS_OBJECT, result.role());
            assertEquals(0, source.opened);
            try (InputStream input = result.openStream()) {
                byte[] bytes = new byte[3];
                assertEquals(3, input.read(bytes));
                assertArrayEquals(source.bytes, bytes);
            }
        }
        assertTrue(source.closed);
    }

    private static PkiRepository repository(StatusObjectType type, ObservedContent source, long length, String digest) {
        DurableContentReference reference = new Reference(length, digest);
        StatusObject status = new StatusObject(STATUS, new FormatId("x509"), CA, type, NOW, Optional.empty(),
                reference, new SimpleAttributeSet());
        StagedContentStore staging = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                new Class<?>[] {StagedContentStore.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("openContent")) {
                        assertSame(reference, arguments[0]);
                        return source;
                    }
                    throw new AssertionError("Unexpected staging call: " + method.getName());
                });
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] {PkiStore.class}, (proxy, method, arguments) -> switch (method.getName()) {
                    case "stagedContent" -> staging;
                    case "getStatusObject" -> Optional.of(status);
                    default -> throw new AssertionError("Unexpected store call: " + method.getName());
                });
        return new DefaultPkiRepository(store, () -> { });
    }

    private static byte[] crl(int entries) throws Exception {
        KeyPair key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name("CN=Repository CRL"), Date.from(NOW));
        builder.setNextUpdate(Date.from(NOW.plusSeconds(3600)));
        for (int index = 1; index <= entries; index++) {
            builder.addCRLEntry(BigInteger.valueOf(index), Date.from(NOW.minusSeconds(1)), 1);
        }
        return builder.build(new JcaContentSignerBuilder("Ed25519").build(key.getPrivate())).getEncoded();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String consume(PkiRepositoryContent content) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long length = 0L;
        try (InputStream input = content.openStream()) {
            byte[] chunk = new byte[8192];
            for (int read; (read = input.read(chunk)) != -1;) {
                length += read;
                digest.update(chunk, 0, read);
            }
        }
        assertEquals(content.length(), length);
        return HexFormat.of().formatHex(digest.digest());
    }

    private record Reference(long length, String sha256) implements DurableContentReference {
        @Override public String storeId() { return "test-store"; }
        @Override public String contentId() { return "test-content"; }
        @Override public Encoding encoding() { return Encoding.DER; }
        @Override public Lifecycle lifecycle() { return Lifecycle.PERSISTED; }
    }

    private static final class ObservedContent implements RepeatableContent {
        private final byte[] bytes;
        private final Path path;
        private int opened;
        private int closedStreams;
        private int maximumRead;
        private int minimumRead = Integer.MAX_VALUE;
        private int singleByteReads;
        private int bulkReads;
        private boolean closed;
        private IOException closeFailure;

        private ObservedContent(byte[] bytes) { this(bytes, null); }
        private ObservedContent(byte[] bytes, Path path) {
            this.bytes = bytes;
            this.path = path;
        }

        @Override public InputStream openStream() throws IOException {
            assertFalse(closed);
            opened++;
            return new FilterInputStream(path == null ? new ByteArrayInputStream(bytes) : Files.newInputStream(path)) {
                private boolean streamClosed;
                @Override public int read() throws IOException {
                    singleByteReads++;
                    return super.read();
                }
                @Override public int read(byte[] buffer, int offset, int length) throws IOException {
                    assertTrue(length <= 16 * 1024, "Aggregate payload read requested");
                    maximumRead = Math.max(maximumRead, length);
                    minimumRead = Math.min(minimumRead, length);
                    bulkReads++;
                    return super.read(buffer, offset, length);
                }
                @Override public byte[] readAllBytes() { throw new AssertionError("Aggregate readAllBytes"); }
                @Override public byte[] readNBytes(int length) { throw new AssertionError("Aggregate readNBytes"); }
                @Override public void close() throws IOException {
                    if (!streamClosed) {
                        closedStreams++;
                        streamClosed = true;
                    }
                    super.close();
                }
            };
        }
        @Override public OptionalLong length() { return OptionalLong.empty(); }
        @Override public String contentId() { return "test-content"; }
        @Override public void close() throws IOException {
            closed = true;
            if (closeFailure != null) { throw closeFailure; }
        }
    }
}
