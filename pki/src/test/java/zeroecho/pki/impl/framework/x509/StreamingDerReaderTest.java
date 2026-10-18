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
package zeroecho.pki.impl.framework.x509;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.impl.framework.x509.StreamingDerReader.SignedObjectKind;
import zeroecho.pki.impl.framework.x509.StreamingDerReader.SignedObjectLayout;

final class StreamingDerReaderTest {

    private static final byte[] CRL = {
            0x30, 0x32,
            0x30, 0x26,
            0x02, 0x01, 0x01,
            0x30, 0x04, 0x06, 0x02, 0x2a, 0x03,
            0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 0x49,
            0x17, 0x0d, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x30, 0x04, 0x06, 0x02, 0x2a, 0x03,
            0x03, 0x02, 0x00, (byte) 0xaa
    };

    @Test
    void unsignedCertificateTbsSpansReferToOriginalDerAndRejectMalformedBounds() throws Exception {
        byte[] tbs = java.util.HexFormat.of().parseHex("301a020101300406022a033000300030003009300406022a03030100");
        StreamingDerReader reader = new StreamingDerReader();
        StreamingDerReader.CertificateTbsLayout layout = reader.inspectUnsignedCertificateTbs(tbs, tbs.length);
        assertEquals(tbs.length, layout.encodedLength());
        assertEquals(5, layout.algorithmOffset());
        assertEquals(6, layout.algorithmLength());
        assertEquals(17, layout.subjectPublicKeyInfoOffset());
        assertEquals(11, layout.subjectPublicKeyInfoLength());
        assertEquals("300406022a03", java.util.HexFormat.of().formatHex(tbs,
                layout.algorithmOffset(), layout.algorithmOffset() + layout.algorithmLength()));
        assertEquals("3009300406022a03030100", java.util.HexFormat.of().formatHex(tbs,
                layout.subjectPublicKeyInfoOffset(), layout.subjectPublicKeyInfoOffset() + layout.subjectPublicKeyInfoLength()));
        for (int length = 0; length < tbs.length; length++) {
            byte[] truncated = Arrays.copyOf(tbs, length);
            assertThrows(IOException.class, () -> reader.inspectUnsignedCertificateTbs(truncated, tbs.length));
        }
        assertThrows(IOException.class, () -> reader.inspectUnsignedCertificateTbs(tbs, tbs.length - 1));
        assertThrows(IOException.class, () -> reader.inspectUnsignedCertificateTbs(Arrays.copyOf(tbs, tbs.length + 1), tbs.length + 1));
        for (int offset : new int[] {0, 5, 11, 13, 15, 17}) {
            byte[] malformed = tbs.clone();
            malformed[offset] = 0x31; // Canonical DER SET still fails the required certificate SEQUENCE tag.
            assertThrows(IOException.class, () -> reader.inspectUnsignedCertificateTbs(malformed, malformed.length));
        }
        byte[] escapedSpki = tbs.clone();
        escapedSpki[18] = 0x7f;
        assertThrows(IOException.class, () -> reader.inspectUnsignedCertificateTbs(escapedSpki, escapedSpki.length));
        assertThrows(IndexOutOfBoundsException.class, () -> new StreamingDerReader.CertificateTbsLayout(
                28, Integer.MAX_VALUE, 6, 17, 11));
        assertThrows(IndexOutOfBoundsException.class, () -> new StreamingDerReader.CertificateTbsLayout(
                28, 5, 6, 17, Integer.MAX_VALUE));
    }

    @Test
    void validatesCanonicalCrlAndLocatesSignedFields() throws Exception {
        System.out.println("validatesCanonicalCrlAndLocatesSignedFields");
        StreamingDerReader reader = new StreamingDerReader();
        ImmutableByteContent content = new ImmutableByteContent(CRL);
        SignedObjectLayout layout = reader.inspectSignedObject(content, SignedObjectKind.CRL,
                CancellationSignal.NONE);
        System.out.println("...encodedLength=" + reader.validate(content, CancellationSignal.NONE));
        assertEquals(2L, layout.tbsOffset());
        assertEquals(40L, layout.tbsLength());
        assertEquals(7L, layout.tbsAlgorithmOffset());
        assertEquals(6L, layout.tbsAlgorithmLength());
        assertEquals(13L, layout.issuerOffset());
        assertEquals(14L, layout.issuerLength());
        assertEquals(42L, layout.outerAlgorithmOffset());
        assertEquals(6L, layout.outerAlgorithmLength());
        assertEquals(51L, layout.signatureOffset());
        assertEquals(1L, layout.signatureLength());
        assertEquals(java.util.Optional.of(java.time.Instant.parse("2026-01-01T00:00:00Z")),
                layout.thisUpdate());
        assertEquals(java.util.Optional.empty(), layout.nextUpdate());
        System.out.println("validatesCanonicalCrlAndLocatesSignedFields...ok");
    }

    @Test
    void crlInspectionRejectsStructurallyValidV1Certificate() {
        System.out.println("crlInspectionRejectsStructurallyValidV1Certificate");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] validity = sequence(utcTime("250101000000Z"), utcTime("270101000000Z"));
        byte[] subjectPublicKeyInfo = sequence(algorithm(), tlv(3, new byte[] { 0, 1 }));
        byte[] certificate = signedObject(sequence(integer(1), algorithm(), issuer(), validity, issuer(),
                subjectPublicKeyInfo));
        ImmutableByteContent content = new ImmutableByteContent(certificate);

        SignedObjectLayout certificateLayout = assertDoesNotThrow(() -> reader.inspectSignedObject(content,
                SignedObjectKind.CERTIFICATE, CancellationSignal.NONE));
        assertEquals(java.util.Optional.empty(), certificateLayout.thisUpdate());
        assertEquals(java.util.Optional.empty(), certificateLayout.nextUpdate());
        assertThrows(IOException.class, () -> reader.inspectSignedObject(content, SignedObjectKind.CRL,
                CancellationSignal.NONE));
        System.out.println("...rejected=certificate TBS is not TBSCertList");
        System.out.println("crlInspectionRejectsStructurallyValidV1Certificate...ok");
    }

    @Test
    void crlInspectionReturnsExactOptionalNextUpdate() throws Exception {
        System.out.println("crlInspectionReturnsExactOptionalNextUpdate");
        byte[] encoded = signedObject(sequence(integer(1), algorithm(), issuer(), utcTime("260803120000Z"),
                utcTime("260810120000Z")));

        SignedObjectLayout layout = new StreamingDerReader().inspectSignedObject(
                new ImmutableByteContent(encoded), SignedObjectKind.CRL, CancellationSignal.NONE);

        assertEquals(java.util.Optional.of(java.time.Instant.parse("2026-08-03T12:00:00Z")),
                layout.thisUpdate());
        assertEquals(java.util.Optional.of(java.time.Instant.parse("2026-08-10T12:00:00Z")),
                layout.nextUpdate());
        System.out.println("...thisUpdate=" + layout.thisUpdate().orElseThrow()
                + " nextUpdate=" + layout.nextUpdate().orElseThrow());
        System.out.println("crlInspectionReturnsExactOptionalNextUpdate...ok");
    }

    @Test
    void crlInspectionRejectsMalformedOptionalTimesEntriesAndExtensions() {
        System.out.println("crlInspectionRejectsMalformedOptionalTimesEntriesAndExtensions");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] thisUpdate = utcTime("260101000000Z");
        byte[] earlier = utcTime("250101000000Z");
        byte[] zeroSerialEntry = sequence(integer(0), thisUpdate);
        byte[] oversizedSerial = new byte[21];
        oversizedSerial[0] = 1;
        byte[] oversizedSerialEntry = sequence(tlv(2, oversizedSerial), thisUpdate);
        byte[] malformedEntry = sequence(integer(1), thisUpdate, tlv(4, new byte[] { 1 }));
        byte[] falseCritical = explicitExtensions(sequence(sequence(oid(), tlv(1, new byte[] { 0 }),
                tlv(4, new byte[] { 1 }))));
        byte[] extensionOnV1 = explicitExtensions(sequence(sequence(oid(), tlv(4, new byte[] { 1 }))));

        assertCrlRejected(reader, integer(0), algorithm(), issuer(), thisUpdate);
        assertCrlRejected(reader, integer(1), algorithm(), sequence(), thisUpdate);
        assertCrlRejected(reader, integer(1), algorithm(), issuer(), thisUpdate, earlier);
        assertCrlRejected(reader, integer(1), algorithm(), issuer(), thisUpdate, thisUpdate);
        assertCrlRejected(reader, integer(1), algorithm(), issuer(), thisUpdate, sequence(zeroSerialEntry));
        assertCrlRejected(reader, integer(1), algorithm(), issuer(), thisUpdate, sequence(oversizedSerialEntry));
        assertCrlRejected(reader, integer(1), algorithm(), issuer(), thisUpdate, sequence(malformedEntry));
        assertCrlRejected(reader, integer(1), algorithm(), issuer(), thisUpdate, falseCritical);
        assertCrlRejected(reader, algorithm(), issuer(), thisUpdate, extensionOnV1);
        System.out.println("...rejected=version, issuer, time order/equality, serial, entry, DEFAULT, v1 extensions");
        System.out.println("crlInspectionRejectsMalformedOptionalTimesEntriesAndExtensions...ok");
    }

    @Test
    void rejectsTrailingIndefiniteAndNonMinimalLength() {
        System.out.println("rejectsTrailingIndefiniteAndNonMinimalLength");
        StreamingDerReader reader = new StreamingDerReader();
        assertThrows(IOException.class, () -> reader.validate(
                new ImmutableByteContent(Arrays.copyOf(CRL, CRL.length + 1)), CancellationSignal.NONE));
        byte[] indefinite = { 0x30, (byte) 0x80, 0x00, 0x00 };
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(indefinite), CancellationSignal.NONE));
        byte[] nonMinimal = { 0x30, (byte) 0x81, 0x00 };
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(nonMinimal), CancellationSignal.NONE));
        System.out.println("...rejected=3");
        System.out.println("rejectsTrailingIndefiniteAndNonMinimalLength...ok");
    }

    @Test
    void rejectsNonCanonicalPrimitiveForms() {
        System.out.println("rejectsNonCanonicalPrimitiveForms");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] integer = { 0x02, 0x02, 0x00, 0x01 };
        byte[] oid = { 0x06, 0x01, (byte) 0x80 };
        byte[] bitString = { 0x03, 0x02, 0x01, 0x01 };
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(integer), CancellationSignal.NONE));
        assertThrows(IOException.class, () -> reader.validate(new ImmutableByteContent(oid), CancellationSignal.NONE));
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(bitString), CancellationSignal.NONE));
        System.out.println("...rejected=3");
        System.out.println("rejectsNonCanonicalPrimitiveForms...ok");
    }

    @Test
    void boundedEntryRejectsOversizeAndHostileHighTags() throws Exception {
        System.out.println("boundedEntryRejectsOversizeAndHostileHighTags");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] highTag31 = { (byte) 0x9f, 0x1f, 0x00 };
        assertEquals(highTag31.length, reader.validate(highTag31, highTag31.length));
        assertThrows(IOException.class, () -> reader.validate(highTag31, highTag31.length - 1));
        assertThrows(IOException.class, () -> reader.validate(new byte[] { 0x1f, 0x1e, 0x00 }, 3));
        assertThrows(IOException.class, () -> reader.validate(new byte[] { 0x1f, 0x1f, 0x00 }, 3));
        assertThrows(IOException.class,
                () -> reader.validate(new byte[] { 0x1f, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                        (byte) 0xff, 0x7f, 0x00 }, 7));
        System.out.println("...rejected=limit, non-minimal tag, tag overflow");
        System.out.println("boundedEntryRejectsOversizeAndHostileHighTags...ok");
    }

    @Test
    void validatesReachableEnumeratedTimesAndX509Strings() throws Exception {
        System.out.println("validatesReachableEnumeratedTimesAndX509Strings");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] values = { 0x30, 0x1f, 0x0a, 0x01, 0x01, 0x0c, 0x02, (byte) 0xc3, (byte) 0xa9,
                0x13, 0x02, 'C', 'N', 0x16, 0x03, 'a', '@', 'b', 0x17, 0x0d,
                '2', '6', '0', '8', '0', '3', '1', '2', '0', '0', '0', '0', 'Z' };
        assertEquals(values.length, reader.validate(values, values.length));
        assertThrows(IOException.class, () -> reader.validate(new byte[] { 0x0a, 0x02, 0x00, 0x01 }, 4));
        assertThrows(IOException.class,
                () -> reader.validate(new byte[] { 0x17, 0x0d, '2', '6', '0', '2', '3', '0', '1', '2', '0',
                        '0', '0', '0', 'Z' }, 15));
        assertThrows(IOException.class,
                () -> reader.validate(new byte[] { 0x0c, 0x02, (byte) 0xc0, (byte) 0x80 }, 4));
        assertThrows(IOException.class, () -> reader.validate(new byte[] { 0x13, 0x01, '@' }, 3));
        System.out.println("...rejected=ENUMERATED, date, UTF-8, PrintableString");
        System.out.println("validatesReachableEnumeratedTimesAndX509Strings...ok");
    }

    @Test
    void subjectPublicKeyInfoRequiresZeroPadBits() throws Exception {
        System.out.println("subjectPublicKeyInfoRequiresZeroPadBits");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] valid = { 0x30, 0x08, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x01, 0x00 };
        byte[] padded = { 0x30, 0x09, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x02, 0x01, 0x00 };
        assertEquals(valid.length, reader.validateSubjectPublicKeyInfo(valid, valid.length));
        assertThrows(IOException.class, () -> reader.validateSubjectPublicKeyInfo(padded, padded.length));
        System.out.println("...rejected=nonzero pad bits");
        System.out.println("subjectPublicKeyInfoRequiresZeroPadBits...ok");
    }

    @Test
    void enforcesCanonicalSetOrdering() throws Exception {
        System.out.println("enforcesCanonicalSetOrdering");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] canonical = { 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
        byte[] reversed = { 0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01 };
        assertEquals(canonical.length,
                reader.validate(new ImmutableByteContent(canonical), CancellationSignal.NONE));
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(reversed), CancellationSignal.NONE));
        System.out.println("...rejected=reversed SET");
        System.out.println("enforcesCanonicalSetOrdering...ok");
    }

    @Test
    void setOrderingUsesFixedSourcePasses() throws Exception {
        System.out.println("setOrderingUsesFixedSourcePasses");
        byte[] encoded = repeatedIntegerSet(128);
        CountingContent content = new CountingContent(encoded);
        StreamingDerReader reader = new StreamingDerReader();

        assertEquals(encoded.length, reader.validate(content, CancellationSignal.NONE));
        assertEquals(3, content.openCount());
        assertEquals(3, content.closeCount());
        System.out.println("...sourcePasses=" + content.openCount());
        System.out.println("setOrderingUsesFixedSourcePasses...ok");
    }

    @Test
    void denseEmptyPrimitiveInputUsesOneStreamingPass() throws Exception {
        System.out.println("denseEmptyPrimitiveInputUsesOneStreamingPass");
        byte[] encoded = new byte[4 + 2 * 16_384];
        encoded[0] = 0x30;
        encoded[1] = (byte) 0x82;
        encoded[2] = (byte) ((encoded.length - 4) >>> 8);
        encoded[3] = (byte) (encoded.length - 4);
        for (int index = 4; index < encoded.length; index += 2) {
            encoded[index] = 0x04;
            encoded[index + 1] = 0x00;
        }
        CountingContent content = new CountingContent(encoded);
        assertEquals(encoded.length, new StreamingDerReader().validate(content, CancellationSignal.NONE));
        assertEquals(1, content.openCount());
        assertEquals(1, content.closeCount());
        System.out.println("...emptyPrimitives=16384 sourcePasses=" + content.openCount());
        System.out.println("denseEmptyPrimitiveInputUsesOneStreamingPass...ok");
    }

    @Test
    void crlSemanticsExtractsFullAndDeltaNumbersWithoutChangingLayout() throws Exception {
        StreamingDerReader reader = new StreamingDerReader();
        for (java.math.BigInteger number : new java.math.BigInteger[] {
                java.math.BigInteger.ZERO, java.math.BigInteger.ONE.shiftLeft(159).subtract(java.math.BigInteger.ONE) }) {
            byte[] encoded = semanticCrl(crlExtension(20, false, tlv(2, number.toByteArray())));
            StreamingDerReader.CrlSemanticLayout semantic = reader.inspectCrlSemantics(
                    new ImmutableByteContent(encoded), CancellationSignal.NONE);
            assertEquals(number, semantic.crlNumber());
            assertEquals(java.util.Optional.empty(), semantic.deltaIndicator());
            assertEquals(reader.inspectSignedObject(new ImmutableByteContent(encoded), SignedObjectKind.CRL,
                    CancellationSignal.NONE), semantic.layout());
        }
        byte[] delta = semanticCrl(crlExtension(20, false, integer(7)), crlExtension(27, true, integer(3)));
        StreamingDerReader.CrlSemanticLayout semantic = reader.inspectCrlSemantics(
                new ImmutableByteContent(delta), CancellationSignal.NONE);
        assertEquals(java.math.BigInteger.valueOf(7), semantic.crlNumber());
        assertEquals(java.util.Optional.of(java.math.BigInteger.valueOf(3)), semantic.deltaIndicator());
    }

    @Test
    void crlSemanticsRejectsMissingDuplicateWrongCriticalityAndMalformedNumbers() {
        StreamingDerReader reader = new StreamingDerReader();
        byte[] number = crlExtension(20, false, integer(1));
        byte[] delta = crlExtension(27, true, integer(0));
        byte[][] invalid = {
                CRL,
                semanticCrl(delta),
                semanticCrl(number, number),
                semanticCrl(number, delta, delta),
                semanticCrl(crlExtension(20, true, integer(1))),
                semanticCrl(number, crlExtension(27, false, integer(0)))
        };
        for (byte[] encoded : invalid) {
            assertThrows(IOException.class, () -> reader.inspectCrlSemantics(
                    new ImmutableByteContent(encoded), CancellationSignal.NONE));
        }
        byte[][] malformed = {
                new byte[0], tlv(4, new byte[] {1}), tlv(2, new byte[0]),
                tlv(2, new byte[] {(byte) 0x80}), tlv(2, new byte[] {0, 1}),
                new byte[] {2, (byte) 0x81, 1, 1}, new byte[] {2, 2, 1},
                concatenate(integer(1), integer(2)),
                tlv(2, java.math.BigInteger.ONE.shiftLeft(159).toByteArray()),
                tlv(2, new byte[21])
        };
        for (byte[] payload : malformed) {
            for (int oidSuffix : new int[] {20, 27}) {
                byte[] encoded = oidSuffix == 20 ? semanticCrl(crlExtension(20, false, payload))
                        : semanticCrl(number, crlExtension(27, true, payload));
                assertThrows(IOException.class, () -> reader.inspectCrlSemantics(
                        new ImmutableByteContent(encoded), CancellationSignal.NONE));
            }
        }
        assertDoesNotThrow(() -> reader.inspectSignedObject(new ImmutableByteContent(CRL),
                SignedObjectKind.CRL, CancellationSignal.NONE));
    }

    @Test
    void crlSemanticsDoesNotCollectEntryExtensionsAndClosesOnCancellation() throws Exception {
        StreamingDerReader reader = new StreamingDerReader();
        byte[] entry = sequence(integer(1), utcTime("260101000000Z"),
                sequence(crlExtension(20, false, integer(99)), crlExtension(27, true, integer(98))));
        byte[] entryOnly = signedObject(sequence(integer(1), algorithm(), issuer(), utcTime("260101000000Z"),
                sequence(entry)));
        assertDoesNotThrow(() -> reader.inspectSignedObject(new ImmutableByteContent(entryOnly),
                SignedObjectKind.CRL, CancellationSignal.NONE));
        assertThrows(IOException.class, () -> reader.inspectCrlSemantics(
                new ImmutableByteContent(entryOnly), CancellationSignal.NONE));
        byte[] encoded = signedObject(sequence(integer(1), algorithm(), issuer(), utcTime("260101000000Z"),
                sequence(entry), explicitExtensions(sequence(crlExtension(20, false, integer(7))))));
        StreamingDerReader.CrlSemanticLayout semantic = reader.inspectCrlSemantics(
                new ImmutableByteContent(encoded), CancellationSignal.NONE);
        assertEquals(java.math.BigInteger.valueOf(7), semantic.crlNumber());
        assertEquals(java.util.Optional.empty(), semantic.deltaIndicator());
        for (int length = 0; length < encoded.length; length++) {
            byte[] truncated = Arrays.copyOf(encoded, length);
            assertThrows(IOException.class, () -> reader.inspectCrlSemantics(
                    new ImmutableByteContent(truncated), CancellationSignal.NONE));
        }
        CountingContent content = new CountingContent(encoded);
        AtomicInteger checks = new AtomicInteger();
        assertThrows(java.io.InterruptedIOException.class,
                () -> reader.inspectCrlSemantics(content, () -> checks.incrementAndGet() > 8));
        assertEquals(content.openCount(), content.closeCount());
    }

    private static byte[] semanticCrl(byte[]... extensions) {
        return signedObject(sequence(integer(1), algorithm(), issuer(), utcTime("260101000000Z"),
                explicitExtensions(sequence(extensions))));
    }

    private static byte[] crlExtension(int oidSuffix, boolean critical, byte[] payload) {
        byte[] identifier = tlv(6, new byte[] {0x55, 0x1d, (byte) oidSuffix});
        return critical ? sequence(identifier, tlv(1, new byte[] {(byte) 0xff}), tlv(4, payload))
                : sequence(identifier, tlv(4, payload));
    }

    private static byte[] repeatedIntegerSet(int count) {
        int valueLength = Math.multiplyExact(count, 3);
        byte[] encoded = new byte[Math.addExact(valueLength, 4)];
        encoded[0] = 0x31;
        encoded[1] = (byte) 0x82;
        encoded[2] = (byte) (valueLength >>> 8);
        encoded[3] = (byte) valueLength;
        for (int index = 4; index < encoded.length; index += 3) {
            encoded[index] = 0x02;
            encoded[index + 1] = 0x01;
            encoded[index + 2] = 0x01;
        }
        return encoded;
    }

    private static void assertCrlRejected(StreamingDerReader reader, byte[]... tbsFields) {
        byte[] encoded = signedObject(sequence(tbsFields));
        assertThrows(IOException.class, () -> reader.inspectSignedObject(new ImmutableByteContent(encoded),
                SignedObjectKind.CRL, CancellationSignal.NONE));
    }

    private static byte[] signedObject(byte[] tbs) {
        return sequence(tbs, algorithm(), tlv(3, new byte[] { 0, (byte) 0xaa }));
    }

    private static byte[] algorithm() {
        return sequence(oid());
    }

    private static byte[] issuer() {
        return sequence(tlv(0x31, sequence(tlv(6, new byte[] { 0x55, 0x04, 0x03 }),
                tlv(12, new byte[] { 'I' }))));
    }

    private static byte[] oid() {
        return tlv(6, new byte[] { 0x2a, 0x03 });
    }

    private static byte[] integer(int value) {
        return tlv(2, new byte[] { (byte) value });
    }

    private static byte[] utcTime(String value) {
        return tlv(23, value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static byte[] explicitExtensions(byte[] extensions) {
        return tlv(0xa0, extensions);
    }

    private static byte[] sequence(byte[]... values) {
        return tlv(0x30, concatenate(values));
    }

    private static byte[] tlv(int tag, byte[] value) {
        if (value.length >= 128) {
            throw new IllegalArgumentException("test DER value too long");
        }
        byte[] encoded = new byte[value.length + 2];
        encoded[0] = (byte) tag;
        encoded[1] = (byte) value.length;
        System.arraycopy(value, 0, encoded, 2, value.length);
        return encoded;
    }

    private static byte[] concatenate(byte[]... values) {
        int length = 0;
        for (byte[] value : values) {
            length = Math.addExact(length, value.length);
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    /** Repeatable test content that accounts for every fixed comparison pass. */
    private static final class CountingContent implements RepeatableContent {
        private final byte[] encoded;
        private final AtomicInteger opens = new AtomicInteger();
        private final AtomicInteger closes = new AtomicInteger();

        private CountingContent(byte[] encoded) {
            this.encoded = encoded.clone();
        }

        @Override
        public InputStream openStream() {
            opens.incrementAndGet();
            return new FilterInputStream(new ByteArrayInputStream(encoded)) {
                @Override
                public void close() throws IOException {
                    super.close();
                    closes.incrementAndGet();
                }
            };
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(encoded.length);
        }

        @Override
        public String contentId() {
            return "test:counting-set";
        }

        @Override
        public void close() {
            // The immutable test value owns no external resource.
        }

        private int openCount() {
            return opens.get();
        }

        private int closeCount() {
            return closes.get();
        }
    }
}
