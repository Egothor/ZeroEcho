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
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/**
 * Strict current-schema tests for {@link FsCodec}.
 */
final class FsCodecTest {

    private static final int VERSION_OFFSET = Integer.BYTES;
    private static final int TYPE_OFFSET = VERSION_OFFSET + 1;
    private static final int FIRST_FIELD_TYPE_OFFSET = TYPE_OFFSET + 1;

    @Test
    void approvedSchemaRoundTripAndTypeBinding() {
        System.out.println("approvedSchemaRoundTripAndTypeBinding");
        CertificateProfile profile = profile();

        byte[] encoded = FsCodec.encode(FsCodec.CERTIFICATE_PROFILE, profile);
        CertificateProfile decoded = FsCodec.decode(FsCodec.CERTIFICATE_PROFILE, encoded);

        System.out.println("...encoded length=" + encoded.length);
        assertEquals(profile, decoded);
        assertThrows(IllegalStateException.class, () -> FsCodec.decode(FsCodec.CA_RECORD, encoded));
        System.out.println("...ok");
    }

    @Test
    void currentEnvelopeRejectsUnknownOldAndCorruptedPayloads() {
        System.out.println("currentEnvelopeRejectsUnknownOldAndCorruptedPayloads");
        byte[] valid = FsCodec.encode(FsCodec.CERTIFICATE_PROFILE, profile());

        byte[] unsupportedVersion = valid.clone();
        unsupportedVersion[VERSION_OFFSET] = (byte) (FsCodec.CURRENT_CODEC_VERSION + 1);
        assertInvalid(unsupportedVersion);

        byte[] unknownType = valid.clone();
        unknownType[TYPE_OFFSET] = (byte) 127;
        assertInvalid(unknownType);

        byte[] wrongFieldType = valid.clone();
        wrongFieldType[FIRST_FIELD_TYPE_OFFSET] = (byte) 2;
        assertInvalid(wrongFieldType);

        assertInvalid(Arrays.copyOf(valid, valid.length - 1));
        byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
        trailing[trailing.length - 1] = 1;
        assertInvalid(trailing);

        byte[] oldSetTag = "java.util.Set".getBytes(StandardCharsets.UTF_8);
        assertInvalid(oldSetTag);
        System.out.println("...ok");
    }

    @Test
    void attackerClassNamesCannotSelectOrInitializeRuntimeTypes() {
        System.out.println("attackerClassNamesCannotSelectOrInitializeRuntimeTypes");
        List<String> classNames = List.of("java.io.File", "org.bouncycastle.asn1.ASN1ObjectIdentifier",
                "zeroecho.pki.impl.fs.FsCodecTest$ArbitraryRecord",
                "zeroecho.pki.impl.fs.FsCodecTest$ArbitraryEnum",
                "zeroecho.pki.impl.fs.FsCodecTest$StaticInitializerSentinel");

        for (String className : classNames) {
            byte[] oldPayload = className.getBytes(StandardCharsets.UTF_8);
            assertInvalid(oldPayload);
        }

        System.out.println("...rejected class names=" + classNames.size());
        assertFalse(InitializationProbe.INITIALIZED.get());
        System.out.println("...ok");
    }

    @Test
    void attributeSetsPersistStructurallyAndDecodeCanonically() {
        System.out.println("attributeSetsPersistStructurallyAndDecodeCanonically");
        AttributeId id = new AttributeId("test.attribute");
        List<AttributeValue> values = List.of(new AttributeValue.StringValue("value"),
                new AttributeValue.BooleanValue(true), new AttributeValue.IntegerValue(42L),
                new AttributeValue.InstantValue(Instant.parse("2026-01-02T03:04:05Z")),
                new AttributeValue.BytesValue(new byte[] { 1, 2, 3 }));

        AttributeSet core = new SimpleAttributeSet(List.of(new SimpleAttributeSet.Entry(id, values)));
        Map<AttributeId, List<AttributeValue>> map = new LinkedHashMap<>();
        map.put(id, values);
        AttributeSet framework = zeroecho.pki.impl.framework.x509.bc.SimpleAttributeSet.of(map);

        ParsedCertificationRequest decodedCore = roundTripRequest(core);
        ParsedCertificationRequest decodedFramework = roundTripRequest(framework);

        assertInstanceOf(SimpleAttributeSet.class, decodedCore.attributes());
        assertInstanceOf(SimpleAttributeSet.class, decodedFramework.attributes());
        assertAttributeValues(values, decodedCore.attributes().getAll(id));
        assertAttributeValues(values, decodedFramework.attributes().getAll(id));
        System.out.println("...canonical type=" + decodedFramework.attributes().getClass().getSimpleName());
        System.out.println("...ok");
    }

    @Test
    void byteAttributeValuesAreDefensivelyCopied() {
        System.out.println("byteAttributeValuesAreDefensivelyCopied");
        AttributeId id = new AttributeId("test.bytes");
        byte[] source = new byte[] { 10, 11, 12 };
        AttributeValue.BytesValue bytesValue = new AttributeValue.BytesValue(source);
        AttributeSet attributes = new SimpleAttributeSet(
                List.of(new SimpleAttributeSet.Entry(id, List.of(bytesValue))));
        byte[] encoded = FsCodec.encode(FsCodec.PARSED_REQUEST, request(attributes));

        Arrays.fill(source, (byte) 0);
        ParsedCertificationRequest decoded = FsCodec.decode(FsCodec.PARSED_REQUEST, encoded);
        AttributeValue.BytesValue decodedValue =
                (AttributeValue.BytesValue) decoded.attributes().getAll(id).get(0);
        byte[] second = decodedValue.value();

        System.out.println("...decoded byte count=" + second.length);
        assertArrayEquals(new byte[] { 10, 11, 12 }, second);
        System.out.println("...ok");
    }

    @Test
    void malformedPackedLengthAndOptionalMarkerFailClosed() {
        System.out.println("malformedPackedLengthAndOptionalMarkerFailClosed");
        byte[] encoded = FsCodec.encode(FsCodec.CERTIFICATE_PROFILE, profile());
        byte[] malformedLength = encoded.clone();
        malformedLength[FIRST_FIELD_TYPE_OFFSET + 1] = (byte) 0xFF;
        assertInvalid(malformedLength);

        byte[] truncatedHeader = Arrays.copyOf(encoded, TYPE_OFFSET);
        assertInvalid(truncatedHeader);
        System.out.println("...ok");
    }

    private static ParsedCertificationRequest roundTripRequest(AttributeSet attributes) {
        byte[] encoded = FsCodec.encode(FsCodec.PARSED_REQUEST, request(attributes));
        return FsCodec.decode(FsCodec.PARSED_REQUEST, encoded);
    }

    private static ParsedCertificationRequest request(AttributeSet attributes) {
        return new ParsedCertificationRequest(new PkiId("request-1"), new FormatId("x509"),
                new SubjectRef("subject-1"), new EncodedObject(Encoding.DER, new byte[] { 4, 5, 6 }),
                Optional.of(new Validity(Instant.parse("2026-01-02T03:04:05Z"),
                        Instant.parse("2027-01-02T03:04:05Z"))),
                Optional.of("profile-1"), attributes);
    }

    private static CertificateProfile profile() {
        return new CertificateProfile("profile-a", new FormatId("x509"), "Profile A",
                List.of(new AttributeId("required")), List.of(new AttributeId("optional")),
                Optional.of(Duration.ofDays(365)), true);
    }

    private static void assertInvalid(byte[] encoded) {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> FsCodec.decode(FsCodec.CERTIFICATE_PROFILE, encoded));
        assertTrue(failure.getMessage().contains("INVALID_CURRENT_PAYLOAD"));
    }

    private static void assertAttributeValues(List<AttributeValue> expected, List<AttributeValue> actual) {
        assertEquals(expected.size(), actual.size());
        for (int index = 0; index < expected.size(); index++) {
            AttributeValue expectedValue = expected.get(index);
            AttributeValue actualValue = actual.get(index);
            if (expectedValue instanceof AttributeValue.BytesValue expectedBytes
                    && actualValue instanceof AttributeValue.BytesValue actualBytes) {
                assertArrayEquals(expectedBytes.value(), actualBytes.value());
            } else {
                assertEquals(expectedValue, actualValue);
            }
        }
    }

    private record ArbitraryRecord(String value) {
    }

    private enum ArbitraryEnum {
        VALUE
    }

    private static final class InitializationProbe {
        private static final AtomicBoolean INITIALIZED = new AtomicBoolean();
    }

    private static final class StaticInitializerSentinel {
        static {
            InitializationProbe.INITIALIZED.set(true);
        }

        private StaticInitializerSentinel() {
        }
    }
}
