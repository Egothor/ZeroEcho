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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;

final class EvidencePayloadEncodingTest {
    @Test void typedFamiliesRoundTripCanonicalFeedBytesAndIgnoreAbsentFamilies() {
        byte[] absent = payload(SimpleAttributeSet.builder().put(new AttributeId("urn:test:unrelated"),
                new AttributeValue.StringValue("value")).build());
        for (Sample sample : samples()) {
            assertEquals(sample.expected(), sample.decode().apply(payload(sample.attributes())).orElseThrow());
            assertTrue(sample.decode().apply(absent).isEmpty());
            for (Sample other : samples()) {
                if (other.expected().getClass() != sample.expected().getClass()) {
                    assertTrue(sample.decode().apply(payload(other.attributes())).isEmpty());
                }
            }
        }
    }

    @Test void rejectsMalformedNoncanonicalRawBinaryAndOversizedPayloadsWithSafeErrors() {
        for (Sample sample : samples()) {
            byte[] canonical = payload(sample.attributes());
            List<byte[]> invalid = new ArrayList<>();
            invalid.add(null);
            invalid.add(new byte[0]);
            invalid.add(Base64.getUrlDecoder().decode(canonical));
            invalid.add((new String(canonical, StandardCharsets.US_ASCII) + "=").getBytes(StandardCharsets.US_ASCII));
            invalid.add((new String(canonical, StandardCharsets.US_ASCII) + "\n").getBytes(StandardCharsets.US_ASCII));
            invalid.add(new byte[] {(byte) 0xff});
            invalid.add(new byte[1_048_581]); // Rejected before String/base64 allocation.
            invalid.add("A".repeat(1_048_580).getBytes(StandardCharsets.US_ASCII)); // Inclusive framing bound still requires valid content.
            for (byte[] value : invalid) {
                IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> sample.decode().apply(value));
                assertEquals(sample.error(), failure.getMessage());
                assertNull(failure.getCause());
            }
        }
    }

    @Test void rejectsPartialMistypedAndUnknownVersionVocabulariesAfterCanonicalTransport() {
        for (Sample sample : samples()) {
            AttributeId first = sample.attributes().ids().iterator().next();
            List<AttributeSet> invalid = List.of(
                    SimpleAttributeSet.builder().put(first, new AttributeValue.StringValue("partial")).build(),
                    SimpleAttributeSet.builder().put(first, new AttributeValue.BooleanValue(true)).build(),
                    SimpleAttributeSet.builder().put(new AttributeId(first.value().replace(":v1", ":v2")),
                            new AttributeValue.StringValue("unknown")).build());
            for (AttributeSet attributes : invalid) {
                IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                        () -> sample.decode().apply(payload(attributes)));
                assertEquals(sample.error(), failure.getMessage());
                assertNull(failure.getCause());
            }
        }
    }

    @Test void signingOutcomesRetainTheHistoricalClosedVocabulary() {
        for (SigningExecutionEvidence.Outcome outcome : SigningExecutionEvidence.Outcome.values()) {
            SigningExecutionEvidence evidence = SigningExecutionEvidence.terminal("store.provider", "accept-sign:v3:commitment",
                    "SYSTEM", "pki", Optional.of("SIGNED"), outcome);
            assertEquals(evidence, SigningExecutionEvidence.decode(evidence.attributes()).orElseThrow());
            assertEquals(evidence, SigningExecutionEvidence.decode(payload(evidence.attributes())).orElseThrow());
        }
        assertThrows(IllegalArgumentException.class, () -> SigningExecutionEvidence.terminal("store.provider", "commitment",
                "SYSTEM", "x".repeat(257), Optional.empty(), SigningExecutionEvidence.Outcome.FAILED));
    }

    private static byte[] payload(AttributeSet attributes) {
        return DomainAttributeEncoding.encode(attributes).getBytes(StandardCharsets.UTF_8);
    }

    private static List<Sample> samples() {
        IssuanceExecutionEvidence issuance = IssuanceExecutionEvidence.acme("account", "realm", "request", "ca", "profile");
        StatusGenerationEvidence status = StatusGenerationEvidence.system("CRL", "ca", "x509", "2026-01-01T00:00:00Z", Optional.empty());
        PublicationExecutionEvidence publication = PublicationExecutionEvidence.terminal("CREDENTIAL", "credential", "FILESYSTEM",
                "target", 1, Optional.empty(), Optional.empty(), PublicationExecutionEvidence.Outcome.SUCCEEDED);
        SigningExecutionEvidence signing = SigningExecutionEvidence.terminal("store.provider", "commitment", "SYSTEM", "pki",
                Optional.empty(), SigningExecutionEvidence.Outcome.SIGNED);
        return List.of(new Sample(issuance, issuance.attributes(), bytes -> IssuanceExecutionEvidence.decode(bytes),
                        "Issuance execution evidence is invalid"),
                new Sample(status, status.attributes(), bytes -> StatusGenerationEvidence.decode(bytes),
                        "Status generation evidence is invalid"),
                new Sample(publication, publication.attributes(), bytes -> PublicationExecutionEvidence.decode(bytes),
                        "Publication execution evidence is invalid"),
                new Sample(signing, signing.attributes(), bytes -> SigningExecutionEvidence.decode(bytes),
                        "Signing execution evidence is invalid"));
    }

    private record Sample(Object expected, AttributeSet attributes, Function<byte[], Optional<?>> decode, String error) { }
}
