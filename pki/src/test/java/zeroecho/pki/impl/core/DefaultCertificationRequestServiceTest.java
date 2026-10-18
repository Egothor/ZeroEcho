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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;

final class DefaultCertificationRequestServiceTest {
    @Test
    void encodedRequestReturnsOnlyAnIndependentFingerprintCheckedSnapshot() throws Exception {
        DefaultCertificationRequestService service = isolated();
        byte[] original = { 1, 2, 3 }; // Deliberately not a CSR: restoration must not parse or verify it.
        byte[] source = original.clone();
        ParsedCertificationRequest parsed = parsed(BcX509CredentialFramework.FORMAT_ID, identity(source),
                attributes(new AttributeValue.BytesValue(source)));
        CertificationRequest restored = service.encodedRequest(parsed);
        source[0] = 9;
        restored.encoded().bytes()[1] = 9;
        assertEquals(BcX509CredentialFramework.FORMAT_ID, restored.formatId());
        assertEquals(Encoding.DER, restored.encoded().encoding());
        assertArrayEquals(original, restored.encoded().bytes());
        assertThrows(IllegalArgumentException.class, () -> service.encodedRequest(parsed));
        byte[] maximum = new byte[1024 * 1024];
        assertEquals(maximum.length, service.encodedRequest(parsed(BcX509CredentialFramework.FORMAT_ID,
                identity(maximum), attributes(new AttributeValue.BytesValue(maximum)))).encoded().bytes().length);
    }

    @Test
    void typedRecoveryRejectsMixedAttributesWrongIdentityAndMutation() throws Exception {
        DefaultCertificationRequestService service = isolated();
        byte[] bytes = { 1, 2, 3 };
        String crmfId = "crmf:" + identity(bytes).substring(4);
        AttributeSet crmf = new SimpleAttributeSet(List.of(new SimpleAttributeSet.Entry(BcX509Attributes.CRMF_DER,
                List.of(new AttributeValue.BytesValue(bytes)))));
        ParsedCertificationRequest parsed = parsed(BcX509CredentialFramework.FORMAT_ID, crmfId, crmf);
        assertEquals(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, service.encodedX509Request(parsed).kind());
        assertArrayEquals(bytes, service.encodedX509Request(parsed).der());
        assertThrows(IllegalArgumentException.class, () -> service.encodedRequest(parsed));
        assertThrows(IllegalArgumentException.class, () -> service.encodedX509Request(
                parsed(BcX509CredentialFramework.FORMAT_ID, identity(bytes), crmf)));
        AttributeSet mixed = new SimpleAttributeSet(List.of(
                new SimpleAttributeSet.Entry(BcX509Attributes.CRMF_DER, List.of(new AttributeValue.BytesValue(bytes))),
                new SimpleAttributeSet.Entry(BcX509Attributes.CSR_DER, List.of(new AttributeValue.BytesValue(bytes)))));
        assertThrows(IllegalArgumentException.class, () -> service.encodedX509Request(
                parsed(BcX509CredentialFramework.FORMAT_ID, crmfId, mixed)));
        bytes[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> service.encodedX509Request(parsed));
    }

    @Test
    void encodedRequestRejectsWrongFormatCardinalityTypeSizeAndIdentity() throws Exception {
        DefaultCertificationRequestService service = isolated();
        byte[] bytes = { 1, 2, 3 };
        String identity = identity(bytes);
        assertThrows(IllegalArgumentException.class, () -> service.encodedRequest(null));
        assertThrows(IllegalArgumentException.class, () -> service.encodedRequest(parsed(new FormatId("other"),
                identity, attributes(new AttributeValue.BytesValue(bytes)))));
        for (AttributeSet attributes : List.of(attributes(), attributes(new AttributeValue.StringValue("private")),
                attributes(new AttributeValue.BytesValue(bytes), new AttributeValue.BytesValue(bytes)),
                attributes(new AttributeValue.BytesValue(new byte[1024 * 1024 + 1])))) {
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> service.encodedRequest(parsed(BcX509CredentialFramework.FORMAT_ID, identity, attributes)));
            assertEquals("Retained certification request payload is invalid", failure.getMessage());
        }
        // Empty byte attributes are already rejected by the immutable value constructor.
        assertThrows(IllegalArgumentException.class, () -> new AttributeValue.BytesValue(new byte[0]));
        for (String wrong : List.of("csr:" + "0".repeat(64), "req:" + identity.substring(4),
                identity.toUpperCase(java.util.Locale.ROOT))) {
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> service.encodedRequest(parsed(BcX509CredentialFramework.FORMAT_ID, wrong,
                            attributes(new AttributeValue.BytesValue(bytes)))));
            assertEquals("Retained certification request identity differs", failure.getMessage());
        }
    }

    private static DefaultCertificationRequestService isolated() {
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                    throw new AssertionError("Unexpected store access: " + method.getName());
                });
        CredentialFramework framework = (CredentialFramework) Proxy.newProxyInstance(CredentialFramework.class.getClassLoader(),
                new Class<?>[] { CredentialFramework.class }, (proxy, method, args) -> {
                    throw new AssertionError("Unexpected framework access: " + method.getName());
                });
        return new DefaultCertificationRequestService(store, framework);
    }

    private static AttributeSet attributes(AttributeValue... values) {
        return new SimpleAttributeSet(List.of(new SimpleAttributeSet.Entry(BcX509Attributes.CSR_DER, List.of(values))));
    }

    private static ParsedCertificationRequest parsed(FormatId format, String identity, AttributeSet attributes) {
        return new ParsedCertificationRequest(new PkiId(identity), format, new SubjectRef("CN=Diagnostic"),
                new EncodedObject(Encoding.DER, new byte[] { 1 }), Optional.empty(), Optional.empty(), attributes);
    }

    private static String identity(byte[] bytes) throws Exception {
        return "csr:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
