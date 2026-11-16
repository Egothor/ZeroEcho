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
package zeroecho.pki.api.hybrid.sdk;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.*;
import zeroecho.pki.api.profile.*;
import zeroecho.pki.api.request.*;

/**
 * Public target projections bind exact keys, provider and complete path without private data.
 */
final class SdkIssuancePreviewTest {
    /**
     * Snapshots effective names and retains absolute validity and both issuer bindings.
     *
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void snapshotsEffectiveNamesAndRetainsAbsoluteValidityAndBothIssuerBindings() throws Exception {
        var names = new ArrayList<SubjectRdn>(); names.add(new SubjectRdn(SubjectRdnType.COMMON_NAME, "Preview"));
        var value = preview("a".repeat(64), names, true);
        names.clear();
        var effective = value.effectiveSubjectValue().objectFields();
        assertEquals("2026-11-14T00:00:00Z", effective.get("notBefore").textValue());
        assertEquals("2026-11-14T01:00:00Z", effective.get("notAfter").textValue());
        assertEquals(1, value.subject().size());
        assertEquals(8, value.primaryIssuerBindingFrame().kind());
        assertEquals(9, value.alternativeIssuerBindingFrame().orElseThrow().kind());
        assertArrayEquals(HybridSdkFrame.hash(value.issuerPrimarySpki().bytes()), value.primaryIssuerBindingFrame().field(5));
        assertTrue(value.bindingSetCommitment().matches("sha512:[0-9a-f]{128}"));
        assertNotEquals(value.bindingSetCommitment(), preview("b".repeat(64), value.subject(), true).bindingSetCommitment());
    }
    /**
     * Represents absent alternative and empty subject without creating key references.
     *
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void representsAbsentAlternativeAndEmptySubjectWithoutCreatingKeyReferences() throws Exception {
        var value = preview("a".repeat(64), List.of(), false);
        assertTrue(value.subject().isEmpty());
        assertTrue(value.alternativeIssuerBindingFrame().isEmpty());
        assertTrue(value.effectiveSubjectValue().objectFields().containsKey("sans"));
        assertThrows(UnsupportedOperationException.class, () -> value.subject().add(new SubjectRdn(SubjectRdnType.COMMON_NAME, "changed")));
        assertThrows(NullPointerException.class, () -> preview("a".repeat(64), null, false));
    }
    private static SdkIssuancePreview preview(String path, List<SubjectRdn> names, boolean alternative) throws Exception {
        byte[] spki = HexFormat.of().parseHex("302a300506032b6570032100" + "11".repeat(32));
        var encoded = new EncodedObject(Encoding.DER, spki);
        var key = new IssuerKeyBinding(new KeyRef("managed:primary"), BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE, new EncodedObject(Encoding.DER, HexFormat.of().parseHex("300506032b6570")),
                HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(spki)));
        var ca = new PkiId("ca:preview"); var credential = new PkiId("x509:" + "c".repeat(64));
        var issuer = IssuerGeneration.idFor(ca, credential);
        var profile = new CertificateProfileRef("preview", 1, HexFormat.of().parseHex("d".repeat(64)));
        var optional = alternative ? Optional.of(key) : Optional.<IssuerKeyBinding>empty();
        var binding = new IssuerCryptographicBinding(1, issuer, ca, credential, "x509", key, optional,
                "c".repeat(64), profile, "b".repeat(64), alternative
                        ? IssuerCryptographicBinding.HybridSignatureBaseline.COR3_SIGNED_WRAPPER
                        : IssuerCryptographicBinding.HybridSignatureBaseline.NONE,
                "e".repeat(64));
        return new SdkIssuancePreview(ca, issuer, new PkiId("path:preview"), path, profile, new SubjectRef("CN=Preview"),
                names, List.of(new SubjectAlternativeName.IpAddress(new byte[]{127, 0, 0, 1})),
                new Validity(Instant.parse("2026-11-14T00:00:00Z"), Instant.parse("2026-11-14T01:00:00Z")),
                encoded, encoded, binding, encoded, alternative ? Optional.of(encoded) : Optional.empty(),
                "f".repeat(128), "a".repeat(64), HybridSdkValue.object(Map.of()));
    }
}
