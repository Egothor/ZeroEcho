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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

class RevocationExecutionEvidenceTest {

    @Test
    void commitsExactJustificationPresenceAndNeverStoresPlaintext() {
        String absent = RevocationExecutionEvidence.commitJustification(Optional.empty());
        String empty = RevocationExecutionEvidence.commitJustification(Optional.of(""));
        String first = RevocationExecutionEvidence.commitJustification(Optional.of("ticket-ä"));
        String changed = RevocationExecutionEvidence.commitJustification(Optional.of("ticket-a"));
        assertNotEquals(absent, empty);
        assertNotEquals(first, changed);

        RevocationExecutionEvidence evidence = RevocationExecutionEvidence.administrative("operator-a", "realm-a",
                "request-a", RevocationExecutionEvidence.Authentication.DIRECT_MTLS,
                RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT, "a".repeat(64),
                Optional.of("ticket-ä"));
        assertEquals(first, string(evidence, RevocationExecutionEvidence.JUSTIFICATION_COMMITMENT));
        assertFalse(evidence.attributes().ids().stream().flatMap(id -> evidence.attributes().getAll(id).stream())
                .filter(AttributeValue.StringValue.class::isInstance)
                .map(AttributeValue.StringValue.class::cast).map(AttributeValue.StringValue::value)
                .anyMatch("ticket-ä"::equals));
    }

    @Test
    void keepsAcmeProtocolNativeAndRejectsMixedClassifications() {
        RevocationExecutionEvidence acme = RevocationExecutionEvidence.acme("account-a", "realm-a", "request-a");
        assertEquals("ACME_ACCOUNT", string(acme, RevocationExecutionEvidence.ACTOR_TYPE));
        assertEquals("ACME_ACCOUNT_JWS", string(acme, RevocationExecutionEvidence.AUTHENTICATION));
        assertEquals("ACME_OWNERSHIP", string(acme, RevocationExecutionEvidence.AUTHORIZATION));
        assertFalse(acme.attributes().ids().contains(RevocationExecutionEvidence.AUTHORIZATION_PATH));
        assertFalse(acme.attributes().ids().contains(RevocationExecutionEvidence.OPERATION_COMMITMENT));
        assertThrows(IllegalArgumentException.class, () -> new RevocationExecutionEvidence(
                RevocationExecutionEvidence.ActorType.ACME_ACCOUNT, "account-a", "realm-a", "request-a",
                RevocationExecutionEvidence.Authentication.DIRECT_MTLS,
                RevocationExecutionEvidence.Authorization.ALLOWED,
                Optional.of(RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT),
                Optional.of("a".repeat(64)), Optional.of("b".repeat(64)),
                RevocationExecutionEvidence.Outcome.COMMITTED));
    }

    @Test
    void strictlyDecodesOnlyCompleteClosedVersionOneEvidence() {
        RevocationExecutionEvidence administrative = RevocationExecutionEvidence.administrative("operator-a",
                "realm-a", "request-a", RevocationExecutionEvidence.Authentication.TRUSTED_REVERSE_PROXY,
                RevocationExecutionEvidence.AuthorizationPath.APPROVAL, "a".repeat(64), Optional.empty());
        RevocationExecutionEvidence acme = RevocationExecutionEvidence.acme("account-a", "realm-a", "request-b");
        assertEquals(administrative,
                RevocationExecutionEvidence.decode(administrative.attributes()).orElseThrow());
        assertEquals(acme, RevocationExecutionEvidence.decode(acme.attributes()).orElseThrow());
        assertTrue(RevocationExecutionEvidence.decode(SimpleAttributeSet.builder()
                .put(new AttributeId("legacy.note"), new AttributeValue.StringValue("ignored")).build()).isEmpty());

        AttributeSet partial = SimpleAttributeSet.builder()
                .put(RevocationExecutionEvidence.ACTOR_TYPE,
                        new AttributeValue.StringValue("ADMIN_PRINCIPAL"))
                .build();
        AttributeSet unknownName = SimpleAttributeSet.builder()
                .put(new AttributeId("urn:zeroecho:pki:revocation-evidence:unknown:v1"),
                        new AttributeValue.StringValue("value"))
                .build();
        AttributeSet unknownVersion = SimpleAttributeSet.builder()
                .put(new AttributeId("urn:zeroecho:pki:revocation-evidence:actor-type:v2"),
                        new AttributeValue.StringValue("ADMIN_PRINCIPAL"))
                .build();
        AttributeSet wrongType = SimpleAttributeSet.builder()
                .put(RevocationExecutionEvidence.ACTOR_TYPE, new AttributeValue.IntegerValue(1L))
                .build();
        SimpleAttributeSet duplicated = new SimpleAttributeSet(List.of(new SimpleAttributeSet.Entry(
                RevocationExecutionEvidence.ACTOR_TYPE, List.of(
                        new AttributeValue.StringValue("ADMIN_PRINCIPAL"),
                        new AttributeValue.StringValue("ADMIN_PRINCIPAL")))));
        List<SimpleAttributeSet.Entry> mixedEntries = new ArrayList<>();
        for (AttributeId id : administrative.attributes().ids()) {
            mixedEntries.add(new SimpleAttributeSet.Entry(id, administrative.attributes().getAll(id)));
        }
        mixedEntries.add(new SimpleAttributeSet.Entry(
                new AttributeId("urn:zeroecho:pki:revocation-evidence:actor-type:v2"),
                List.of(new AttributeValue.StringValue("ADMIN_PRINCIPAL"))));
        AttributeSet validWithUnknownVersion = new SimpleAttributeSet(mixedEntries);
        assertThrows(IllegalArgumentException.class, () -> RevocationExecutionEvidence.decode(partial));
        assertThrows(IllegalArgumentException.class, () -> RevocationExecutionEvidence.decode(unknownName));
        assertThrows(IllegalArgumentException.class, () -> RevocationExecutionEvidence.decode(unknownVersion));
        assertThrows(IllegalArgumentException.class, () -> RevocationExecutionEvidence.decode(wrongType));
        assertThrows(IllegalArgumentException.class, () -> RevocationExecutionEvidence.decode(duplicated));
        assertThrows(IllegalArgumentException.class,
                () -> RevocationExecutionEvidence.decode(validWithUnknownVersion));
    }

    private static String string(RevocationExecutionEvidence evidence, AttributeId id) {
        return ((AttributeValue.StringValue) evidence.attributes().get(id).orElseThrow()).value();
    }
}
