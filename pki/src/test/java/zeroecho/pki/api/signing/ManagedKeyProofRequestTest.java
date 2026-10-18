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

package zeroecho.pki.api.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

final class ManagedKeyProofRequestTest {
    private static final PkiId AUTHORITY = new PkiId("authority");
    private static final PkiId RESPONDER = new PkiId("responder");
    private static final KeyRef KEY = new KeyRef("managed-key");

    @Test void requestsValidateRequiredCoordinatesWithoutResolvingThem() {
        assertEquals(KEY, new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(), "profile", KEY).keyRef());
        assertEquals(KEY, new ManagedKeyProofRequest.OcspResponder(AUTHORITY, RESPONDER, KEY).keyRef());
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofRequest.CaSubject(null, Optional.empty(), "profile", KEY));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofRequest.CaSubject(AUTHORITY, null, "profile", KEY));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(), null, KEY));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(), "profile", null));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofRequest.OcspResponder(null, RESPONDER, KEY));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofRequest.OcspResponder(AUTHORITY, null, KEY));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofRequest.OcspResponder(AUTHORITY, RESPONDER, null));
        for (String blank : List.of("", " ", "\t\n")) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(), blank, KEY));
        }
    }

    @Test void limitsUseStrictUtf8BytesWithInclusiveBoundaries() {
        PkiId maximumId = new PkiId("\u00e9".repeat(2048));
        String maximumProfile = "\u00e9".repeat(128);
        KeyRef maximumKey = new KeyRef("\ud83d\ude00".repeat(262_144));
        new ManagedKeyProofRequest.CaSubject(maximumId, Optional.of(maximumId), maximumProfile, maximumKey);
        new ManagedKeyProofRequest.OcspResponder(maximumId, maximumId, maximumKey);
        for (String invalid : List.of(maximumId.value() + "x", "x\ud800", "x\udc00", "\ud800x")) {
            PkiId id = new PkiId(invalid);
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.CaSubject(id, Optional.empty(), "profile", KEY));
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.of(id), "profile", KEY));
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.OcspResponder(id, RESPONDER, KEY));
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.OcspResponder(AUTHORITY, id, KEY));
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofScope(ManagedKeyProofPurpose.OCSP_RESPONDER_KEY, Optional.of(id)));
        }
        for (String invalid : List.of(maximumProfile + "x", "x\ud800", "x\udc00")) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(), invalid, KEY));
        }
        for (String invalid : List.of(maximumKey.value() + "x", "x\ud800", "x\udc00")) {
            KeyRef key = new KeyRef(invalid);
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(), "profile", key));
            assertThrows(IllegalArgumentException.class,
                    () -> new ManagedKeyProofRequest.OcspResponder(AUTHORITY, RESPONDER, key));
        }
    }

    @Test void purposeScopeAndSemanticKindHaveExactCombinations() {
        ManagedKeyProofScope ca = new ManagedKeyProofScope(ManagedKeyProofPurpose.CA_SUBJECT_KEY, Optional.empty());
        ManagedKeyProofScope ocsp = new ManagedKeyProofScope(ManagedKeyProofPurpose.OCSP_RESPONDER_KEY, Optional.of(RESPONDER));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofScope(null, Optional.empty()));
        assertThrows(NullPointerException.class, () -> new ManagedKeyProofScope(ManagedKeyProofPurpose.CA_SUBJECT_KEY, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ManagedKeyProofScope(ManagedKeyProofPurpose.CA_SUBJECT_KEY, Optional.of(RESPONDER)));
        assertThrows(IllegalArgumentException.class,
                () -> new ManagedKeyProofScope(ManagedKeyProofPurpose.OCSP_RESPONDER_KEY, Optional.empty()));
        AccessContext access = new AccessContext(new Principal("TEST", "actor"), new Purpose("PROOF"),
                Optional.empty(), Optional.empty());
        for (SemanticSigningKind kind : SemanticSigningKind.values()) {
            if (kind == SemanticSigningKind.KEY_PROOF) {
                for (ManagedKeyProofScope proof : List.of(ca, ocsp)) {
                    assertEquals(Optional.of(proof), scope(kind, access, Optional.of(proof)).keyProof());
                }
                assertThrows(IllegalArgumentException.class, () -> scope(kind, access, Optional.empty()));
            } else {
                assertEquals(Optional.empty(), scope(kind, access, Optional.empty()).keyProof());
                assertThrows(IllegalArgumentException.class, () -> scope(kind, access, Optional.of(ca)));
            }
            assertThrows(NullPointerException.class, () -> scope(kind, access, null));
        }
    }

    private static SemanticSigningScope scope(SemanticSigningKind kind, AccessContext access,
            Optional<ManagedKeyProofScope> proof) {
        return new SemanticSigningScope(kind, "operation", access, KEY, Optional.of(AUTHORITY),
                Optional.empty(), Optional.empty(), proof);
    }
}
