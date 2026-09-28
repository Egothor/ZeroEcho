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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.signing.ManagedKeyProofPurpose;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningScope;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.impl.core.continuation.DomainContinuationPublisher.PostconditionFailure;

final class ManagedKeyProofCommandTest {
    private static final PkiId AUTHORITY = new PkiId("authority");
    private static final PkiId SUBJECT = new PkiId("subject");
    private static final PkiId RESPONDER = new PkiId("responder");
    private static final KeyRef KEY = new KeyRef("key");
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "actor"),
            new Purpose("PROOF"), Optional.empty(), Optional.empty());

    @Test void prefixRoundTripMapsOnlyThePurposeSpecificScope() {
        for (ManagedKeyProofRequest request : requests()) {
            List<String> fields = ManagedKeyProofCommand.prefix(request);
            DomainCommandEncoding.Decoded command = new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, fields);
            assertEquals(request, ManagedKeyProofCommand.decodePrefix(command));
            SemanticSigningScope scope = ManagedKeyProofCommand.scope(command, ACCESS, KEY);
            assertEquals(SemanticSigningKind.KEY_PROOF, scope.kind());
            assertEquals(ManagedKeyProofCommand.OPERATION, scope.operation());
            assertEquals(ACCESS, scope.accessContext());
            assertEquals(KEY, scope.keyRef());
            assertEquals(Optional.of(AUTHORITY), scope.authorityId());
            switch (request) {
                case ManagedKeyProofRequest.CaSubject ca -> {
                    assertEquals(List.of("CA_SUBJECT_KEY", "authority",
                            ca.subjectAuthorityId().map(PkiId::value).orElse(""), "profile", "", "key"), fields);
                    assertEquals(ca.subjectAuthorityId(), scope.subjectAuthorityId());
                    assertEquals(Optional.of("profile"), scope.profileId());
                    assertEquals(ManagedKeyProofPurpose.CA_SUBJECT_KEY, scope.keyProof().orElseThrow().purpose());
                    assertEquals(Optional.empty(), scope.keyProof().orElseThrow().responderCredentialId());
                }
                case ManagedKeyProofRequest.OcspResponder ignored -> {
                    assertEquals(List.of("OCSP_RESPONDER_KEY", "authority", "", "", "responder", "key"), fields);
                    assertEquals(Optional.empty(), scope.subjectAuthorityId());
                    assertEquals(Optional.empty(), scope.profileId());
                    assertEquals(ManagedKeyProofPurpose.OCSP_RESPONDER_KEY, scope.keyProof().orElseThrow().purpose());
                    assertEquals(Optional.of(RESPONDER), scope.keyProof().orElseThrow().responderCredentialId());
                }
            }
            assertThrows(IllegalArgumentException.class,
                    () -> ManagedKeyProofCommand.scope(command, ACCESS, new KeyRef("other-key")));
        }
    }

    @Test void prefixRejectsCrossPurposeCoordinatesAndMalformedFields() {
        for (ManagedKeyProofRequest request : requests()) {
            List<String> valid = ManagedKeyProofCommand.prefix(request);
            for (int index = 0; index < 6; index++) {
                List<String> fields = new ArrayList<>(valid);
                fields.set(index, index == 0 ? "UNKNOWN" : " ");
                assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.decodePrefix(
                        new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, fields)));
            }
            assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.decodePrefix(
                    new DomainCommandEncoding.Decoded("OTHER", valid)));
            for (int count = 0; count < 6; count++) {
                List<String> truncated = valid.subList(0, count);
                assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.decodePrefix(
                        new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, truncated)));
            }
        }
        for (List<String> fields : List.of(
                List.of("CA_SUBJECT_KEY", "authority", "", "profile", "responder", "key"),
                List.of("CA_SUBJECT_KEY", "authority", "", "", "", "key"),
                List.of("OCSP_RESPONDER_KEY", "authority", "subject", "", "responder", "key"),
                List.of("OCSP_RESPONDER_KEY", "authority", "", "profile", "responder", "key"),
                List.of("OCSP_RESPONDER_KEY", "authority", "", "", "", "key"))) {
            assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.decodePrefix(
                    new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, fields)));
        }
    }

    @Test void prefixNeverAdmitsFullPreparationOrArtifactPublication() {
        PkiStore forbidden = (PkiStore) java.lang.reflect.Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    throw new AssertionError("Proof prefix must not access artifact storage");
                });
        DomainContinuationPublisher publisher = new DomainContinuationPublisher(forbidden);
        for (ManagedKeyProofRequest request : requests()) {
            DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.KEY_PROOF,
                    ManagedKeyProofCommand.OPERATION, ManagedKeyProofCommand.prefix(request).toArray(String[]::new));
            assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(template));
            DomainContinuationStore.Record domain = new DomainContinuationStore.Record(new PkiId("proof"), 2,
                    DomainContinuationStore.Kind.KEY_PROOF, Optional.empty(), DomainContinuationStore.State.FAILED,
                    0, Instant.EPOCH, Instant.EPOCH.plusSeconds(60), template.command(), template.commandCommitment(),
                    Optional.empty(), Optional.empty(), Optional.of("FAILED"));
            EncodedObject signature = new EncodedObject(Encoding.BINARY, new byte[] { 1 });
            assertThrows(PostconditionFailure.class, () -> publisher.reconstruct(domain, signature));
            assertThrows(PostconditionFailure.class, () -> publisher.publish(domain, signature));
        }
    }

    private static List<ManagedKeyProofRequest> requests() {
        return List.of(new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(), "profile", KEY),
                new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.of(SUBJECT), "profile", KEY),
                new ManagedKeyProofRequest.OcspResponder(AUTHORITY, RESPONDER, KEY));
    }
}
