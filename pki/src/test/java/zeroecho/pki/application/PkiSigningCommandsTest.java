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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningScope;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

final class PkiSigningCommandsTest {
    private static final PkiId CA = new PkiId("ca:subject");
    private static final PkiId PARENT = new PkiId("ca:parent");
    private static final PkiId GENERATION = new PkiId("issuer:exact-generation");
    private static final PkiId REQUEST = new PkiId("csr:request");
    private static final PkiId CREDENTIAL = new PkiId("credential:predecessor");
    private static final KeyRef KEY = new KeyRef("key:current");
    private static final KeyRef NEW_KEY = new KeyRef("key:replacement");
    private static final FormatId FORMAT = new FormatId("x509");
    private static final SubjectRef SUBJECT = new SubjectRef("CN=Subject");
    private static final Instant NOW = Instant.parse("2026-01-02T03:04:05Z");
    private static final byte[] CSR = { 1, 2, 3 };
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "caller"),
            new Purpose("ISSUE"), Optional.empty(), Optional.empty());
    private static final Optional<IssuanceExecutionEvidence> EVIDENCE = Optional.of(
            IssuanceExecutionEvidence.administrative("caller", "realm", "request",
                    IssuanceExecutionEvidence.Authentication.DIRECT_MTLS,
                    IssuanceExecutionEvidence.AuthorizationPath.APPROVAL, "1".repeat(64), CA.value(), "profile"));

    @Test
    void mapsEveryCommandWithoutAcceptanceAndPassesExactCallerEvidenceAndCancellation() {
        Validity validity = new Validity(NOW, NOW.plusSeconds(60));
        List<Mapping> mappings = List.of(
                new Mapping(new PkiSigningOperation.CreateAuthority(FORMAT, SUBJECT, "profile", KEY),
                        "prepareRootCreation", value -> {
                            CaCreateCommand command = assertInstanceOf(CaCreateCommand.class, value);
                            assertEquals(FORMAT, command.formatId());
                            assertEquals(SUBJECT, command.subjectRef());
                            assertEquals("profile", command.profileId());
                            assertEquals(KEY, command.keyRef());
                            assertTrue(command.attributes().ids().isEmpty());
                        }),
                new Mapping(new PkiSigningOperation.CreateIntermediate(FORMAT, PARENT, SUBJECT, "profile", Optional.of(KEY)),
                        "prepareIntermediateCreation", value -> {
                            IntermediateCreateCommand command = assertInstanceOf(IntermediateCreateCommand.class, value);
                            assertEquals(PARENT, command.issuerCaId());
                            assertEquals(KEY, command.keyRef());
                            assertEquals(SUBJECT, command.subjectRef());
                        }),
                new Mapping(new PkiSigningOperation.IssueIntermediateCertificate(FORMAT, PARENT, CA, "profile", Optional.of(validity)),
                        "prepareIntermediateIssuance", value -> {
                            IntermediateCertIssueCommand command = assertInstanceOf(IntermediateCertIssueCommand.class, value);
                            assertEquals(CA, command.subjectCaId());
                            assertEquals(PARENT, command.issuerCaId());
                            assertEquals(KEY, command.keyRef());
                            assertEquals(Optional.of(validity), command.requestedValidity());
                        }),
                new Mapping(new PkiSigningOperation.RolloverCaCertificate(CA, Optional.empty()),
                        "prepareCaRollover", value -> assertEquals(CA, assertInstanceOf(CaRolloverCommand.Root.class, value).caId())),
                new Mapping(new PkiSigningOperation.RotateCaKey(CA, Optional.of(NEW_KEY), Optional.empty()),
                        "prepareCaKeyRotation", value -> assertEquals(NEW_KEY, assertInstanceOf(CaKeyRotationCommand.Root.class, value).newKeyRef())),
                new Mapping(new PkiSigningOperation.IssueCredential(CA, REQUEST, "profile"),
                        "prepareEndEntity", value -> {
                            EndEntityIssuanceRequest command = assertInstanceOf(EndEntityIssuanceRequest.class, value);
                            assertEquals(CA, command.issuerCaId());
                            assertEquals("profile", command.profileId());
                            assertArrayEquals(CSR, command.csrDer());
                            assertTrue(command.validityOverride().isEmpty());
                        }),
                new Mapping(new PkiSigningOperation.RenewCredential(CREDENTIAL), "prepareRenewal",
                        value -> assertEquals(CREDENTIAL, assertInstanceOf(EndEntityRenewalRequest.class, value).existingCredentialId())),
                new Mapping(new PkiSigningOperation.ReplaceCredential(CREDENTIAL, REQUEST, "profile"), "prepareReplacement", value -> {
                    EndEntityReplacementRequest command = assertInstanceOf(EndEntityReplacementRequest.class, value);
                    assertEquals(CREDENTIAL, command.existingCredentialId());
                    assertEquals("profile", command.profileId());
                    assertArrayEquals(CSR, command.csrDer());
                }),
                new Mapping(new PkiSigningOperation.ReissueCredential(CREDENTIAL), "prepareReissue",
                        value -> assertEquals(CREDENTIAL, assertInstanceOf(EndEntityReissueRequest.class, value).existingCredentialId())),
                new Mapping(new PkiSigningOperation.GenerateStatus(CA, StatusObjectType.CRL, FORMAT), "prepareFullCrl", value -> {
                    FullCrlRequest command = assertInstanceOf(FullCrlRequest.class, value);
                    assertEquals(GENERATION, command.issuerGenerationId());
                    assertEquals(Duration.ofDays(7), command.validity());
                }),
                new Mapping(new PkiSigningOperation.GenerateStatus(CA, StatusObjectType.DELTA_CRL, FORMAT), "prepareDeltaCrl", value -> {
                    DeltaCrlRequest command = assertInstanceOf(DeltaCrlRequest.class, value);
                    assertEquals(GENERATION, command.issuerGenerationId());
                    assertEquals(Duration.ofDays(7), command.validity());
                }));
        for (Mapping mapping : mappings) {
            checkMapping(mapping, CaKind.ROOT, EVIDENCE);
            checkMapping(mapping, CaKind.ROOT, Optional.empty());
        }
        checkMapping(new Mapping(new PkiSigningOperation.RolloverCaCertificate(CA, Optional.of(PARENT)),
                "prepareCaRollover", value -> {
                    CaRolloverCommand.Intermediate command = assertInstanceOf(CaRolloverCommand.Intermediate.class, value);
                    assertEquals(CA, command.caId());
                    assertEquals(PARENT, command.issuerCaId());
                    assertEquals(KEY, command.keyRef());
                }), CaKind.INTERMEDIATE, Optional.empty());
        checkMapping(new Mapping(new PkiSigningOperation.RotateCaKey(CA, Optional.of(NEW_KEY), Optional.of(PARENT)),
                "prepareCaKeyRotation", value -> {
                    CaKeyRotationCommand.Intermediate command = assertInstanceOf(CaKeyRotationCommand.Intermediate.class, value);
                    assertEquals(PARENT, command.issuerCaId());
                    assertEquals(NEW_KEY, command.newKeyRef());
                }), CaKind.INTERMEDIATE, Optional.empty());
    }

    @Test
    void rejectsMissingKeysInvalidIssuerStatusAndAbsentRequestsBeforePreparation() {
        assertThrows(IllegalArgumentException.class, () -> new PkiSigningOperation.CreateIntermediate(
                FORMAT, PARENT, SUBJECT, "profile", Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new PkiSigningOperation.RotateCaKey(CA, Optional.empty(), Optional.empty()));
        for (CaKind kind : CaKind.values()) {
            PkiSigningCommands commands = commands(rejectingService(), kind, Optional.of(requests()), () -> { });
            Optional<PkiId> invalidIssuer = kind == CaKind.ROOT ? Optional.of(PARENT) : Optional.empty();
            assertThrows(PkiException.class, () -> commands.prepare(
                    new PkiSigningOperation.RolloverCaCertificate(CA, invalidIssuer), ACCESS, Optional.empty(), CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> commands.prepare(
                    new PkiSigningOperation.RotateCaKey(CA, Optional.of(NEW_KEY), invalidIssuer), ACCESS, Optional.empty(), CancellationSignal.NONE));
        }
        PkiSigningCommands commands = commands(rejectingService(), CaKind.ROOT, Optional.of(requests()), () -> { });
        assertEquals("OCSP_TARGET_REQUIRED", assertThrows(PkiException.class, () -> commands.prepare(
                new PkiSigningOperation.GenerateStatus(CA, StatusObjectType.OCSP, FORMAT), ACCESS, Optional.empty(), CancellationSignal.NONE)).getMessage());
        assertThrows(IllegalArgumentException.class, () -> commands.prepare(new PkiSigningOperation.GenerateStatus(
                CA, StatusObjectType.CRL, new FormatId("other")), ACCESS, Optional.empty(), CancellationSignal.NONE));
        assertThrows(NoSuchElementException.class, () -> commands.prepare(new PkiSigningOperation.IssueCredential(
                CA, new PkiId("csr:absent"), "profile"), ACCESS, Optional.empty(), CancellationSignal.NONE));
        assertThrows(NoSuchElementException.class, () -> commands.prepare(new PkiSigningOperation.RolloverCaCertificate(
                new PkiId("ca:absent"), Optional.empty()), ACCESS, Optional.empty(), CancellationSignal.NONE));
        PkiSigningCommands noRequests = commands(rejectingService(), CaKind.ROOT, Optional.empty(), () -> { });
        assertThrows(UnsupportedOperationException.class, () -> noRequests.prepare(new PkiSigningOperation.IssueCredential(
                CA, REQUEST, "profile"), ACCESS, Optional.empty(), CancellationSignal.NONE));
    }

    @Test
    void projectsExactOrderedSafeCredentialAndStatusMetadataAndRejectsIncompleteState() throws Exception {
        PkiId statusId = new PkiId("status:exact");
        for (SemanticSigningKind kind : List.of(SemanticSigningKind.CA, SemanticSigningKind.ISSUANCE, SemanticSigningKind.STATUS)) {
            SemanticSigningOperation completed = observation(kind, SemanticSigningState.COMPLETED);
            SemanticSigningService service = proxy(SemanticSigningService.class, (receiver, method, arguments) -> {
                assertEquals("completedStatusObjectId", method.getName());
                assertSame(completed, arguments[0]);
                return kind == SemanticSigningKind.STATUS ? Optional.of(statusId) : Optional.empty();
            });
            PkiOperationResult result = commands(service, CaKind.ROOT, Optional.empty(), () -> { }).completedResult(completed);
            assertEquals("signing.operation", result.operationName());
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(CSR));
            assertEquals(List.of("operationId", "kind", "encoding", "resultSha256",
                    kind == SemanticSigningKind.STATUS ? "statusObjectId" : "credentialId"), new ArrayList<>(result.fields().keySet()));
            assertEquals(new PkiOperationValue.Text(completed.submissionId().id().value()), result.fields().get("operationId"));
            assertEquals(new PkiOperationValue.Text(kind.name()), result.fields().get("kind"));
            assertEquals(new PkiOperationValue.Text("DER"), result.fields().get("encoding"));
            assertEquals(new PkiOperationValue.Text(digest), result.fields().get("resultSha256"));
            assertEquals(new PkiOperationValue.Text(kind == SemanticSigningKind.STATUS ? statusId.value() : "x509:" + digest),
                    result.fields().get(kind == SemanticSigningKind.STATUS ? "statusObjectId" : "credentialId"));
        }
        PkiSigningCommands commands = commands(rejectingService(), CaKind.ROOT, Optional.empty(), () -> { });
        for (SemanticSigningState state : SemanticSigningState.values()) {
            if (state != SemanticSigningState.COMPLETED) {
                assertThrows(IllegalArgumentException.class, () -> commands.completedResult(observation(SemanticSigningKind.CA, state)));
            }
        }
    }

    private static void checkMapping(Mapping mapping, CaKind kind, Optional<IssuanceExecutionEvidence> evidence) {
        RuntimeException reachedPreparation = new IllegalStateException("Preparation boundary reached");
        CancellationSignal cancellation = () -> false;
        SemanticSigningService service = proxy(SemanticSigningService.class, (receiver, method, arguments) -> {
            assertEquals(mapping.method(), method.getName());
            assertSame(ACCESS, arguments[0]);
            mapping.check().accept(arguments[1]);
            assertSame(cancellation, arguments[arguments.length - 1]);
            if (arguments.length == 4) assertSame(evidence, arguments[2]);
            throw reachedPreparation;
        });
        assertSame(reachedPreparation, assertThrows(IllegalStateException.class, () ->
                commands(service, kind, Optional.of(requests()), () -> { }).prepare(mapping.operation(), ACCESS, evidence, cancellation)));
    }

    private static PkiSigningCommands commands(SemanticSigningService service, CaKind kind,
            Optional<CertificationRequestService> requests, Runnable requireOpen) {
        PkiRepository repository = proxy(PkiRepository.class, (receiver, method, arguments) -> {
            assertEquals("authority", method.getName());
            return CA.equals(arguments[0]) ? Optional.of(new CaRecord(CA, kind, CaState.ACTIVE, KEY, SUBJECT,
                    List.of(GENERATION), GENERATION, new PkiId("path:current"))) : Optional.empty();
        });
        return new DefaultPkiSigningCommands(service, repository, requests, requireOpen);
    }

    private static CertificationRequestService requests() {
        ParsedCertificationRequest parsed = new ParsedCertificationRequest(REQUEST, FORMAT, SUBJECT,
                new EncodedObject(Encoding.DER, CSR), Optional.empty(), Optional.empty(), new SimpleAttributeSet());
        return proxy(CertificationRequestService.class, (receiver, method, arguments) -> switch (method.getName()) {
            case "get" -> REQUEST.equals(arguments[0]) ? Optional.of(parsed) : Optional.empty();
            case "encodedRequest" -> {
                assertSame(parsed, arguments[0]);
                yield new CertificationRequest(FORMAT, new EncodedObject(Encoding.DER, CSR));
            }
            default -> throw new AssertionError("Unexpected request method: " + method.getName());
        });
    }

    private static SemanticSigningService rejectingService() {
        return proxy(SemanticSigningService.class, (receiver, method, arguments) -> {
            throw new AssertionError("Unexpected semantic call: " + method.getName());
        });
    }

    private static SemanticSigningOperation observation(SemanticSigningKind kind, SemanticSigningState state) {
        SigningSubmissionId id = SigningSubmissionId.create("test.signer", NOW, new SecureRandom());
        SemanticSigningScope scope = new SemanticSigningScope(kind, "TEST", ACCESS, KEY,
                Optional.of(CA), Optional.empty(), Optional.empty(), Optional.empty());
        return new SemanticSigningOperation(id, scope, SigningOperationState.SUCCEEDED, state, 1, 1,
                NOW, NOW.plusSeconds(60), Optional.empty(), state == SemanticSigningState.COMPLETED
                        ? Optional.of(new EncodedObject(Encoding.DER, CSR)) : Optional.empty());
    }

    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler));
    }

    private record Mapping(PkiSigningOperation operation, String method, Consumer<Object> check) { }
}
