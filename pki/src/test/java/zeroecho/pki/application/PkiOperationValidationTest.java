/*
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
 */
package zeroecho.pki.application;

import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.*;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.api.ca.*;
import zeroecho.pki.api.confirmation.*;
import zeroecho.pki.api.revocation.*;
import zeroecho.pki.impl.core.*;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.fs.*;
import zeroecho.pki.spi.store.*;
import zeroecho.pki.testkit.*;

/** Actual-store pure validation for administrative state, profile, revocation and OCSP inputs. */
class PkiOperationValidationTest {
    @Test void checksCurrentStateWithoutMutationsOrAudit(@TempDir Path root) throws Exception { exercise(root); }
    interface Action { void run() throws Exception; }
    static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    static void rejected(Action action) throws Exception {
        try { action.run(); throw new AssertionError("Invalid input accepted"); } catch (RuntimeException expected) { }
    }
    static <T> T unreachable(Class<T> type) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> { throw new AssertionError("Unexpected collaborator mutation: " + method.getName()); }));
    }
    static PkiStore readOnly(PkiStore store) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[]{PkiStore.class}, (proxy, method, args) -> {
            if (method.getName().equals("stagedContent")) {
                return Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(), new Class<?>[]{StagedContentStore.class}, (content, call, values) -> {
                    if (!call.getName().equals("openContent")) throw new AssertionError("Content mutation during validation");
                    try { return call.invoke(store.stagedContent(), values); } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            }
            if (method.getName().matches("(put|replace|activate|accept|transition|retire|revoke|begin).*|signingNow")) {
                throw new AssertionError("Store mutation during validation: " + method.getName());
            }
            try { return method.invoke(store, args); } catch (InvocationTargetException failure) { throw failure.getCause(); }
        });
    }
    static void exercise(Path root) throws Exception {
        try (var store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            var fixture = new IntermediateCreationFixture(); fixture.initialize(store, 2);
            var ca = store.getCa(IntermediateCreationFixture.CA).orElseThrow();
            var credential = store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow().credentialId();
            var pureStore = readOnly(store);
            var audit = unreachable(AuditSink.class);
            var profiles = new DefaultProfileService(pureStore, IntermediateCreationFixture.CLOCK, audit);
            var executor = new DefaultPkiOperationExecutor(new DefaultPkiOperationExecutor.ConfigurationSummary(1, "fs", "memory"),
                    pureStore, profiles, new DefaultRevocationService(pureStore, IntermediateCreationFixture.CLOCK, audit),
                    Optional.empty(), Optional.empty(), unreachable(CredentialConfirmationService.class), fixture.bindings, () -> { },
                    (limit, after, cancellation) -> { throw new AssertionError("Unexpected choice scan"); },
                    IntermediateCreationFixture.CLOCK, DashboardLiveSource.NONE);
            String profileId = store.requireActiveProfile("root-ca").reference().profileId();
            executor.validate(new PkiOperation.ActivateProfile(profileId, 1), CancellationSignal.NONE);
            rejected(() -> executor.validate(new PkiOperation.ActivateProfile("missing", 1), CancellationSignal.NONE));
            executor.validate(new PkiOperation.TransitionAuthority(ca.caId(), CaState.DISABLED, "maintenance"), CancellationSignal.NONE);
            check(store.getCa(ca.caId()).orElseThrow().equals(ca), "Transition validation changed CA");
            executor.validate(new PkiOperation.SelectIssuancePath(ca.caId(), ca.currentIssuanceIssuerId(), ca.issuanceChainPathId(), "select"), CancellationSignal.NONE);
            rejected(() -> executor.validate(new PkiOperation.SelectIssuancePath(ca.caId(), ca.currentIssuanceIssuerId(), new PkiId("missing"), "select"), CancellationSignal.NONE));
            rejected(() -> executor.validate(new PkiOperation.UnholdCredential(credential, Optional.empty()), CancellationSignal.NONE));
            rejected(() -> executor.validate(new PkiOperation.RevokePendingCredentialConfirmation(credential, Optional.empty()), CancellationSignal.NONE));
            var initial = store.initializeCredentialConfirmation(new CredentialConfirmationInitialization(credential,
                    ConfirmationDisclosurePolicy.AUTHENTICATED, "1".repeat(64), true, IntermediateCreationFixture.NOW.minusSeconds(1),
                    new ConfirmationProofSuiteRef("holder-proof.v1", "2".repeat(64))));
            executor.validate(new PkiOperation.RevokePendingCredentialConfirmation(credential, Optional.empty()), CancellationSignal.NONE);
            check(store.getCredentialConfirmation(credential).orElseThrow().equals(initial) && store.getRevocation(credential).isEmpty(),
                    "Pending revocation validation mutated lifecycle");
            executor.validate(new PkiOperation.HoldCredential(credential, Optional.empty()), CancellationSignal.NONE);
            check(store.getRevocation(credential).isEmpty(), "Hold validation wrote transition");
            var held = store.transitionRevocation(new RevocationCommand.Hold(credential, new SimpleAttributeSet()), IntermediateCreationFixture.NOW);
            executor.validate(new PkiOperation.UnholdCredential(credential, Optional.empty()), CancellationSignal.NONE);
            executor.validate(new PkiOperation.RevokeCredential(credential, RevocationReason.KEY_COMPROMISE, Optional.empty()), CancellationSignal.NONE);
            check(store.getRevocation(credential).orElseThrow().transition().revision() == held.transition().revision(), "Unhold/revoke validation wrote transition");
            store.transitionRevocation(new RevocationCommand.RevokePermanently(credential, RevocationReason.KEY_COMPROMISE, new SimpleAttributeSet()), IntermediateCreationFixture.NOW);
            rejected(() -> executor.validate(new PkiOperation.HoldCredential(credential, Optional.empty()), CancellationSignal.NONE));
            rejected(() -> executor.validate(new PkiOperation.TransitionAuthority(ca.caId(), CaState.ACTIVE, "check"), () -> true));
            var provider = (zeroecho.pki.spi.crypto.SigningProvider) Proxy.newProxyInstance(
                    zeroecho.pki.spi.crypto.SigningProvider.class.getClassLoader(),
                    new Class<?>[]{zeroecho.pki.spi.crypto.SigningProvider.class, zeroecho.pki.spi.crypto.PublicKeyInfoSource.class},
                    (proxy, method, values) -> {
                        if (method.getName().equals("resolvePublicKeyInfo")) {
                            if (values[0].equals(IntermediateCreationFixture.PARENT_KEY)) return new EncodedObject(Encoding.DER, fixture.parentKey.getPublic().getEncoded());
                            if (values[0].equals(IntermediateCreationFixture.CHILD_KEY)) return new EncodedObject(Encoding.DER, fixture.childKey.getPublic().getEncoded());
                            throw new IllegalArgumentException("Unknown key");
                        }
                        try { return method.invoke(fixture.provider, values); } catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            var ocsp = new DefaultOcspResponseService(pureStore, unreachable(SigningService.class), provider,
                    PkiTestRuntime.signingAuthority(provider), () -> { });
            ocsp.validateSigningMetadata(ca.caId(), credential, IntermediateCreationFixture.PARENT_KEY, IntermediateCreationFixture.ALGORITHM, Optional.empty(), CancellationSignal.NONE);
            rejected(() -> ocsp.validateSigningMetadata(ca.caId(), credential, IntermediateCreationFixture.CHILD_KEY, IntermediateCreationFixture.ALGORITHM, Optional.empty(), CancellationSignal.NONE));
            rejected(() -> ocsp.validateSigningMetadata(ca.caId(), credential, new KeyRef("missing"), IntermediateCreationFixture.ALGORITHM, Optional.empty(), CancellationSignal.NONE));
            rejected(() -> ocsp.validateSigningMetadata(ca.caId(), credential, IntermediateCreationFixture.PARENT_KEY, IntermediateCreationFixture.ALGORITHM, Optional.of("missing"), CancellationSignal.NONE));
            check(fixture.provider.dispatches == 0, "OCSP metadata validation signed a challenge");
        }
        System.out.println("PASS pure profile/CA/path/revoke/hold/unhold/pending revocation and OCSP metadata; missing/state-conflict inputs rejected; no mutation/audit/signature");
    }
    public static void main(String[] args) throws Exception { exercise(Files.createTempDirectory("zeroecho-pure-operations-")); }
}
