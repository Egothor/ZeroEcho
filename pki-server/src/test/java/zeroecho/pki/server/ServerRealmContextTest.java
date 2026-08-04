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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.spi.ProviderConfig;

/** Realm composition, one-session lifecycle and exposure-policy tests. */
class ServerRealmContextTest {
    @TempDir Path temporaryDirectory;

    @Test
    void opensOneLongLivedSessionClosesAndRecoversControlState() throws Exception {
        System.out.println("opensOneLongLivedSessionClosesAndRecoversControlState");
        ServerRealmConfiguration configuration = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        try (ServerRealmContext context = ServerRealmContext.open(configuration,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertSame(context.session(), context.session());
            PkiOperationOutcome first = context.session().operations().execute(new PkiOperation.ValidateConfiguration(),
                    zeroecho.core.io.CancellationSignal.NONE);
            PkiOperationOutcome second = context.session().operations().execute(new PkiOperation.ValidateConfiguration(),
                    zeroecho.core.io.CancellationSignal.NONE);
            assertEquals(PkiOperationOutcome.Success.class, first.getClass());
            assertEquals(PkiOperationOutcome.Success.class, second.getClass());
            context.createPrincipal(ServerTestSupport.principal("auditor"), "bootstrap");
            assertEquals(ServerRealmContext.State.OPEN, context.state());
            System.out.println("...session-reused=true");
        }
        try (ServerRealmContext reopened = ServerRealmContext.open(configuration,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertThrows(IllegalStateException.class,
                    () -> reopened.createPrincipal(ServerTestSupport.principal("auditor"), "bootstrap"));
            assertEquals(ServerRealmContext.State.OPEN, reopened.state());
            System.out.println("...control-recovered=true");
        }
        System.out.println("...ok");
    }

    @Test
    void supportsExplicitOneAuthorityAndRejectsOtherAuthority() {
        System.out.println("supportsExplicitOneAuthorityAndRejectsOtherAuthority");
        AuthorityExposurePolicy exposure = new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.EXPLICIT_AUTHORITIES, Set.of(ServerTestSupport.AUTHORITY), false);
        assertEquals(true, exposure.allows(ServerTestSupport.AUTHORITY));
        assertEquals(false, exposure.allows(new PkiId("ca-b")));
        assertThrows(IllegalArgumentException.class, () -> new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.EXPLICIT_AUTHORITIES, Set.of(), false));
        System.out.println("...visible-authorities=" + exposure.authorityIds().size());
        System.out.println("...ok");
    }

    @Test
    void rejectsChangedRealmCommitmentOnReopen() throws Exception {
        System.out.println("rejectsChangedRealmCommitmentOnReopen");
        ServerRealmConfiguration original = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        try (ServerRealmContext ignored = ServerRealmContext.open(original, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, deterministicRandom())) {
            System.out.println("...initial-open=true");
        }
        String changed = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        ServerRealmConfiguration incompatible = new ServerRealmConfiguration(original.realmId(),
                original.displayName(), original.pkiSessionConfiguration(), original.authorityExposure(), changed,
                original.approvalCommitment(), original.disclosureCommitment(), original.disclosureDefaults(),
                original.controlLogPath(), original.controlStoreId(), original.approvalPolicies());
        assertThrows(IllegalStateException.class, () -> ServerRealmContext.open(incompatible,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom()));
        System.out.println("...changed-commitment=rejected");
        System.out.println("...ok");
    }

    private ServerRealmConfiguration configuration(AuthorityExposurePolicy exposure) {
        ApprovalService.Policy approval = new ApprovalService.Policy("high-risk", 1, Set.of("approver"),
                Set.of(), true, Duration.ofHours(1), true);
        PkiSessionConfiguration pki = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("pki-store").toString())),
                new ProviderConfig("memory", Map.of("size", "128")), Optional.empty(), List.of(), List.of());
        return new ServerRealmConfiguration(ServerTestSupport.REALM, "Production", pki, exposure,
                ServerTestSupport.DIGEST, approval.commitment(), ServerTestSupport.DIGEST,
                DisclosureService.Defaults.recommended(), temporaryDirectory.resolve("control.log"),
                ServerTestSupport.STORE_ID,
                Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval));
    }

    private static SecureRandom deterministicRandom() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 });
        return random;
    }
}
