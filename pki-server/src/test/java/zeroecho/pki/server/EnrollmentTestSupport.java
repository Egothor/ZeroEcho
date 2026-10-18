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
package zeroecho.pki.server;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;

/** Real durable policy/endpoint fixture shared by protocol service tests. */
public final class EnrollmentTestSupport implements AutoCloseable {
    /** Returns explicit small transaction budgets for tests without protocol credentials. */
    public static zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration runtimeConfiguration() {
        return zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.decode(runtimeJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Returns the strict companion used by in-process and packaged ACME tests. */
    public static String runtimeJson() {
        return """
                {"version":1,"budgets":{"maximumTransactions":1000,"maximumPending":100,
                "maximumRetainedRequestBytes":10485760,"maximumRequestBytes":1048576,
                "maximumConcurrentDispatches":1,"pendingLifetimeSeconds":600,"retryAfterSeconds":5},
                "keyrings":[],"credentialSets":[],"activeCredentials":[]}
                """;
    }
    private final ServerTestSupport.OpenedStore opened;
    private final EnrollmentEndpointRegistry endpoints;
    private final ServerRealmContext realm;

    /** Creates a dedicated registry containing explicit fixture policy bindings. */
    public EnrollmentTestSupport(Path directory, List<String> certificateProfiles) throws IOException {
        opened = ServerTestSupport.open(directory);
        EnrollmentProfileService profiles = new EnrollmentProfileService(opened.store());
        for (String certificate : certificateProfiles) {
            profiles.register(new EnrollmentProfile("enrollment-" + certificate, "Test policy",
                    EnrollmentProfileState.ACTIVE, certificate, Set.of(), Optional.empty(), List.of(), false));
        }
        endpoints = new EnrollmentEndpointRegistry(opened.store(), profiles);
        realm = mock(ServerRealmContext.class);
        when(realm.enrollmentEndpoints()).thenReturn(endpoints);
        when(realm.enrollmentProfiles()).thenReturn(profiles);
    }

    /** Returns the realm facade backed by the actual durable registry. */
    public ServerRealmContext realm() { return realm; }

    /** Returns the durable endpoint registry. */
    public EnrollmentEndpointRegistry endpoints() { return endpoints; }

    /** Closes the fixture's durable authority. */
    @Override
    public void close() throws IOException { opened.close(); }
}
