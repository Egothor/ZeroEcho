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
package demo;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.LocalPkiSessionConfiguration;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Demonstrates session bootstrap and the non-signing operation catalog.
 *
 * <p>Signing operations — root CA creation, intermediate creation, certificate issuance,
 * CRL and OCSP generation — are excluded here because they require a {@code zeroecho-lib}
 * signing provider backed by a keyring that already contains the CA signing keys. See the
 * {@code LocalPkiSessionConfiguration} and {@code LocalSigningConfiguration} types for the
 * full signing path, and the CLI documentation for how to generate and store keys before
 * bootstrapping the PKI.
 *
 * <p>Run with: {@code ./gradlew :samples:test -PrunSamples}
 */
@Tag("sample")
class PkiDemoTest {

    private static final Logger LOG = Logger.getLogger(PkiDemoTest.class.getName());

    /**
     * Shows how to assemble a {@code LocalPkiSessionConfiguration} and open a
     * read-only session backed by the filesystem store.
     *
     * <p>The filesystem store creates and versions its own directory layout the first
     * time it opens. An in-memory audit sink is used here so the sample leaves no
     * files outside the temporary store directory.
     *
     * <p>To add signing capability, supply a {@code LocalSigningConfiguration} with
     * {@code backendId = "zeroecho-lib"}, a canonical algorithm identity, and an
     * environment variable that unlocks the pre-populated signing keyring. Then call
     * {@code session.localSigning()} to obtain the sequential caller-thread executor.
     */
    @Test
    void sessionBootstrapAndConfigurationValidation(@TempDir Path storeRoot) throws Exception {
        // The filesystem store needs only a root directory. It is self-versioning:
        // on first open it writes its store-format header; on subsequent opens it
        // validates that header before handing back any data.
        ProviderConfig store = new ProviderConfig("fs", Map.of("root", storeRoot.toString()));

        // An in-memory audit sink is sufficient for development and samples; a
        // production deployment would use the "file" or "syslog" audit backend.
        ProviderConfig audit = new ProviderConfig("memory", Map.of());

        // The operatorId is stamped on every audit event produced by this local session.
        // In production it identifies the human or service account that opened the CLI.
        LocalPkiSessionConfiguration config = new LocalPkiSessionConfiguration(
                store,
                audit,
                "demo-operator",
                Optional.empty(),  // no signing; pass a LocalSigningConfiguration here to enable
                List.of(),         // no publication destinations
                List.of()          // no custom X.509 binding providers
        );

        // openLocal executes every signing operation on the caller thread. It never
        // builds a reactor or background threads, making it safe for CLI and batch use.
        try (PkiSession session = PkiSession.openLocal(config, PkiSessionRuntimeDependencies.none())) {

            // ValidateConfiguration is the cheapest way to confirm that all configured
            // providers are reachable and that the store format is current.
            PkiOperationOutcome outcome = session.operations()
                    .execute(new PkiOperation.ValidateConfiguration(), CancellationSignal.NONE);

            PkiOperationResult result = assertCompleted(outcome);
            LOG.log(Level.INFO, "Configuration valid: store={0} audit={1}",
                    new Object[] {
                        field(result, "storeProvider"),
                        field(result, "auditProvider")
                    });
        }
    }

    /**
     * Shows the three most common read-only listing operations: listing authorities,
     * profiles, and the built-in X.509 algorithm-binding registry.
     *
     * <p>Listings are keyset-paginated. When {@code truncated} is {@code true} in the
     * result, pass the returned {@code nextCursor} as {@code after} to fetch the next
     * page. Pages are bounded by the supplied {@code limit} (max 1000).
     *
     * <p>This sample opens an empty store so every list returns zero entries, but the
     * algorithm-binding registry is always populated from the built-in standard bindings.
     */
    @Test
    void listingOperations(@TempDir Path storeRoot) throws Exception {
        LocalPkiSessionConfiguration config = new LocalPkiSessionConfiguration(
                new ProviderConfig("fs", Map.of("root", storeRoot.toString())),
                new ProviderConfig("memory", Map.of()),
                "demo-operator",
                Optional.empty(),
                List.of(),
                List.of()
        );

        try (PkiSession session = PkiSession.openLocal(config, PkiSessionRuntimeDependencies.none())) {

            // List all certificate authorities in the store. An empty store returns
            // count=0 and truncated=false. After CA creation the same call surfaces
            // one row per authority with its caId, kind, state, and current issuerId.
            PkiOperationResult authorities = assertCompleted(session.operations()
                    .execute(new PkiOperation.ListAuthorities(100, Optional.empty()),
                            CancellationSignal.NONE));
            LOG.log(Level.INFO, "Authorities: count={0} truncated={1}",
                    new Object[] { field(authorities, "count"), field(authorities, "truncated") });

            // List imported certificate profiles. Profiles define the subject policy,
            // key usage, and validity rules for a class of certificates. They must be
            // imported and activated before any CA or end-entity certificate can be issued.
            PkiOperationResult profiles = assertCompleted(session.operations()
                    .execute(new PkiOperation.ListProfiles(100, Optional.empty()),
                            CancellationSignal.NONE));
            LOG.log(Level.INFO, "Profiles: count={0}", field(profiles, "count"));

            // The algorithm-binding registry is always available, even in a read-only
            // session. It enumerates every X.509 algorithm binding known to this
            // installation, keyed by a stable bindingId. Standard NIST-approved bindings
            // are pre-populated; deployer-defined private-OID bindings appear only if
            // explicitly activated through bindingProviders in the session configuration.
            PkiOperationResult bindings = assertCompleted(session.operations()
                    .execute(new PkiOperation.ListAlgorithmBindings(
                            Optional.empty(), Optional.empty(), 100, Optional.empty()),
                            CancellationSignal.NONE));
            LOG.log(Level.INFO, "Algorithm bindings: count={0} registryCommitment={1}",
                    new Object[] { field(bindings, "count"), field(bindings, "registryCommitment") });
        }
    }

    // -------------------------------------------------------------------------
    // helpers

    private static PkiOperationResult assertCompleted(PkiOperationOutcome outcome) {
        if (outcome instanceof PkiOperationOutcome.Failed f) {
            throw new AssertionError("Operation failed: " + f.operationName()
                    + " [" + f.classification() + "] " + f.code());
        }
        if (outcome instanceof PkiOperationOutcome.Completed c) {
            return c.result();
        }
        throw new AssertionError("Unexpected outcome type: " + outcome);
    }

    private static String field(PkiOperationResult result, String name) {
        return result.field(name).map(v -> switch (v) {
            case PkiOperationValue.Text t -> t.value();
            case PkiOperationValue.IntegerValue i -> String.valueOf(i.value());
            case PkiOperationValue.BooleanValue b -> String.valueOf(b.value());
            default -> v.toString();
        }).orElse("<absent>");
    }
}
