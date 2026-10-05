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

package zeroecho.pki.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.application.LocalPkiSessionConfiguration;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;

/**
 * Deployment-only profile initializer executed before the permanent server starts.
 * Profiles whose active content matches the incoming document are skipped; profiles
 * with changed or absent content are registered and activated at the version declared
 * in their document. The local session exclusively owns the configured store until
 * initialization finishes.
 */
public final class PkiProfileBootstrap {
    private PkiProfileBootstrap() { }

    /**
     * Imports configured profile documents and exits with a PKI CLI status code.
     * @param arguments ordered {@code --config FILE --profiles-dir DIRECTORY --store-dir DIRECTORY}
     */
    public static void main(String[] arguments) {
        System.exit(execute(arguments, System.err));
    }

    /* default */ // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
                  // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
                  // Input rejection is classified after resource close, preserving close-failure precedence.
                  // Standalone execution checks or restores interruption; it neither creates threads nor runs in a J2EE container.
                  @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops", "PMD.DoNotUseThreads", "PMD.PreserveStackTrace", "PMD.ExceptionAsFlowControl" })
                  static int execute(String[] arguments, PrintStream diagnostics) {
        if (arguments.length != 6 || !"--config".equals(arguments[0])
                || !"--profiles-dir".equals(arguments[2]) || !"--store-dir".equals(arguments[4])) {
            diagnostics.println("Profile bootstrap requires --config FILE --profiles-dir DIRECTORY --store-dir DIRECTORY");
            return PkiExitCodes.INVALID_INVOCATION;
        }
        LocalPkiSessionConfiguration configuration;
        List<Path> profiles = new ArrayList<>();
        try {
            // Kubernetes ConfigMap projections are symlinks. Resolve the projection, then
            // retain the CLI's bounded, no-follow regular-file read of that exact target.
            configuration = PkiCliConfiguration.read(Path.of(arguments[1]).toRealPath());
            requireBootstrapConfiguration(configuration, arguments[5]);
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(Path.of(arguments[3]), "*.json")) {
                for (Path entry : entries) {
                    profiles.add(entry);
                }
            }
            profiles.sort(Comparator.comparing(path -> path.getFileName().toString()));
        } catch (IOException | RuntimeException failure) {
            diagnostics.println("Profile bootstrap configuration or input directory is invalid");
            return PkiExitCodes.CONFIGURATION_FAILURE;
        }
        try (PkiSession session = PkiSession.openLocal(configuration, PkiSessionRuntimeDependencies.none())) {
            int registered = 0;
            int skipped = 0;
            for (Path profile : profiles) {
                byte[] document = PkiCliFiles.readRegularFile(profile.toRealPath(),
                        CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES);
                CertificateProfileDefinition definition;
                try {
                    definition = CertificateProfileDocumentCodec.parse(document);
                } catch (PkiException invalid) {
                    throw new IllegalArgumentException("Invalid profile document");
                }
                byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
                String incomingShaHex = bootstrapSha256Hex(canonical);
                PkiOperationResult listResult = execute(session, new PkiOperation.ListProfileVersions(definition.profileId()));
                PkiOperationValue activeVersionValue = listResult.fields().get("activeVersion");
                if (activeVersionValue instanceof PkiOperationValue.IntegerValue activeVersionInt) {
                    PkiOperationResult inspectResult = execute(session,
                            new PkiOperation.InspectProfile(definition.profileId(), activeVersionInt.value()));
                    String activeShaHex = ((PkiOperationValue.Text) inspectResult.fields().get("canonicalSha256")).value();
                    if (incomingShaHex.equals(activeShaHex)) {
                        skipped++;
                        continue;
                    }
                }
                execute(session, new PkiOperation.RegisterProfile(document));
                execute(session, new PkiOperation.ActivateProfile(definition.profileId(), definition.profileVersion()));
                registered++;
            }
            diagnostics.printf("Profile bootstrap completed: registered=%d skipped=%d%n", registered, skipped);
        } catch (IOException | IllegalArgumentException failure) {
            diagnostics.println("Profile bootstrap input is invalid; earlier profiles may already be registered");
            return PkiExitCodes.VALIDATION_OR_POLICY;
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            diagnostics.println("Profile bootstrap interrupted; inspect persisted profiles before restarting");
            return PkiExitCodes.CANCELLED;
        } catch (Exception failure) {
            // Provider exceptions and profile contents are deliberately excluded from diagnostics.
            diagnostics.println("Profile bootstrap failed; inspect persisted profiles before restarting");
            return PkiExitCodes.RESOURCE_FAILURE;
        }
        return PkiExitCodes.SUCCESS;
    }

    private static PkiOperationResult execute(PkiSession session, PkiOperation operation) {
        PkiOperationOutcome outcome = session.operations().execute(operation, CancellationSignal.NONE);
        if (outcome instanceof PkiOperationOutcome.Completed completed) { return completed.result(); }
        throw new IllegalStateException("Profile bootstrap operation did not complete");
    }

    private static String bootstrapSha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void requireBootstrapConfiguration(LocalPkiSessionConfiguration configuration, String storeDirectory) {
        if (!"fs".equals(configuration.store().backendId()) || configuration.signing().isPresent()
                || !configuration.publishers().isEmpty()
                || !Path.of(configuration.store().require("root")).toAbsolutePath().normalize()
                        .equals(Path.of(storeDirectory).toAbsolutePath().normalize())) {
            throw new IllegalArgumentException("Invalid bootstrap configuration");
        }
    }
}
