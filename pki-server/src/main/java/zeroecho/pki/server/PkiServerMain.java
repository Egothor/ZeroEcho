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

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;

import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;

/** Production command-line entry point for the administrative HTTPS server. */
@SuppressWarnings("PMD")
public final class PkiServerMain {
    private static final String HELP = """
            Usage: zeroecho-pki-server --config <server-config.json>
                   zeroecho-pki-server --validate-config --config <server-config.json>
                   zeroecho-pki-server --help
                   zeroecho-pki-server --version
            """;

    private PkiServerMain() {
    }

    /**
     * Runs configuration validation or starts the long-lived server process.
     *
     * @param arguments exact process arguments
     */
    public static void main(String[] arguments) {
        int result = run(arguments);
        if (result != 0) System.exit(result);
    }

    static int run(String[] arguments) {
        try {
            if (arguments.length == 1 && "--help".equals(arguments[0])) {
                System.out.print(HELP);
                return 0;
            }
            if (arguments.length == 1 && "--version".equals(arguments[0])) {
                String version = Optional.ofNullable(PkiServerMain.class.getPackage().getImplementationVersion())
                        .orElse("development");
                System.out.println("zeroecho-pki-server " + version);
                return 0;
            }
            boolean validate = Arrays.asList(arguments).contains("--validate-config");
            Path path = configurationPath(arguments, validate);
            PkiServerConfiguration configuration = PkiServerConfigurationCodec.read(path);
            if (validate) {
                System.out.println("configuration valid");
                return 0;
            }
            PkiSessionRuntimeDependencies dependencies = runtimeDependencies(configuration);
            PkiHttpsServer server = PkiHttpsServer.start(configuration, dependencies);
            server.installShutdownHook();
            new CountDownLatch(1).await();
            return 0;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return 0;
        } catch (IOException | IllegalArgumentException failure) {
            System.err.println("Server configuration is invalid");
            return 2;
        } catch (RuntimeException failure) {
            System.err.println("Server startup failed");
            return 3;
        }
    }

    private static Path configurationPath(String[] arguments, boolean validate) {
        int expected = validate ? 3 : 2;
        if (arguments.length != expected) throw new IllegalArgumentException("Invalid invocation");
        int configIndex = validate && "--validate-config".equals(arguments[0]) ? 1 : 0;
        if (!"--config".equals(arguments[configIndex])) throw new IllegalArgumentException("Invalid invocation");
        if (validate && !"--validate-config".equals(arguments[2])) {
            if (!"--validate-config".equals(arguments[0])) throw new IllegalArgumentException("Invalid invocation");
        }
        return Path.of(arguments[configIndex + 1]);
    }

    private static PkiSessionRuntimeDependencies runtimeDependencies(PkiServerConfiguration configuration) {
        Optional<String> environment = configuration.runtime().keyUnlockEnvironmentVariable();
        if (environment.isEmpty()) return PkiSessionRuntimeDependencies.none();
        KeyringUnlockProvider provider = () -> {
            String value = System.getenv(environment.orElseThrow());
            if (value == null || value.isEmpty()) throw new IOException("Configured unlock source is unavailable");
            char[] secret = value.toCharArray();
            try {
                return new KeyringPassword(secret);
            } finally {
                Arrays.fill(secret, '\0');
            }
        };
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(provider);
    }
}
