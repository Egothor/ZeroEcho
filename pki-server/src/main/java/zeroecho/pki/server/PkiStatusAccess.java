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

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Explicit offline provisioning of status-content access for the original administrator pair.
 *
 * <p>Run only with the backend stopped. The original mapped, enabled USER and complete initial
 * direct-grant baseline must remain intact. Only the dedicated status full-content grant per initial user
 * may be created; policy commitments, root own-approval authority and PKI data are unchanged.</p>
 */
public final class PkiStatusAccess {
    private static final String HELP = "Usage: zeroecho-pki-status-access --config PATH --admin-id ID --approver-id ID --proxy-id ID\n";
    private PkiStatusAccess() { }

    /**
     * Provisions the known initial pair under an explicit local operator invocation.
     *
     * @param arguments server configuration and exact three original mapped principal identifiers
     */
    public static void main(String[] arguments) {
        int code = run(arguments);
        if (code != 0) System.exit(code);
    }

    static int run(String[] arguments) {
        if (arguments.length == 1 && "--help".equals(arguments[0])) { System.out.print(HELP); return 0; }
        try {
            Map<String, String> options = options(arguments);
            PkiAdminBootstrap.provisionStatusAccess(PkiServerConfigurationCodec.read(Path.of(options.get("--config"))),
                    options.get("--admin-id"), options.get("--approver-id"), options.get("--proxy-id"));
            System.out.println("STATUS_ACCESS_READY");
            return 0;
        } catch (IllegalArgumentException | IOException failure) {
            System.err.println("Status access provisioning refused: " + failure.getMessage());
            return 2;
        } catch (RuntimeException failure) {
            System.err.println("Status access provisioning completion is unconfirmed; retain state and inspect before retrying.");
            return 3;
        }
    }

    private static Map<String, String> options(String[] arguments) {
        Set<String> names = Set.of("--config", "--admin-id", "--approver-id", "--proxy-id");
        if (arguments.length != names.size() * 2) throw new IllegalArgumentException(HELP.strip());
        Map<String, String> result = new HashMap<>();
        for (int index = 0; index < arguments.length; index += 2) {
            if (!names.contains(arguments[index]) || result.putIfAbsent(arguments[index], arguments[index + 1]) != null) {
                throw new IllegalArgumentException("Unknown or repeated option");
            }
        }
        return result;
    }
}
