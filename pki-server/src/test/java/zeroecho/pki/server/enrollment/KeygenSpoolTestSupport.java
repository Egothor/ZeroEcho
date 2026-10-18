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

package zeroecho.pki.server.enrollment;

import java.io.IOException;
import static org.mockito.Mockito.when;

/** Package-local custody bridge for server-level coordinator persistence fixtures. */
public final class KeygenSpoolTestSupport {
    private KeygenSpoolTestSupport() { }
    /**
     * Installs real ciphertext ownership behind a mocked credential runtime.
     * @param runtime existing mocked runtime
     * @param configuration explicit artifact limits and directory
     * @return owned spool to close with the fixture
     * @throws IOException if exclusive storage cannot be opened
     */
    public static AutoCloseable install(EnrollmentRuntime runtime, EnrollmentRuntimeConfiguration configuration) throws IOException {
        EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration.keygenArtifacts().orElseThrow(),
                configuration.budgets().maximumConcurrentDispatches());
        when(runtime.keygenSpool()).thenReturn(spool);
        return spool;
    }

    /** @param value workflow state to persist in corruption/recovery fixtures
     * @return canonical control record */
    public static zeroecho.pki.server.ServerControlStore.ProtocolRecord record(EnrollmentTransaction value) {
        return EnrollmentTransactionCodec.record(value);
    }

    /** @param value descriptor to persist in corruption/recovery fixtures
     * @return canonical control record */
    public static zeroecho.pki.server.ServerControlStore.ProtocolRecord record(EnrollmentKeygenArtifact value) {
        return EnrollmentKeygenCodec.record(value);
    }
}
