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
package zeroecho.pki.spi.crypto;

import java.util.Objects;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.ConfigurableProvider;

/**
 * ServiceLoader provider for {@link SignatureWorkflow}.
 *
 * <p>Service loading discovers provider factories only. Runtime capabilities,
 * including keyring unlock providers, are supplied explicitly through
 * {@link #allocate(ProviderConfig, SignatureWorkflowRuntimeDependencies)} and
 * are never stored in textual provider configuration.</p>
 */
public interface SignatureWorkflowProvider extends ConfigurableProvider<SignatureWorkflow> {
    /**
     * Allocates a workflow using explicit process-local runtime dependencies.
     *
     * <p>The default implementation supports providers that need no additional
     * runtime capability. A provider requiring a software keyring must override
     * this method and reject an absent unlock provider before opening any
     * workflow resource.</p>
     *
     * @param config structural provider configuration
     * @param dependencies explicit process-local runtime dependencies
     * @return allocated workflow
     * @throws NullPointerException if {@code dependencies} is {@code null}
     * @throws RuntimeException if allocation fails
     */
    default SignatureWorkflow allocate(ProviderConfig config,
            SignatureWorkflowRuntimeDependencies dependencies) {
        Objects.requireNonNull(dependencies, "dependencies must not be null");
        return allocate(config);
    }
}
