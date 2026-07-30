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
package zeroecho.pki.spi.async;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.spi.ConfigurableProvider;
import zeroecho.pki.util.async.AsyncBus;

/**
 * ServiceLoader provider for the PKI asynchronous operation bus.
 *
 * <p>
 * The underlying bus implementation is generic and reusable (see
 * {@code zeroecho.pki.util.async}). This SPI publishes a PKI-specific type
 * binding to ensure provider implementations remain strictly typed and do not
 * require unsafe casts.
 * </p>
 *
 * <p>
 * Type parameters used by PKI:
 * </p>
 * <ul>
 * <li>Operation id: {@link PkiId}</li>
 * <li>Owner: {@link Principal}</li>
 * <li>Endpoint id: {@link String}</li>
 * <li>Result: {@link Object} (intentionally not persisted by the default
 * provider)</li>
 * </ul>
 *
 * <p>
 * Result type is {@code Object} because this layer does not prescribe how
 * results are stored. In the recommended architecture, results (certificates,
 * bundles, exports) are stored in PKI stores and the async bus carries only
 * status plus references, not payload.
 * </p>
 */
public interface AsyncBusProvider extends ConfigurableProvider<AsyncBus<PkiId, Principal, String, Object>> {
    // marker
}
