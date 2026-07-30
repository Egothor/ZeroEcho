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
package zeroecho.core.audit;

import java.lang.reflect.Proxy;
import java.util.Objects;

/**
 * Utilities for enforcing the best-effort audit-listener contract.
 *
 * <p>
 * The returned listener suppresses listener failures without logging callback
 * arguments, because those arguments may refer to sensitive cryptographic
 * objects. Cryptographic operation outcomes therefore never depend on an audit
 * sink's availability.
 * </p>
 *
 * @since 1.0
 */
public final class AuditListeners {
    private AuditListeners() {
        // utility class
    }

    /**
     * Returns a listener facade that cannot interrupt the caller.
     *
     * @param listener listener to protect
     * @return non-throwing listener facade
     * @throws NullPointerException if {@code listener} is {@code null}
     */
    public static AuditListener bestEffort(AuditListener listener) {
        AuditListener target = Objects.requireNonNull(listener, "listener");
        ClassLoader contextLoader = Thread.currentThread().getContextClassLoader();
        ClassLoader loader = contextLoader == null ? ClassLoader.getSystemClassLoader() : contextLoader;
        return (AuditListener) Proxy.newProxyInstance(loader, new Class<?>[] { AuditListener.class },
                (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return method.invoke(target, arguments);
                    }
                    try {
                        return method.invoke(target, arguments);
                    } catch (ReflectiveOperationException ignored) {
                        return null;
                    }
                });
    }
}
