/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms.AuditMode;
import zeroecho.core.audit.AuditListener;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.context.DigestContext;

/**
 * Verifies audited proxy wrapping for representative {@link CryptoContext}
 * contract types.
 *
 * <p>
 * These tests focus on the internal audit wrapping path used by
 * {@link CryptoAlgorithms#wrapForAudit(CryptoContext, zeroecho.core.audit.AuditListener, KeyUsage)}.
 * They verify that representative context types are wrapped as audited JDK
 * proxies and that the resulting wrapper preserves the expected basic
 * delegation behavior.
 * </p>
 */
class CryptoAlgorithmsAuditWrapTest {

    @AfterEach
    void restoreAuditConfiguration() {
        CryptoAlgorithms.setAuditListener(AuditListener.noop());
        CryptoAlgorithms.setAuditMode(AuditMode.OFF);
    }

    @Test
    void wrapForAuditDigestContextReturnsProxy() {
        System.out.println("wrapForAuditDigestContextReturnsProxy");

        DigestContext context = mock(DigestContext.class);
        DigestContext wrapped = CryptoAlgorithms.wrapForAudit(context, AuditListener.noop(), KeyUsage.DIGEST);

        System.out.println("...ctxClass=" + wrapped.getClass().getName());
        assertTrue(Proxy.isProxyClass(wrapped.getClass()), "Digest context should be wrapped as JDK proxy");

        System.out.println("wrapForAuditDigestContextReturnsProxy...ok");
    }

    @Test
    void wrapForAuditAgreementContextReturnsProxy() {
        System.out.println("wrapForAuditAgreementContextReturnsProxy");

        AgreementContext context = mock(AgreementContext.class);
        AgreementContext wrapped = CryptoAlgorithms.wrapForAudit(context, AuditListener.noop(), KeyUsage.AGREEMENT);

        System.out.println("...ctxClass=" + wrapped.getClass().getName());
        assertTrue(Proxy.isProxyClass(wrapped.getClass()), "Agreement context should be wrapped as JDK proxy");

        System.out.println("wrapForAuditAgreementContextReturnsProxy...ok");
    }

    @Test
    void wrapForAuditDigestContextCloseDelegatesToWrappedContext() throws Exception {
        System.out.println("wrapForAuditDigestContextCloseDelegatesToWrappedContext");

        DigestContext context = mock(DigestContext.class);
        DigestContext wrapped = CryptoAlgorithms.wrapForAudit(context, AuditListener.noop(), KeyUsage.DIGEST);

        wrapped.close();

        verify(context).close();
        System.out.println("...wrappedCloseDelegated=true");
        System.out.println("wrapForAuditDigestContextCloseDelegatesToWrappedContext...ok");
    }
}