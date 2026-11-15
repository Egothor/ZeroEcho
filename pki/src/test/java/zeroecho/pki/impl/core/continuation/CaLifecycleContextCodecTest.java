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
package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.spi.store.DomainContinuationStore;

class CaLifecycleContextCodecTest {
    @Test void canonicalCaptureCommitsEpochAndCandidateIdentityWithoutCurrentState() {
        var context = context(1);
        String encoded = CaLifecycleContextCodec.encode(context);
        assertEquals(context, CaLifecycleContextCodec.decode(encoded));
        assertEquals(encoded, CaLifecycleContextCodec.encode(CaLifecycleContextCodec.decode(encoded)));
        assertNotEquals(CaLifecycleContextCodec.commitment(context), CaLifecycleContextCodec.commitment(context(2)));
        var candidate = new CaLifecycleContext(1, CaLifecycleContext.Operation.ROOT_CANDIDATE,
                context.expectedHead(), context.originalCredentialId(), context.originalCertificateSha256(),
                Optional.of(new PkiId("transition")));
        assertEquals(candidate, CaLifecycleContextCodec.decode(CaLifecycleContextCodec.encode(candidate)));
        assertNotEquals(CaLifecycleContextCodec.commitment(context), CaLifecycleContextCodec.commitment(candidate));
    }

    @Test void rejectsPaddingNoncanonicalEpochAndUnknownSchema() {
        assertThrows(IllegalArgumentException.class,
                () -> CaLifecycleContextCodec.decode(CaLifecycleContextCodec.encode(context(1)) + "="));
        assertThrows(IllegalArgumentException.class, () -> CaLifecycleContextCodec.decode("a".repeat(131_073)));
        byte[] encoded = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, "CA_LIFECYCLE_CONTEXT_V1",
                "ROOT_ROLLOVER", "ca", "01", "issuer", "path", "0".repeat(64), "credential", "1".repeat(64), "").command().bytes();
        assertThrows(IllegalArgumentException.class,
                () -> CaLifecycleContextCodec.decode(Base64.getUrlEncoder().withoutPadding().encodeToString(encoded)));
        byte[] unknown = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, "CA_LIFECYCLE_CONTEXT_V2",
                "ROOT_ROLLOVER", "ca", "1", "issuer", "path", "0".repeat(64), "credential", "1".repeat(64), "").command().bytes();
        assertThrows(IllegalArgumentException.class,
                () -> CaLifecycleContextCodec.decode(Base64.getUrlEncoder().withoutPadding().encodeToString(unknown)));
        assertThrows(IllegalArgumentException.class, () -> new CaLifecycleContext(1, CaLifecycleContext.Operation.ROOT_CANDIDATE,
                context(1).expectedHead(), new PkiId("credential"), "1".repeat(64), Optional.empty()));
    }

    private static CaLifecycleContext context(long epoch) {
        return new CaLifecycleContext(1, CaLifecycleContext.Operation.ROOT_ROLLOVER,
                new CaHeadSnapshot(1, new PkiId("ca"), epoch, new PkiId("issuer"), new PkiId("path"), "0".repeat(64)),
                new PkiId("credential"), "1".repeat(64), Optional.empty());
    }
}
