/*
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

package zeroecho.pki.spi.store;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.impl.core.IssuerBindingResolver;
import zeroecho.pki.testkit.RootCreationFixture;

/**
 * Contract and regression tests for issuer algorithm evidence verifier.
 */
class IssuerAlgorithmEvidenceVerifierTest {
    /**
     * Verifies only public evidence and rejects wrong identity or changed subject key.
     *
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void verifiesOnlyPublicEvidenceAndRejectsWrongIdentityOrChangedSubjectKey() throws Exception {
        var fixture = new RootCreationFixture();
        var spki = new EncodedObject(Encoding.DER, fixture.key.getPublic().getEncoded());
        var primary = IssuerBindingResolver.createKey(RootCreationFixture.KEY, fixture.verification.resolveIdentity(RootCreationFixture.ALGORITHM),
                spki.bytes(), fixture.provider, fixture.verification);
        int lookups = fixture.provider.lookups.get();
        IssuerAlgorithmEvidenceVerifier configured = IssuerBindingResolver.publicEvidenceVerifier(fixture.verification);
        configured.verify(primary, spki);
        IssuerBindingResolver.defaultPublicEvidenceVerifier().verify(primary, spki);
        assertThrows(IllegalStateException.class, () -> configured.verify(primary, new EncodedObject(Encoding.DER, fixture.otherKey.getPublic().getEncoded())));
        var wrong = new IssuerKeyBinding(primary.keyRef(), zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                primary.signatureAlgorithm(), primary.signatureAlgorithmIdentifier(), primary.subjectSpkiSha256());
        assertThrows(IllegalStateException.class, () -> configured.verify(wrong, spki));
        assertEquals(lookups, fixture.provider.lookups.get(), "Public history validation has no managed-key resolver");
    }
    /**
     * Store dependency keeps clock and captured verifier while legacy construction remains available.
     */
    @Test void storeDependencyKeepsClockAndCapturedVerifierWhileLegacyConstructionRemainsAvailable() {
        var clock = java.time.Clock.fixed(java.time.Instant.EPOCH, java.time.ZoneOffset.UTC);
        IssuerAlgorithmEvidenceVerifier verifier = IssuerBindingResolver.defaultPublicEvidenceVerifier();
        var configured = new PkiStoreRuntimeDependencies(clock, verifier);
        assertSame(clock, configured.clock()); assertSame(verifier, configured.issuerAlgorithmEvidenceVerifier().orElseThrow());
        assertTrue(new PkiStoreRuntimeDependencies(clock).issuerAlgorithmEvidenceVerifier().isEmpty());
        assertNotNull(PkiStoreRuntimeDependencies.systemUtc().clock());
        assertThrows(NullPointerException.class, () -> new PkiStoreRuntimeDependencies(clock, null));
    }
}
