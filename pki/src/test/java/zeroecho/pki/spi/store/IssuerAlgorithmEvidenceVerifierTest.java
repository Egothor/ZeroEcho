package zeroecho.pki.spi.store;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.impl.core.IssuerBindingResolver;
import zeroecho.pki.testkit.RootCreationFixture;

class IssuerAlgorithmEvidenceVerifierTest {
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
