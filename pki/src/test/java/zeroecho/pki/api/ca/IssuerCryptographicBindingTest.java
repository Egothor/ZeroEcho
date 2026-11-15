package zeroecho.pki.api.ca;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.*;
import zeroecho.pki.api.profile.CertificateProfileRef;

class IssuerCryptographicBindingTest {
    @Test void strictRoundTripCommitsCompletePublicEvidenceAndPreservesValueEquality() {
        var binding = binding();
        byte[] encoded = IssuerCryptographicBindingCodec.encode(binding);
        assertEquals(binding, IssuerCryptographicBindingCodec.decode(encoded));
        assertEquals(binding.commitment(), IssuerCryptographicBindingCodec.decode(encoded).commitment());
        var changed = new IssuerKeyBinding(new KeyRef("provider:other.priv"), binding.primary().publicKeyAlgorithm(),
                binding.primary().signatureAlgorithm(), binding.primary().signatureAlgorithmIdentifier(), "1".repeat(64));
        var different = new IssuerCryptographicBinding(1, binding.issuerId(), binding.authorityId(), binding.credentialId(), "X.509", changed,
                Optional.empty(), "2".repeat(64), binding.profile(), "3".repeat(64), binding.certificateHybridBaseline(), "4".repeat(64));
        assertNotEquals(binding.commitment(), different.commitment());
    }
    @Test void rejectsUnknownVersionFlagsTruncationTrailingBytesAndMalformedUtf8() {
        byte[] encoded = IssuerCryptographicBindingCodec.encode(binding());
        for (int offset : new int[] {0, 5, 7}) {
            byte[] bad = encoded.clone(); bad[offset] ^= 1;
            assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(Arrays.copyOf(encoded, encoded.length - 1)));
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(Arrays.copyOf(encoded, encoded.length + 1)));
        byte[] bad = encoded.clone(); bad[12] = (byte)0xff;
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(bad));
    }
    @Test void rejectsUnpairedHybridEvidence() {
        var value = binding();
        assertThrows(IllegalArgumentException.class, () -> new IssuerCryptographicBinding(1, value.issuerId(), value.authorityId(), value.credentialId(), "X.509",
                value.primary(), Optional.empty(), "2".repeat(64), value.profile(), "3".repeat(64),
                IssuerCryptographicBinding.HybridSignatureBaseline.LEGACY_PRE_TBS, "4".repeat(64)));
    }
    private static IssuerCryptographicBinding binding() {
        PkiId ca = new PkiId("ca:test"), cert = new PkiId("cert:test");
        var key = new IssuerKeyBinding(new KeyRef("provider:test.priv"), BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.ECDSA_SHA384, new EncodedObject(Encoding.DER, java.util.HexFormat.of().parseHex("300a06082a8648ce3d040303")), "1".repeat(64));
        return new IssuerCryptographicBinding(1, IssuerGeneration.idFor(ca, cert), ca, cert, "X.509", key, Optional.empty(), "2".repeat(64),
                new CertificateProfileRef("test-ca", 1, new byte[32]), "3".repeat(64), IssuerCryptographicBinding.HybridSignatureBaseline.NONE,
                "4".repeat(64));
    }
}
