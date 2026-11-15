package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.*;
import zeroecho.pki.api.profile.CertificateProfileRef;

class IssuerBindingStorageCodecTest {
    @Test void compactStorageBindsImmutableContextGoldenVectorAndIgnoresOnlyLifecycle() throws Exception {
        var generation = generation("provider:test.priv", IssuerGenerationState.ACTIVE);
        var binding = binding(generation);
        byte[] encoded = IssuerBindingStorageCodec.encode(binding, generation);
        try (var in = new DataInputStream(new ByteArrayInputStream(encoded))) {
            assertEquals(0x5a494342, in.readInt()); assertEquals(1, in.readUnsignedShort()); assertEquals(1, in.readUnsignedShort());
            in.skipNBytes(in.readInt()); assertEquals(32, in.readInt());
            assertEquals("114f2259811cd5d1181c8e566a91b3668230c39965a486a80905cb74791d3ce3", HexFormat.of().formatHex(in.readNBytes(32)));
        }
        assertEquals(binding, IssuerBindingStorageCodec.decode(encoded, generation));
        assertEquals(binding, IssuerBindingStorageCodec.decode(encoded, generation("provider:test.priv", IssuerGenerationState.RETIRED)));
        assertThrows(IOException.class, () -> IssuerBindingStorageCodec.decode(encoded, generation("provider:changed.priv", IssuerGenerationState.ACTIVE)));
        var inconsistentRegistry = new IssuerCryptographicBinding(binding.version(), binding.issuerId(), binding.authorityId(), binding.credentialId(),
                binding.formatId(), binding.primary(), binding.alternative(), binding.certificateSha256(), binding.profile(), "f".repeat(64),
                binding.certificateHybridBaseline(), binding.evidenceSha256());
        assertThrows(IOException.class, () -> IssuerBindingStorageCodec.encode(inconsistentRegistry, generation));
        byte[] corrupt = encoded.clone(); corrupt[corrupt.length - 1] ^= 1;
        assertThrows(IOException.class, () -> IssuerBindingStorageCodec.decode(corrupt, generation));
    }
    @Test void avoidsDuplicatingSupportedMegabyteKeyReferencesWithinAtomicTransactionBudget() throws Exception {
        var generation = generation("k".repeat(1_048_576), IssuerGenerationState.ACTIVE);
        var binding = binding(generation);
        byte[] compact = IssuerBindingStorageCodec.encode(binding, generation);
        assertTrue(compact.length < 4096);
        assertTrue(FsCodec.encode(FsCodec.ISSUER_GENERATION, generation).length + compact.length < SigningWalFrameCodec.MAX_PAYLOAD_BYTES);
        assertEquals(binding.commitment(), IssuerBindingStorageCodec.decode(compact, generation).commitment());
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(compact));
    }
    @Test void fullDomainFormHasIndependentFourMiBBoundWithoutIncreasingCompactStorageBudget() throws Exception {
        var nearLegacy = generation("k".repeat(SigningWalFrameCodec.MAX_PAYLOAD_BYTES - 4096), IssuerGenerationState.ACTIVE);
        var nearBinding = binding(nearLegacy);
        assertTrue(FsCodec.encode(FsCodec.ISSUER_GENERATION, nearLegacy).length < SigningWalFrameCodec.MAX_PAYLOAD_BYTES);
        assertEquals(nearBinding, IssuerBindingStorageCodec.decode(IssuerBindingStorageCodec.encode(nearBinding, nearLegacy), nearLegacy));
        var domainOnly = binding(generation("k".repeat(SigningWalFrameCodec.MAX_PAYLOAD_BYTES + 1024), IssuerGenerationState.ACTIVE));
        byte[] full = IssuerCryptographicBindingCodec.encode(domainOnly);
        assertTrue(full.length > SigningWalFrameCodec.MAX_PAYLOAD_BYTES);
        assertEquals(domainOnly.commitment(), IssuerCryptographicBindingCodec.decode(full).commitment());
        assertThrows(IOException.class, () -> IssuerBindingStorageCodec.encode(domainOnly,
                generation("k".repeat(SigningWalFrameCodec.MAX_PAYLOAD_BYTES + 1024), IssuerGenerationState.ACTIVE)));
        var oversized = binding(generation("k".repeat(4 * 1024 * 1024), IssuerGenerationState.ACTIVE));
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.encode(oversized));
    }

    private static IssuerGeneration generation(String key, IssuerGenerationState state) {
        PkiId ca = new PkiId("ca:test"), cert = new PkiId("cert:test");
        return new IssuerGeneration(IssuerGeneration.idFor(ca, cert), ca, cert, new KeyRef(key), state, "0".repeat(64), "3".repeat(64));
    }
    private static IssuerCryptographicBinding binding(IssuerGeneration generation) {
        var key = new IssuerKeyBinding(generation.signingKeyRef(), BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY, BootstrapAlgorithmIdentities.ECDSA_SHA384,
                new EncodedObject(Encoding.DER, HexFormat.of().parseHex("300a06082a8648ce3d040303")), "1".repeat(64));
        return new IssuerCryptographicBinding(1, generation.issuerId(), generation.authorityId(), generation.credentialId(), "x509", key, Optional.empty(),
                "2".repeat(64), new CertificateProfileRef("test", 1, new byte[32]), "3".repeat(64), IssuerCryptographicBinding.HybridSignatureBaseline.NONE,
                "4".repeat(64));
    }
}
