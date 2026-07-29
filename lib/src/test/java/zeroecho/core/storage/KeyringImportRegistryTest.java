package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.sdk.util.BouncyCastleActivator;

class KeyringImportRegistryTest {
    @BeforeAll
    static void initializeProviders() {
        BouncyCastleActivator.init();
    }

    @Test
    void persistentImporterMatrixIsClosedUniqueAndExecutable() throws Exception {
        start("persistentImporterMatrixIsClosedUniqueAndExecutable");
        List<KeyringImportRegistry.PersistentMapping> mappings =
                KeyringImportRegistry.mappings();
        assertEquals(19, count(mappings, KeyringStore.Kind.PUBLIC_KEY));
        assertEquals(19, count(mappings, KeyringStore.Kind.PRIVATE_KEY));
        assertEquals(6, count(mappings, KeyringStore.Kind.SECRET_KEY));
        assertEquals(mappings.size(), mappings.stream().distinct().count());

        for (KeyringImportRegistry.PersistentMapping mapping : mappings) {
            KeyringImportRegistry.validateMapping(mapping.algorithmId(), mapping.kind(),
                    mapping.encoding(), mapping.hmacVariant());
        }
        roundTripAsymmetricMappings(mappings);
        roundTripSecretMappings(mappings);
        assertEquals(KeyringException.Code.KEYRING_IMPORT_MAPPING_INVALID,
                assertThrows(KeyringException.class,
                        () -> KeyringImportRegistry.validateMapping("RSA",
                                KeyringStore.Kind.SECRET_KEY, KeyringStore.Encoding.RAW,
                                KeyringImportRegistry.HmacVariant.NONE)).code());
        System.out.println("...mapping-count=" + mappings.size());
        ok();
    }

    @Test
    void alternateProviderStandardEncodingUsesCanonicalImporter(
            @TempDir Path temporaryDirectory) throws Exception {
        start("alternateProviderStandardEncodingUsesCanonicalImporter");
        java.security.KeyPairGenerator generator =
                java.security.KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        byte[] encoded = pair.getPublic().getEncoded();
        Key imported = null;
        PublicKey reopened = null;
        byte[] importedEncoding = null;
        byte[] reopenedEncoding = null;
        try {
            imported = KeyringImportRegistry.importKey("RSA",
                    KeyringStore.Kind.PUBLIC_KEY, KeyringStore.Encoding.X509,
                    KeyringImportRegistry.HmacVariant.NONE, encoded);
            importedEncoding = imported.getEncoded();
            assertArrayEquals(encoded, importedEncoding);
            assertEquals("RSA", imported.getAlgorithm());
            assertNotEquals(pair.getPublic().getClass(), imported.getClass());
            Path path = temporaryDirectory.resolve("alternate-provider.zek");
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.create(path, password)) {
                store.putPublic("alternate", "RSA", pair.getPublic());
            }
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.open(path, password)) {
                reopened = store.getPublic("alternate");
                reopenedEncoding = reopened.getEncoded();
                assertArrayEquals(encoded, reopenedEncoding);
            }
        } finally {
            wipe(encoded);
            wipe(importedEncoding);
            wipe(reopenedEncoding);
            destroy(imported);
            destroy(reopened);
        }
        ok();
    }

    private static long count(List<KeyringImportRegistry.PersistentMapping> mappings,
            KeyringStore.Kind kind) {
        return mappings.stream().filter(mapping -> mapping.kind() == kind).count();
    }

    private static void roundTripAsymmetricMappings(
            List<KeyringImportRegistry.PersistentMapping> mappings) throws Exception {
        List<String> algorithms = mappings.stream()
                .filter(mapping -> mapping.kind() == KeyringStore.Kind.PUBLIC_KEY)
                .map(KeyringImportRegistry.PersistentMapping::algorithmId)
                .toList();
        for (String algorithmId : algorithms) {
            KeyPair pair = generatePair(algorithmId);
            roundTrip(mapping(mappings, algorithmId, KeyringStore.Kind.PUBLIC_KEY),
                    pair.getPublic());
            roundTrip(mapping(mappings, algorithmId, KeyringStore.Kind.PRIVATE_KEY),
                    pair.getPrivate());
        }
    }

    private static void roundTripSecretMappings(
            List<KeyringImportRegistry.PersistentMapping> mappings) throws Exception {
        for (KeyringImportRegistry.PersistentMapping mapping : mappings) {
            if (mapping.kind() != KeyringStore.Kind.SECRET_KEY) {
                continue;
            }
            String jcaName = switch (mapping.algorithmId()) {
                case "AES" -> "AES";
                case "CHACHA20", "CHACHA20-POLY1305" -> "ChaCha20";
                case "HMAC" -> mapping.hmacVariant().jcaName();
                default -> throw new AssertionError("Unexpected secret mapping");
            };
            byte[] material = new byte[32];
            Arrays.fill(material, (byte) (mapping.hmacVariant().code() + 1));
            try {
                roundTrip(mapping, new SecretKeySpec(material, jcaName));
            } finally {
                wipe(material);
            }
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static KeyPair generatePair(String algorithmId) throws Exception {
        CryptoAlgorithm algorithm = CryptoAlgorithms.require(algorithmId);
        KeyOperationInfo generation = algorithm.keyOperations().stream()
                .filter(info -> info.operation() == KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE)
                .filter(info -> info.defaultSpec() != null)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "No default key-pair generation mapping for " + algorithmId));
        AsymmetricKeyPairGenerator generator =
                algorithm.asymmetricKeyPairGenerator(generation.specType());
        return generator.generateKeyPair((AlgorithmKeySpec) generation.defaultSpec());
    }

    private static KeyringImportRegistry.PersistentMapping mapping(
            List<KeyringImportRegistry.PersistentMapping> mappings, String algorithmId,
            KeyringStore.Kind kind) {
        return mappings.stream()
                .filter(candidate -> candidate.algorithmId().equals(algorithmId)
                        && candidate.kind() == kind)
                .findFirst()
                .orElseThrow();
    }

    private static void roundTrip(KeyringImportRegistry.PersistentMapping mapping,
            Key source) throws Exception {
        byte[] encoded = source.getEncoded();
        Key imported = null;
        byte[] reconstructed = null;
        try {
            imported = KeyringImportRegistry.importKey(mapping.algorithmId(), mapping.kind(),
                    mapping.encoding(), mapping.hmacVariant(), encoded);
            reconstructed = imported.getEncoded();
            assertArrayEquals(encoded, reconstructed);
        } finally {
            wipe(encoded);
            wipe(reconstructed);
            destroy(imported);
        }
    }

    private static void destroy(Key key) {
        if (key instanceof Destroyable destroyable) {
            try {
                destroyable.destroy();
            } catch (Exception exception) {
                // Provider keys may advertise but not implement destruction.
            }
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static KeyringPassword password() {
        char[] value = "alternate-provider-test".toCharArray();
        try {
            return new KeyringPassword(value);
        } finally {
            Arrays.fill(value, '\0');
        }
    }

    private static void start(String method) {
        System.out.println(method);
    }

    private static void ok() {
        System.out.println("...ok");
    }
}
