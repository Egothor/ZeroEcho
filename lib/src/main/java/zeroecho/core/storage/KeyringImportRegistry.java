/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.alg.aes.AesKeyImportSpec;
import zeroecho.core.alg.bike.BikePrivateKeySpec;
import zeroecho.core.alg.bike.BikePublicKeySpec;
import zeroecho.core.alg.chacha.ChaChaKeyImportSpec;
import zeroecho.core.alg.cmce.CmcePrivateKeySpec;
import zeroecho.core.alg.cmce.CmcePublicKeySpec;
import zeroecho.core.alg.dh.DhPrivateKeySpec;
import zeroecho.core.alg.dh.DhPublicKeySpec;
import zeroecho.core.alg.ecdsa.EcdsaPrivateKeySpec;
import zeroecho.core.alg.ecdsa.EcdsaPublicKeySpec;
import zeroecho.core.alg.ed25519.Ed25519PrivateKeySpec;
import zeroecho.core.alg.ed25519.Ed25519PublicKeySpec;
import zeroecho.core.alg.ed448.Ed448PrivateKeySpec;
import zeroecho.core.alg.ed448.Ed448PublicKeySpec;
import zeroecho.core.alg.elgamal.ElgamalPrivateKeySpec;
import zeroecho.core.alg.elgamal.ElgamalPublicKeySpec;
import zeroecho.core.alg.frodo.FrodoPrivateKeySpec;
import zeroecho.core.alg.frodo.FrodoPublicKeySpec;
import zeroecho.core.alg.hmac.HmacKeyImportSpec;
import zeroecho.core.alg.hqc.HqcPrivateKeySpec;
import zeroecho.core.alg.hqc.HqcPublicKeySpec;
import zeroecho.core.alg.kyber.KyberPrivateKeySpec;
import zeroecho.core.alg.kyber.KyberPublicKeySpec;
import zeroecho.core.alg.mldsa.MldsaPrivateKeySpec;
import zeroecho.core.alg.mldsa.MldsaPublicKeySpec;
import zeroecho.core.alg.ntru.NtruPrivateKeySpec;
import zeroecho.core.alg.ntru.NtruPublicKeySpec;
import zeroecho.core.alg.ntruprime.NtrulPrimePrivateKeySpec;
import zeroecho.core.alg.ntruprime.NtrulPrimePublicKeySpec;
import zeroecho.core.alg.ntruprime.SntruPrimePrivateKeySpec;
import zeroecho.core.alg.ntruprime.SntruPrimePublicKeySpec;
import zeroecho.core.alg.rsa.RsaPrivateKeySpec;
import zeroecho.core.alg.rsa.RsaPublicKeySpec;
import zeroecho.core.alg.saber.SaberPrivateKeySpec;
import zeroecho.core.alg.saber.SaberPublicKeySpec;
import zeroecho.core.alg.slhdsa.SlhDsaPrivateKeySpec;
import zeroecho.core.alg.slhdsa.SlhDsaPublicKeySpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusPrivateKeySpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusPublicKeySpec;
import zeroecho.core.alg.xdh.XdhPrivateKeySpec;
import zeroecho.core.alg.xdh.XdhPublicKeySpec;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.PrivateKeyImporter;
import zeroecho.core.spi.PublicKeyImporter;
import zeroecho.core.spi.SymmetricKeyImporter;

/**
 * Closed trusted mapping from persistent key identities to canonical registered
 * import operations.
 *
 * <p>Provider identity is deliberately absent. Standard encoded key material
 * is reconstructed by the current runtime's canonical ZeroEcho importer. The
 * original JCA provider is neither persisted nor reproduced.</p>
 */
final class KeyringImportRegistry {
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_HMAC = "HMAC";
    private static final String ALGORITHM_CHACHA20 = "CHACHA20";
    private static final String ALGORITHM_CHACHA20_POLY1305 = "CHACHA20-POLY1305";
    private static final Map<Class<? extends AlgorithmKeySpec>,
            Function<byte[], ? extends AlgorithmKeySpec>> SPEC_FACTORIES =
            createSpecFactories();
    private static final Map<Tuple, PersistentMapping> MAPPINGS = createMappings();

    private KeyringImportRegistry() {
    }

    /**
     * Closed HMAC variants admitted by the persistent format.
     */
    /* default */
    enum HmacVariant {
        NONE(0, null),
        SHA256(1, "HmacSHA256"),
        SHA384(2, "HmacSHA384"),
        SHA512(3, "HmacSHA512");

        private final int code;
        private final String jcaName;

        HmacVariant(int code, String jcaName) {
            this.code = code;
            this.jcaName = jcaName;
        }

        /* default */ int code() {
            return code;
        }

        /* default */ String jcaName() {
            return jcaName;
        }

        /* default */ static HmacVariant fromCode(int code) throws KeyringException {
            for (HmacVariant value : values()) {
                if (value.code == code) {
                    return value;
                }
            }
            throw new KeyringException(KeyringException.Code.KEYRING_IMPORT_METADATA_INVALID);
        }

        /* default */ static HmacVariant forStoredKey(String algorithmId, Key key)
                throws KeyringException {
            if (!ALGORITHM_HMAC.equals(algorithmId)) {
                return NONE;
            }
            String algorithm = key.getAlgorithm();
            for (HmacVariant value : values()) {
                if (value != NONE && value.jcaName.equals(algorithm)) {
                    return value;
                }
            }
            throw new KeyringException(KeyringException.Code.KEYRING_IMPORT_METADATA_INVALID);
        }
    }

    /**
     * Immutable description used by the finite importer-matrix test.
     *
     * @param algorithmId canonical ZeroEcho algorithm identifier
     * @param kind key kind
     * @param encoding standard encoding
     * @param hmacVariant closed HMAC variant, or {@link HmacVariant#NONE}
     * @param specType exact registered importer specification type
     */
    /* default */
    record PersistentMapping(String algorithmId, KeyringStore.Kind kind,
            KeyringStore.Encoding encoding, HmacVariant hmacVariant,
            Class<? extends AlgorithmKeySpec> specType) {
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ static Key importKey(String algorithmId, KeyringStore.Kind kind,
            KeyringStore.Encoding encoding, HmacVariant hmacVariant, byte[] encoded)
            throws GeneralSecurityException, KeyringException {
        PersistentMapping mapping = requireMapping(algorithmId, kind, encoding, hmacVariant);
        CryptoAlgorithm algorithm = requireAlgorithm(mapping.algorithmId);
        AlgorithmKeySpec spec = createSpec(mapping, encoded);
        Throwable primary = null;
        try {
            return invokeImporter(algorithm, kind, spec);
        } catch (GeneralSecurityException | RuntimeException exception) {
            primary = exception;
            throw exception;
        } finally {
            KeyringStore.destroyTemporarySpec(spec, primary);
        }
    }

    /* default */ static void validateMapping(String algorithmId, KeyringStore.Kind kind,
            KeyringStore.Encoding encoding, HmacVariant hmacVariant)
            throws KeyringException {
        PersistentMapping mapping = requireMapping(algorithmId, kind, encoding, hmacVariant);
        CryptoAlgorithm algorithm = requireAlgorithm(mapping.algorithmId);
        List<KeyOperationInfo> operations = matchingOperations(algorithm, kind);
        if (operations.size() != 1 || operations.get(0).specType() != mapping.specType) {
            throw new KeyringException(KeyringException.Code.KEYRING_IMPORT_MAPPING_INVALID);
        }
    }

    @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.AvoidCatchingGenericException" })
    /* default */ static void validateCanonical(String algorithmId, KeyringStore.Kind kind,
            KeyringStore.Encoding encoding, HmacVariant hmacVariant, Key source,
            byte[] encoded)
            throws KeyringException {
        Key imported = null;
        byte[] canonical = null;
        try {
            if (!matchesSourceAlgorithm(source, algorithmId, hmacVariant)) {
                throw new KeyringException(
                        KeyringException.Code.KEYRING_KEY_NOT_CANONICALIZABLE);
            }
            imported = importKey(algorithmId, kind, encoding, hmacVariant, encoded);
            canonical = imported.getEncoded();
            if (canonical == null || !matchesFormat(imported.getFormat(), encoding)
                    || !MessageDigest.isEqual(encoded, canonical)
                    || !matchesAlgorithm(imported, algorithmId, hmacVariant)) {
                throw new KeyringException(
                        KeyringException.Code.KEYRING_KEY_NOT_CANONICALIZABLE);
            }
        } catch (GeneralSecurityException | RuntimeException exception) {
            throw new KeyringException(
                    KeyringException.Code.KEYRING_KEY_NOT_CANONICALIZABLE);
        } finally {
            if (canonical != null) {
                Arrays.fill(canonical, (byte) 0);
            }
            destroyImported(imported);
        }
    }

    /* default */ static List<PersistentMapping> mappings() {
        return List.copyOf(MAPPINGS.values());
    }

    private static PersistentMapping requireMapping(String algorithmId,
            KeyringStore.Kind kind, KeyringStore.Encoding encoding,
            HmacVariant hmacVariant) throws KeyringException {
        PersistentMapping mapping = MAPPINGS.get(
                new Tuple(algorithmId, kind, encoding, hmacVariant));
        if (mapping == null) {
            throw new KeyringException(KeyringException.Code.KEYRING_IMPORT_MAPPING_INVALID);
        }
        return mapping;
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static CryptoAlgorithm requireAlgorithm(String algorithmId)
            throws KeyringException {
        try {
            return CryptoAlgorithms.require(algorithmId);
        } catch (IllegalArgumentException exception) {
            throw new KeyringException(KeyringException.Code.KEYRING_IMPORT_MAPPING_INVALID);
        }
    }

    private static List<KeyOperationInfo> matchingOperations(CryptoAlgorithm algorithm,
            KeyringStore.Kind kind) {
        return algorithm.keyOperations().stream()
                .filter(info -> info.operation() == operation(kind))
                .toList();
    }

    private static KeyOperation operation(KeyringStore.Kind kind) {
        return switch (kind) {
            case PUBLIC_KEY -> KeyOperation.ASYMMETRIC_PUBLIC_IMPORT;
            case PRIVATE_KEY -> KeyOperation.ASYMMETRIC_PRIVATE_IMPORT;
            case SECRET_KEY -> KeyOperation.SYMMETRIC_IMPORT;
        };
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static Key invokeImporter(CryptoAlgorithm algorithm, KeyringStore.Kind kind,
            AlgorithmKeySpec spec) throws GeneralSecurityException {
        return switch (kind) {
            case PUBLIC_KEY -> ((PublicKeyImporter) algorithm.publicKeyImporter(spec.getClass()))
                    .importPublic(spec);
            case PRIVATE_KEY -> ((PrivateKeyImporter) algorithm.privateKeyImporter(spec.getClass()))
                    .importPrivate(spec);
            case SECRET_KEY -> ((SymmetricKeyImporter) algorithm.symmetricKeyImporter(spec.getClass()))
                    .importSecret(spec);
        };
    }

    private static AlgorithmKeySpec createSpec(PersistentMapping mapping, byte[] encoded)
            throws KeyringException {
        if (mapping.specType == HmacKeyImportSpec.class) {
            return new HmacKeyImportSpec(mapping.hmacVariant.jcaName, encoded);
        }
        Function<byte[], ? extends AlgorithmKeySpec> factory =
                SPEC_FACTORIES.get(mapping.specType);
        AlgorithmKeySpec result = factory == null ? null : factory.apply(encoded);
        if (result == null) {
            throw new KeyringException(KeyringException.Code.KEYRING_IMPORT_MAPPING_INVALID);
        }
        return result;
    }

    private static boolean matchesFormat(String actual, KeyringStore.Encoding encoding) {
        return actual != null && switch (encoding) {
            case X509 -> "X.509".equalsIgnoreCase(actual) || "X509".equalsIgnoreCase(actual);
            case PKCS8 -> "PKCS#8".equalsIgnoreCase(actual) || "PKCS8".equalsIgnoreCase(actual);
            case RAW -> "RAW".equalsIgnoreCase(actual);
        };
    }

    private static boolean matchesAlgorithm(Key imported, String algorithmId,
            HmacVariant hmacVariant) {
        if (ALGORITHM_HMAC.equals(algorithmId)) {
            return hmacVariant.jcaName.equals(imported.getAlgorithm());
        }
        if (ALGORITHM_AES.equals(algorithmId)) {
            return ALGORITHM_AES.equals(imported.getAlgorithm());
        }
        if (ALGORITHM_CHACHA20.equals(algorithmId)
                || ALGORITHM_CHACHA20_POLY1305.equals(algorithmId)) {
            return "ChaCha20".equals(imported.getAlgorithm());
        }
        return true;
    }

    private static boolean matchesSourceAlgorithm(Key source, String algorithmId,
            HmacVariant hmacVariant) {
        if (ALGORITHM_HMAC.equals(algorithmId)) {
            return hmacVariant.jcaName.equals(source.getAlgorithm());
        }
        if (ALGORITHM_AES.equals(algorithmId)) {
            return ALGORITHM_AES.equals(source.getAlgorithm());
        }
        if (ALGORITHM_CHACHA20.equals(algorithmId)
                || ALGORITHM_CHACHA20_POLY1305.equals(algorithmId)) {
            return "ChaCha20".equals(source.getAlgorithm());
        }
        return true;
    }

    @SuppressWarnings("PMD.EmptyCatchBlock")
    private static void destroyImported(Key imported) {
        if (imported instanceof Destroyable destroyable) {
            try {
                destroyable.destroy();
            } catch (DestroyFailedException exception) {
                // Some JCA key implementations advertise but do not support destruction.
            }
        }
    }

    private static Map<Class<? extends AlgorithmKeySpec>,
            Function<byte[], ? extends AlgorithmKeySpec>> createSpecFactories() {
        return Map.ofEntries(
                Map.entry(AesKeyImportSpec.class, AesKeyImportSpec::fromRaw),
                Map.entry(ChaChaKeyImportSpec.class, ChaChaKeyImportSpec::fromRaw),
                Map.entry(BikePublicKeySpec.class, BikePublicKeySpec::new),
                Map.entry(BikePrivateKeySpec.class, BikePrivateKeySpec::new),
                Map.entry(CmcePublicKeySpec.class, CmcePublicKeySpec::new),
                Map.entry(CmcePrivateKeySpec.class, CmcePrivateKeySpec::new),
                Map.entry(DhPublicKeySpec.class, DhPublicKeySpec::new),
                Map.entry(DhPrivateKeySpec.class, DhPrivateKeySpec::new),
                Map.entry(EcdsaPublicKeySpec.class, EcdsaPublicKeySpec::new),
                Map.entry(EcdsaPrivateKeySpec.class, EcdsaPrivateKeySpec::new),
                Map.entry(Ed25519PublicKeySpec.class, Ed25519PublicKeySpec::new),
                Map.entry(Ed25519PrivateKeySpec.class, Ed25519PrivateKeySpec::new),
                Map.entry(Ed448PublicKeySpec.class, Ed448PublicKeySpec::new),
                Map.entry(Ed448PrivateKeySpec.class, Ed448PrivateKeySpec::new),
                Map.entry(ElgamalPublicKeySpec.class, ElgamalPublicKeySpec::new),
                Map.entry(ElgamalPrivateKeySpec.class, ElgamalPrivateKeySpec::new),
                Map.entry(FrodoPublicKeySpec.class, FrodoPublicKeySpec::new),
                Map.entry(FrodoPrivateKeySpec.class, FrodoPrivateKeySpec::new),
                Map.entry(HqcPublicKeySpec.class, HqcPublicKeySpec::new),
                Map.entry(HqcPrivateKeySpec.class, HqcPrivateKeySpec::new),
                Map.entry(KyberPublicKeySpec.class, KyberPublicKeySpec::new),
                Map.entry(KyberPrivateKeySpec.class, KyberPrivateKeySpec::new),
                Map.entry(MldsaPublicKeySpec.class, MldsaPublicKeySpec::new),
                Map.entry(MldsaPrivateKeySpec.class, MldsaPrivateKeySpec::new),
                Map.entry(NtruPublicKeySpec.class, NtruPublicKeySpec::new),
                Map.entry(NtruPrivateKeySpec.class, NtruPrivateKeySpec::new),
                Map.entry(NtrulPrimePublicKeySpec.class, NtrulPrimePublicKeySpec::new),
                Map.entry(NtrulPrimePrivateKeySpec.class, NtrulPrimePrivateKeySpec::new),
                Map.entry(SntruPrimePublicKeySpec.class, SntruPrimePublicKeySpec::new),
                Map.entry(SntruPrimePrivateKeySpec.class, SntruPrimePrivateKeySpec::new),
                Map.entry(RsaPublicKeySpec.class, RsaPublicKeySpec::new),
                Map.entry(RsaPrivateKeySpec.class, RsaPrivateKeySpec::new),
                Map.entry(SaberPublicKeySpec.class, SaberPublicKeySpec::new),
                Map.entry(SaberPrivateKeySpec.class, SaberPrivateKeySpec::new),
                Map.entry(SlhDsaPublicKeySpec.class, SlhDsaPublicKeySpec::new),
                Map.entry(SlhDsaPrivateKeySpec.class, SlhDsaPrivateKeySpec::new),
                Map.entry(SphincsPlusPublicKeySpec.class, SphincsPlusPublicKeySpec::new),
                Map.entry(SphincsPlusPrivateKeySpec.class, SphincsPlusPrivateKeySpec::new),
                Map.entry(XdhPublicKeySpec.class, XdhPublicKeySpec::new),
                Map.entry(XdhPrivateKeySpec.class, XdhPrivateKeySpec::new));
    }

    private static Map<Tuple, PersistentMapping> createMappings() {
        Map<Tuple, PersistentMapping> mappings = new LinkedHashMap<>();
        addAsymmetric(mappings, "BIKE", BikePublicKeySpec.class, BikePrivateKeySpec.class);
        addAsymmetric(mappings, "CMCE", CmcePublicKeySpec.class, CmcePrivateKeySpec.class);
        addAsymmetric(mappings, "DH", DhPublicKeySpec.class, DhPrivateKeySpec.class);
        addAsymmetric(mappings, "ECDSA", EcdsaPublicKeySpec.class, EcdsaPrivateKeySpec.class);
        addAsymmetric(mappings, "Ed25519", Ed25519PublicKeySpec.class,
                Ed25519PrivateKeySpec.class);
        addAsymmetric(mappings, "Ed448", Ed448PublicKeySpec.class,
                Ed448PrivateKeySpec.class);
        addAsymmetric(mappings, "ElGamal", ElgamalPublicKeySpec.class,
                ElgamalPrivateKeySpec.class);
        addAsymmetric(mappings, "Frodo", FrodoPublicKeySpec.class,
                FrodoPrivateKeySpec.class);
        addAsymmetric(mappings, "HQC", HqcPublicKeySpec.class, HqcPrivateKeySpec.class);
        addAsymmetric(mappings, "ML-KEM", KyberPublicKeySpec.class,
                KyberPrivateKeySpec.class);
        addAsymmetric(mappings, "ML-DSA", MldsaPublicKeySpec.class,
                MldsaPrivateKeySpec.class);
        addAsymmetric(mappings, "NTRU", NtruPublicKeySpec.class, NtruPrivateKeySpec.class);
        addAsymmetric(mappings, "NTRULPRime", NtrulPrimePublicKeySpec.class,
                NtrulPrimePrivateKeySpec.class);
        addAsymmetric(mappings, "SNTRUPrime", SntruPrimePublicKeySpec.class,
                SntruPrimePrivateKeySpec.class);
        addAsymmetric(mappings, "RSA", RsaPublicKeySpec.class, RsaPrivateKeySpec.class);
        addAsymmetric(mappings, "SABER", SaberPublicKeySpec.class,
                SaberPrivateKeySpec.class);
        addAsymmetric(mappings, "SLH-DSA", SlhDsaPublicKeySpec.class,
                SlhDsaPrivateKeySpec.class);
        addAsymmetric(mappings, "SPHINCS+", SphincsPlusPublicKeySpec.class,
                SphincsPlusPrivateKeySpec.class);
        addAsymmetric(mappings, "Xdh", XdhPublicKeySpec.class, XdhPrivateKeySpec.class);
        add(mappings, ALGORITHM_AES, KeyringStore.Kind.SECRET_KEY,
                KeyringStore.Encoding.RAW,
                HmacVariant.NONE, AesKeyImportSpec.class);
        add(mappings, ALGORITHM_CHACHA20, KeyringStore.Kind.SECRET_KEY,
                KeyringStore.Encoding.RAW,
                HmacVariant.NONE, ChaChaKeyImportSpec.class);
        add(mappings, ALGORITHM_CHACHA20_POLY1305, KeyringStore.Kind.SECRET_KEY,
                KeyringStore.Encoding.RAW, HmacVariant.NONE, ChaChaKeyImportSpec.class);
        add(mappings, ALGORITHM_HMAC, KeyringStore.Kind.SECRET_KEY,
                KeyringStore.Encoding.RAW,
                HmacVariant.SHA256, HmacKeyImportSpec.class);
        add(mappings, ALGORITHM_HMAC, KeyringStore.Kind.SECRET_KEY,
                KeyringStore.Encoding.RAW,
                HmacVariant.SHA384, HmacKeyImportSpec.class);
        add(mappings, ALGORITHM_HMAC, KeyringStore.Kind.SECRET_KEY,
                KeyringStore.Encoding.RAW,
                HmacVariant.SHA512, HmacKeyImportSpec.class);
        return Collections.unmodifiableMap(mappings);
    }

    private static void addAsymmetric(Map<Tuple, PersistentMapping> mappings,
            String algorithmId, Class<? extends AlgorithmKeySpec> publicSpec,
            Class<? extends AlgorithmKeySpec> privateSpec) {
        add(mappings, algorithmId, KeyringStore.Kind.PUBLIC_KEY,
                KeyringStore.Encoding.X509, HmacVariant.NONE, publicSpec);
        add(mappings, algorithmId, KeyringStore.Kind.PRIVATE_KEY,
                KeyringStore.Encoding.PKCS8, HmacVariant.NONE, privateSpec);
    }

    private static void add(Map<Tuple, PersistentMapping> mappings, String algorithmId,
            KeyringStore.Kind kind, KeyringStore.Encoding encoding,
            HmacVariant hmacVariant, Class<? extends AlgorithmKeySpec> specType) {
        Tuple tuple = new Tuple(algorithmId, kind, encoding, hmacVariant);
        PersistentMapping mapping = new PersistentMapping(algorithmId, kind,
                encoding, hmacVariant, specType);
        if (mappings.put(tuple, mapping) != null) {
            throw new IllegalStateException("Duplicate persistent key importer tuple");
        }
    }

    private record Tuple(String algorithmId, KeyringStore.Kind kind,
            KeyringStore.Encoding encoding, HmacVariant hmacVariant) {
    }
}
