/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import zeroecho.core.storage.KeyringException.Code;
import zeroecho.core.storage.KeyringFileOperations.Target;
import zeroecho.core.util.RandomSupport;

/**
 * Path-bound encrypted local software keystore.
 *
 * <p>
 * A keyring uses PBKDF2-HMAC-SHA-256 to unwrap one random 256-bit store master
 * key. Every entry and the ordered manifest are independently protected by
 * AES-256-GCM. Java class names are neither persisted nor resolved. Import
 * mappings come exclusively from a closed mapping to the immutable algorithm
 * registry. Provider names are not persisted: standard key encodings are
 * reconstructed by the current runtime's canonical importer. HMAC persistence
 * admits only HmacSHA256, HmacSHA384, and HmacSHA512.
 * </p>
 *
 * <p>
 * The keyring exclusively owns its filesystem path from successful
 * {@link #create(Path, KeyringPassword)} or
 * {@link #open(Path, KeyringPassword)} until {@link #close()}. Only POSIX
 * filesystems on which owner-only permissions and ownership can be verified are
 * supported. Mutations replace a complete encrypted image atomically.
 * </p>
 *
 * <p>
 * The nonce-reservation sidecar is authenticated independently from AES entry
 * and manifest encryption. Its 256-bit MAC key is derived from the store master
 * key and binary store UUID with HKDF-HMAC-SHA-256 and the fixed domain label
 * {@code zeroecho:keyring:nonce-reservation-mac:v1}. The derived key is
 * retained only while the store is open and is cleared on close. Previous
 * sidecar versions are rejected.
 * </p>
 *
 * <p>
 * Instances are thread-safe. Reads may proceed concurrently; mutations and
 * close are exclusive. Closing clears the master and sidecar MAC keys and makes
 * all subsequent operations fail. The pre-release plaintext format is rejected
 * and is not migrated.
 * </p>
 */
// The store intentionally centralizes its closed format, crypto, and lifecycle types.
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class KeyringStore implements AutoCloseable, Destroyable {
    // NOPMD
    /* default */ static final byte[] MAGIC = { 'Z', 'E', 'K', 'R', 'I', 'N', 'G', '2' };
    /* default */ static final int FORMAT_VERSION = 2;
    /* default */ static final int ENTRY_FORMAT_VERSION = 1;
    /* default */ static final int MANIFEST_FORMAT_VERSION = 1;
    /* default */ static final int MAX_FILE_BYTES = 128 * 1024 * 1024;
    /* default */ static final int MAX_ENTRY_COUNT = 16_384;
    /* default */ static final int MAX_ENTRY_CIPHERTEXT_BYTES = 16 * 1024 * 1024;
    /* default */ static final int MAX_ALIAS_BYTES = 512;
    /* default */ static final int MAX_METADATA_BYTES = 4_096;
    /* default */ static final int SALT_BYTES = 32;
    /* default */ static final int KEK_BYTES = 32;
    /* default */ static final int MASTER_KEY_BYTES = 32;
    /* default */ static final int NONCE_BYTES = 12;
    /* default */ static final int UUID_BYTES = 16;
    /* default */ static final int GCM_TAG_BITS = 128;
    /* default */ static final int GCM_TAG_BYTES = GCM_TAG_BITS / 8;
    /* default */ static final int SHA256_BYTES = 32;
    /* default */ static final byte KDF_PBKDF2_SHA256 = 1;
    /* default */ static final byte AEAD_AES_256_GCM = 1;
    private static final byte[] NONCE_RESERVATION_MAGIC = { 'Z', 'E', 'K', 'N', 'O', 'N', 'C', '2' };
    private static final int NONCE_RESERVATION_VERSION = 2;
    private static final int NONCE_RESERVATION_TAG_BYTES = 32;
    private static final byte MASTER_WRAP_NONCE_DOMAIN = 1;
    private static final byte ENTRY_NONCE_DOMAIN = 2;

    private static final String SUFFIX_PUBLIC = ".pub";
    private static final String SUFFIX_PRIVATE = ".priv";
    private static final long MIN_NONCE_HIGH_WATER = 1L;
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);
    private static final FileAttribute<Set<PosixFilePermission>> DIRECTORY_ATTRIBUTE = PosixFilePermissions
            .asFileAttribute(DIRECTORY_PERMISSIONS);
    private static final FileAttribute<Set<PosixFilePermission>> FILE_ATTRIBUTE = PosixFilePermissions
            .asFileAttribute(FILE_PERMISSIONS);
    private static final KeyringRandomBytes SYSTEM_RANDOM = destination -> RandomSupport.getRandom()
            .nextBytes(destination);
    private final Path path;
    private final Path nonceReservationPath;
    private final Ownership ownership;
    private final KeyringRandomBytes random;
    private final KeyringFileOperations fileOperations;
    private final ReentrantReadWriteLock lifecycleLock = new ReentrantReadWriteLock();
    private final AtomicBoolean destroyed = new AtomicBoolean();
    private final byte[] storeId;
    private final byte[] salt;
    private final byte[] masterWrapNonce;
    private final byte[] wrappedMasterKey;
    private final byte[] masterKey;
    private final byte[] nonceReservationMacKey;
    private final int iterations;
    private final int noncePrefix;
    private long nonceHighWater;
    private Map<String, EncryptedEntry> entries;
    private boolean poisoned;

    /**
     * Standard encoded key forms supported by the encrypted store.
     */
    public enum Encoding {
        X509(1), PKCS8(2), RAW(3);

        private final int code;

        Encoding(int code) {
            this.code = code;
        }

        /* default */ static Encoding fromCode(int code) throws KeyringException {
            for (Encoding value : values()) {
                if (value.code == code) {
                    return value;
                }
            }
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    /**
     * Key classifications supported by the encrypted store.
     */
    public enum Kind {
        PUBLIC_KEY(1), PRIVATE_KEY(2), SECRET_KEY(3);

        private final int code;

        Kind(int code) {
            this.code = code;
        }

        /* default */ static Kind fromCode(int code) throws KeyringException {
            for (Kind value : values()) {
                if (value.code == code) {
                    return value;
                }
            }
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    private KeyringStore(Path path, Ownership ownership, KeyringRandomBytes random,
            KeyringFileOperations fileOperations, Header header, byte[] masterKey, byte[] nonceReservationMacKey,
            Manifest manifest, Map<String, EncryptedEntry> entries) {
        this.path = path;
        this.nonceReservationPath = nonceReservationPath(path);
        this.ownership = ownership;
        this.random = random;
        this.fileOperations = fileOperations;
        this.storeId = header.storeId.clone();
        this.salt = header.salt.clone();
        this.masterWrapNonce = header.masterWrapNonce.clone();
        this.wrappedMasterKey = header.wrappedMasterKey.clone();
        this.masterKey = masterKey;
        this.nonceReservationMacKey = nonceReservationMacKey.clone();
        this.iterations = header.iterations;
        this.noncePrefix = manifest.noncePrefix;
        this.nonceHighWater = manifest.highWater;
        this.entries = entries;
    }

    /**
     * Creates a new encrypted keyring with the standard protection policy.
     *
     * @param path     new keyring file
     * @param password borrowed unlock password; the caller remains responsible for
     *                 destroying it
     * @return open encrypted keyring
     * @throws IOException              if secure creation or durable persistence
     *                                  fails
     * @throws GeneralSecurityException if cryptographic initialization fails
     */
    public static KeyringStore create(Path path, KeyringPassword password)
            throws IOException, GeneralSecurityException {
        return create(path, password, KeyringProtection.standard());
    }

    /**
     * Creates a new encrypted keyring.
     *
     * @param path       new keyring file
     * @param password   borrowed unlock password
     * @param protection operational protection policy
     * @return open encrypted keyring
     * @throws IOException              if secure creation or durable persistence
     *                                  fails
     * @throws GeneralSecurityException if cryptographic initialization fails
     */
    public static KeyringStore create(Path path, KeyringPassword password, KeyringProtection protection)
            throws IOException, GeneralSecurityException {
        return create(path, password, protection, SYSTEM_RANDOM);
    }

    /* default */ static KeyringStore create(Path path, KeyringPassword password, KeyringProtection protection,
            KeyringRandomBytes random) throws IOException, GeneralSecurityException {
        return create(path, password, protection, random, KeyringFileOperations.NIO);
    }

    @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
    /* default */ static KeyringStore create(Path path, KeyringPassword password, KeyringProtection protection,
            KeyringRandomBytes random, KeyringFileOperations fileOperations)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(password, "password must not be null");
        Objects.requireNonNull(protection, "protection must not be null");
        Objects.requireNonNull(random, "random must not be null");
        Objects.requireNonNull(fileOperations, "fileOperations must not be null");
        Path normalized = securePath(path, true);
        Ownership ownership = Ownership.acquire(normalized);
        byte[] masterKey = new byte[MASTER_KEY_BYTES];
        byte[] salt = new byte[SALT_BYTES];
        byte[] storeId = new byte[UUID_BYTES];
        byte[] wrapNonce = new byte[NONCE_BYTES];
        byte[] kek = null;
        byte[] aad = null;
        byte[] wrapped = null;
        byte[] nonceReservationMacKey = null;
        KeyringStore store = null;
        boolean success = false;
        try {
            if (Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
                throw new KeyringException(Code.KEYRING_IO_FAILED);
            }
            random.nextBytes(masterKey);
            random.nextBytes(salt);
            random.nextBytes(storeId);
            nonceReservationMacKey = KeyringNonceReservationKdf.derive(masterKey, storeId);
            fillMasterWrapNonce(random, wrapNonce);
            int prefix = randomPrefix(random);
            Header provisional = new Header(storeId, KeyringProtection.CREATION_ITERATIONS, salt, wrapNonce,
                    new byte[0]);
            aad = masterWrapAad(provisional);
            kek = deriveKek(password, salt, provisional.iterations);
            wrapped = crypt(Cipher.ENCRYPT_MODE, kek, wrapNonce, aad, masterKey);
            Header header = new Header(storeId, provisional.iterations, salt, wrapNonce, wrapped);
            Manifest initial = new Manifest(prefix, 0, List.of());
            store = new KeyringStore(normalized, ownership, random, fileOperations, header, masterKey,
                    nonceReservationMacKey, initial, new LinkedHashMap<>());
            store.persistSnapshot(new LinkedHashMap<>());
            success = true;
            return store;
        } finally {
            wipe(kek);
            wipe(aad);
            wipe(wrapped);
            wipe(salt);
            wipe(storeId);
            wipe(wrapNonce);
            wipe(nonceReservationMacKey);
            if (!success) {
                wipe(masterKey);
                if (store != null) {
                    store.close();
                } else {
                    ownership.close();
                }
            }
        }
    }

    /**
     * Opens an encrypted keyring with the standard protection policy.
     *
     * @param path     keyring file
     * @param password borrowed unlock password
     * @return open encrypted keyring
     * @throws IOException              if the format, filesystem, or authentication
     *                                  check fails
     * @throws GeneralSecurityException if cryptographic initialization fails
     */
    public static KeyringStore open(Path path, KeyringPassword password) throws IOException, GeneralSecurityException {
        return open(path, password, KeyringProtection.standard());
    }

    /**
     * Opens an encrypted keyring.
     *
     * @param path       keyring file
     * @param password   borrowed unlock password
     * @param protection operational protection policy
     * @return open encrypted keyring
     * @throws IOException              if the format, filesystem, or authentication
     *                                  check fails
     * @throws GeneralSecurityException if cryptographic initialization fails
     */
    public static KeyringStore open(Path path, KeyringPassword password, KeyringProtection protection)
            throws IOException, GeneralSecurityException {
        return open(path, password, protection, SYSTEM_RANDOM);
    }

    /* default */ static KeyringStore open(Path path, KeyringPassword password, KeyringProtection protection,
            KeyringRandomBytes random) throws IOException, GeneralSecurityException {
        return open(path, password, protection, random, KeyringFileOperations.NIO);
    }

    @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
    /* default */ static KeyringStore open(Path path, KeyringPassword password, KeyringProtection protection,
            KeyringRandomBytes random, KeyringFileOperations fileOperations)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(password, "password must not be null");
        Objects.requireNonNull(protection, "protection must not be null");
        Objects.requireNonNull(random, "random must not be null");
        Objects.requireNonNull(fileOperations, "fileOperations must not be null");
        Path normalized = securePath(path, false);
        Ownership ownership = Ownership.acquire(normalized);
        byte[] image = null;
        byte[] masterKey = null;
        byte[] nonceReservationMacKey = null;
        boolean success = false;
        try {
            validateExistingFile(normalized, ownership.owner());
            image = readStoreImage(normalized);
            Decoded decoded = decodeImage(image, password, protection);
            masterKey = decoded.masterKey;
            nonceReservationMacKey = KeyringNonceReservationKdf.derive(masterKey, decoded.header.storeId);
            long reservedHighWater = readNonceReservation(normalized, ownership.owner(), decoded.header.storeId,
                    decoded.manifest.noncePrefix, nonceReservationMacKey);
            if (reservedHighWater < decoded.manifest.highWater) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            Manifest effectiveManifest = new Manifest(decoded.manifest.noncePrefix, reservedHighWater,
                    decoded.manifest.entries);
            KeyringStore store = new KeyringStore(normalized, ownership, random, fileOperations, decoded.header,
                    masterKey, nonceReservationMacKey, effectiveManifest, decoded.entries);
            success = true;
            return store;
        } finally {
            wipe(image);
            wipe(nonceReservationMacKey);
            if (!success) {
                wipe(masterKey);
                ownership.close();
            }
        }
    }

    /**
     * Adds or replaces an encoded public key and persists the mutation.
     *
     * @param alias       logical alias
     * @param algorithmId canonical registered algorithm identifier
     * @param key         exportable public key
     * @throws IOException              if validation or durable persistence fails
     * @throws GeneralSecurityException if entry encryption fails
     */
    public void putPublic(String alias, String algorithmId, PublicKey key)
            throws IOException, GeneralSecurityException {
        put(withPublicSuffix(alias), algorithmId, Kind.PUBLIC_KEY, Encoding.X509, key,
                KeyringImportRegistry.HmacVariant.NONE);
    }

    /**
     * Adds or replaces an encoded private key and persists the mutation.
     *
     * @param alias       logical alias
     * @param algorithmId canonical registered algorithm identifier
     * @param key         exportable private key
     * @throws IOException              if validation or durable persistence fails
     * @throws GeneralSecurityException if entry encryption fails
     */
    public void putPrivate(String alias, String algorithmId, PrivateKey key)
            throws IOException, GeneralSecurityException {
        put(withPrivateSuffix(alias), algorithmId, Kind.PRIVATE_KEY, Encoding.PKCS8, key,
                KeyringImportRegistry.HmacVariant.NONE);
    }

    /**
     * Adds or replaces an encoded secret key and persists the mutation.
     *
     * @param alias       logical alias
     * @param algorithmId canonical registered algorithm identifier
     * @param key         exportable secret key
     * @throws IOException              if validation or durable persistence fails
     * @throws GeneralSecurityException if entry encryption fails
     */
    public void putSecret(String alias, String algorithmId, SecretKey key)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(key, "key must not be null");
        KeyringImportRegistry.HmacVariant hmacVariant = KeyringImportRegistry.HmacVariant.forStoredKey(algorithmId,
                key);
        put(alias, algorithmId, Kind.SECRET_KEY, Encoding.RAW, key, hmacVariant);
    }

    /**
     * Reports whether an alias is present.
     *
     * @param alias logical or suffixed alias
     * @return {@code true} if a matching entry exists
     * @throws IllegalStateException after close
     */
    public boolean contains(String alias) {
        lifecycleLock.readLock().lock();
        try {
            ensureOpenUnchecked();
            if (alias == null) {
                return false;
            }
            return entries.containsKey(alias) || entries.containsKey(withPublicSuffix(alias))
                    || entries.containsKey(withPrivateSuffix(alias));
        } finally {
            lifecycleLock.readLock().unlock();
        }
    }

    /**
     * Returns aliases in their persisted order.
     *
     * @return independent alias list
     * @throws IllegalStateException after close
     */
    public List<String> aliases() {
        lifecycleLock.readLock().lock();
        try {
            ensureOpenUnchecked();
            List<String> result = new ArrayList<>(entries.size());
            for (String alias : entries.keySet()) {
                result.add(stripKnownSuffix(alias));
            }
            return result;
        } finally {
            lifecycleLock.readLock().unlock();
        }
    }

    /**
     * Resolves a public key and its canonical algorithm identifier.
     *
     * @param alias logical alias
     * @return imported key and algorithm
     * @throws IOException              if the entry cannot be authenticated
     * @throws GeneralSecurityException if decryption or import fails
     */
    public PublicWithId getPublicWithId(String alias) throws IOException, GeneralSecurityException {
        Imported imported = importEntry(withPublicSuffix(alias), Kind.PUBLIC_KEY);
        return new PublicWithId(imported.algorithm, (PublicKey) imported.key);
    }

    /**
     * Resolves a private key and its canonical algorithm identifier.
     *
     * @param alias logical alias
     * @return imported key and algorithm
     * @throws IOException              if the entry cannot be authenticated
     * @throws GeneralSecurityException if decryption or import fails
     */
    public PrivateWithId getPrivateWithId(String alias) throws IOException, GeneralSecurityException {
        Imported imported = importEntry(withPrivateSuffix(alias), Kind.PRIVATE_KEY);
        return new PrivateWithId(imported.algorithm, (PrivateKey) imported.key);
    }

    /**
     * Resolves a secret key and its canonical algorithm identifier.
     *
     * @param alias logical alias
     * @return imported key and algorithm
     * @throws IOException              if the entry cannot be authenticated
     * @throws GeneralSecurityException if decryption or import fails
     */
    public SecretWithId getSecretWithId(String alias) throws IOException, GeneralSecurityException {
        Imported imported = importEntry(alias, Kind.SECRET_KEY);
        return new SecretWithId(imported.algorithm, (SecretKey) imported.key);
    }

    /**
     * Resolves a public key.
     *
     * @param alias logical alias
     * @return imported public key
     * @throws IOException              if the entry cannot be authenticated
     * @throws GeneralSecurityException if decryption or import fails
     */
    public PublicKey getPublic(String alias) throws IOException, GeneralSecurityException {
        return getPublicWithId(alias).key();
    }

    /**
     * Resolves a private key.
     *
     * @param alias logical alias
     * @return imported private key
     * @throws IOException              if the entry cannot be authenticated
     * @throws GeneralSecurityException if decryption or import fails
     */
    public PrivateKey getPrivate(String alias) throws IOException, GeneralSecurityException {
        return getPrivateWithId(alias).key();
    }

    /**
     * Resolves a secret key.
     *
     * @param alias logical alias
     * @return imported secret key
     * @throws IOException              if the entry cannot be authenticated
     * @throws GeneralSecurityException if decryption or import fails
     */
    public SecretKey getSecret(String alias) throws IOException, GeneralSecurityException {
        return getSecretWithId(alias).key();
    }

    /**
     * Algorithm identifier paired with an imported public key.
     *
     * @param algorithm canonical algorithm identifier
     * @param key       imported key
     */
    public record PublicWithId(String algorithm, PublicKey key) {
    }

    /**
     * Algorithm identifier paired with an imported private key.
     *
     * @param algorithm canonical algorithm identifier
     * @param key       imported key
     */
    public record PrivateWithId(String algorithm, PrivateKey key) {
    }

    /**
     * Algorithm identifier paired with an imported secret key.
     *
     * @param algorithm canonical algorithm identifier
     * @param key       imported key
     */
    public record SecretWithId(String algorithm, SecretKey key) {
    }

    /**
     * Clears the master and nonce-reservation MAC keys and releases filesystem
     * ownership.
     *
     * <p>
     * Concurrent calls are safe and cleanup occurs exactly once.
     * </p>
     *
     * @throws DestroyFailedException if resource release fails
     */
    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public void destroy() throws DestroyFailedException {
        lifecycleLock.writeLock().lock();
        try {
            if (!destroyed.compareAndSet(false, true)) {
                return;
            }
            wipe(masterKey);
            wipe(nonceReservationMacKey);
            entries.clear();
            entries = new LinkedHashMap<>();
            try {
                ownership.close();
            } catch (IOException exception) {
                throw new DestroyFailedException("KEYRING_IO_FAILED");
            }
        } finally {
            lifecycleLock.writeLock().unlock();
        }
    }

    /**
     * Reports whether the keyring has been destroyed.
     *
     * @return {@code true} after close or destruction
     */
    @Override
    public boolean isDestroyed() {
        return destroyed.get();
    }

    /**
     * Closes the keyring, clearing its master key.
     */
    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public void close() {
        try {
            destroy();
        } catch (DestroyFailedException exception) {
            throw new IllegalStateException("KEYRING_IO_FAILED");
        }
    }

    private void put(String alias, String algorithmId, Kind kind, Encoding encoding, Key key,
            KeyringImportRegistry.HmacVariant hmacVariant) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(key, "key must not be null");
        validateString(alias, MAX_ALIAS_BYTES);
        validateString(algorithmId, MAX_METADATA_BYTES);
        KeyringImportRegistry.validateMapping(algorithmId, kind, encoding, hmacVariant);
        String format = key.getFormat();
        if (format == null || !matchesFormat(format, encoding)) {
            throw new KeyringException(Code.KEYRING_IMPORT_MAPPING_INVALID);
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new KeyringException(Code.KEYRING_NON_EXPORTABLE_KEY);
        }
        try {
            KeyringImportRegistry.validateCanonical(algorithmId, kind, encoding, hmacVariant, key, encoded);
            lifecycleLock.writeLock().lock();
            try {
                ensureOpen();
                if (entries.size() >= MAX_ENTRY_COUNT && !entries.containsKey(alias)) {
                    throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
                }
                Map<String, EncryptedEntry> candidate = new LinkedHashMap<>(entries);
                int position = positionFor(candidate, alias);
                byte[] entryId = new byte[UUID_BYTES];
                random.nextBytes(entryId);
                byte[] nonce = nextNonce();
                byte[] plaintext = null;
                byte[] aad = null;
                byte[] ciphertext = null;
                try {
                    plaintext = encodeEntryPlaintext(alias, algorithmId, kind, encoding, hmacVariant, encoded);
                    aad = entryAad(entryId, position);
                    ciphertext = crypt(Cipher.ENCRYPT_MODE, masterKey, nonce, aad, plaintext);
                    if (ciphertext.length > MAX_ENTRY_CIPHERTEXT_BYTES) {
                        throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
                    }
                    EncryptedEntry entry = new EncryptedEntry(entryId, position, alias, algorithmId, kind, encoding,
                            hmacVariant, nonce, ciphertext, digest(ciphertext));
                    candidate.put(alias, entry);
                    persistSnapshot(candidate);
                    entries = candidate;
                } finally {
                    wipe(entryId);
                    wipe(nonce);
                    wipe(plaintext);
                    wipe(aad);
                    wipe(ciphertext);
                }
            } finally {
                lifecycleLock.writeLock().unlock();
            }
        } finally {
            wipe(encoded);
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private Imported importEntry(String alias, Kind expected) throws IOException, GeneralSecurityException {
        lifecycleLock.readLock().lock();
        try {
            ensureOpen();
            EncryptedEntry entry = entries.get(alias);
            if (entry == null || entry.kind != expected) {
                throw new IllegalArgumentException("Requested key entry is unavailable");
            }
            byte[] aad = null;
            byte[] plaintext = null;
            EntryPlain decoded = null;
            try {
                aad = entryAad(entry.entryId, entry.position);
                plaintext = crypt(Cipher.DECRYPT_MODE, masterKey, entry.nonce, aad, entry.ciphertext);
                decoded = decodeEntryPlaintext(plaintext);
                validateEntryBinding(entry, decoded);
                Key key = KeyringImportRegistry.importKey(decoded.algorithm, decoded.kind, decoded.encoding,
                        decoded.hmacVariant, decoded.encoded);
                return new Imported(decoded.algorithm, key);
            } catch (AEADBadTagException exception) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            } finally {
                if (decoded != null) {
                    wipe(decoded.encoded);
                }
                wipe(plaintext);
                wipe(aad);
            }
        } finally {
            lifecycleLock.readLock().unlock();
        }
    }

    private void persistSnapshot(Map<String, EncryptedEntry> candidate) throws IOException, GeneralSecurityException {
        byte[] manifestNonce = null;
        byte[] manifestPlain = null;
        byte[] manifestAad = null;
        byte[] manifestCipher = null;
        byte[] image = null;
        try {
            manifestNonce = nextNonce();
            manifestPlain = encodeManifest(candidate);
            manifestAad = manifestAad(candidate.size());
            manifestCipher = crypt(Cipher.ENCRYPT_MODE, masterKey, manifestNonce, manifestAad, manifestPlain);
            image = encodeImage(candidate, manifestNonce, manifestCipher);
            writeAtomically(image);
        } catch (IOException | GeneralSecurityException exception) {
            if (poisoned) {
                destroyPoisonedStore(exception);
            }
            throw exception;
        } finally {
            wipe(manifestNonce);
            wipe(manifestPlain);
            wipe(manifestAad);
            wipe(manifestCipher);
            wipe(image);
        }
    }

    private void writeAtomically(byte[] image) throws IOException {
        if (image.length > MAX_FILE_BYTES) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
        writeAtomically(Target.MAIN_IMAGE, path, image);
    }

    @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.ExceptionAsFlowControl" })
    private void writeAtomically(Target target, Path destination, byte[] image) throws IOException {
        Path parent = destination.getParent();
        Path temporary = null;
        boolean moved = false;
        IOException primary = null;
        try {
            temporary = fileOperations.createTemporary(target, parent, "." + destination.getFileName() + ".", ".tmp",
                    FILE_ATTRIBUTE);
            validateOwnerOnly(temporary, false);
            fileOperations.writeTemporary(target, temporary, image);
            fileOperations.forceTemporary(target, temporary);
            try {
                fileOperations.atomicReplace(target, temporary, destination);
            } catch (AtomicMoveNotSupportedException exception) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
            moved = true;
            validateExistingFile(destination, ownership.owner());
            fileOperations.forceDirectory(target, parent);
        } catch (UnsupportedOperationException exception) {
            primary = persistenceFailure(moved);
        } catch (IOException exception) {
            primary = moved ? persistenceFailure(true) : sanitizePersistenceFailure(exception);
        }
        if (!moved && temporary != null) {
            try {
                fileOperations.deleteTemporary(target, temporary);
            } catch (IOException cleanupFailure) {
                primary.addSuppressed(new KeyringException(Code.KEYRING_IO_FAILED));
            }
        }
        if (primary != null) {
            throw primary;
        }
    }

    private IOException persistenceFailure(boolean moved) {
        if (moved) {
            poisoned = true;
            return new KeyringException(Code.KEYRING_DURABILITY_UNCONFIRMED);
        }
        return new KeyringException(Code.KEYRING_IO_FAILED);
    }

    private static IOException sanitizePersistenceFailure(IOException failure) {
        if (failure instanceof KeyringException) {
            return failure;
        }
        return new KeyringException(Code.KEYRING_IO_FAILED);
    }

    private void destroyPoisonedStore(Throwable primaryFailure) {
        wipe(masterKey);
        wipe(nonceReservationMacKey);
        entries.clear();
        destroyed.set(true);
        try {
            ownership.close();
        } catch (IOException exception) {
            primaryFailure.addSuppressed(new KeyringException(Code.KEYRING_IO_FAILED));
        }
    }

    private void writeNonceReservation(long highWater) throws IOException, GeneralSecurityException {
        byte[] authenticated = encodeNonceReservation(storeId, noncePrefix, highWater);
        byte[] tag = null;
        byte[] image = null;
        try {
            tag = hmac(nonceReservationMacKey, authenticated);
            image = ByteBuffer.allocate(authenticated.length + tag.length).put(authenticated).put(tag).array();
            writeSidecarAtomically(nonceReservationPath, image);
        } finally {
            wipe(authenticated);
            wipe(tag);
            wipe(image);
        }
    }

    private static long readNonceReservation(Path keyring, UserPrincipal owner, byte[] expectedStoreId,
            int expectedPrefix, byte[] nonceReservationMacKey) throws IOException, GeneralSecurityException {
        Path reservation = nonceReservationPath(keyring);
        validateExistingFile(reservation, owner);
        byte[] image = readFixedImage(reservation, NONCE_RESERVATION_MAGIC.length + Integer.BYTES + UUID_BYTES
                + Integer.BYTES + Long.BYTES + NONCE_RESERVATION_TAG_BYTES);
        byte[] authenticated = Arrays.copyOf(image, image.length - NONCE_RESERVATION_TAG_BYTES);
        byte[] actualTag = Arrays.copyOfRange(image, authenticated.length, image.length);
        byte[] expectedTag = null;
        try {
            expectedTag = hmac(nonceReservationMacKey, authenticated);
            if (!MessageDigest.isEqual(actualTag, expectedTag)) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            ByteBuffer buffer = ByteBuffer.wrap(authenticated);
            byte[] magic = new byte[NONCE_RESERVATION_MAGIC.length];
            buffer.get(magic);
            byte[] storeId = new byte[UUID_BYTES];
            buffer.position(NONCE_RESERVATION_MAGIC.length + Integer.BYTES);
            buffer.get(storeId);
            int prefix = buffer.getInt();
            long highWater = buffer.getLong();
            if (!MessageDigest.isEqual(magic, NONCE_RESERVATION_MAGIC)
                    || ByteBuffer.wrap(authenticated, NONCE_RESERVATION_MAGIC.length, Integer.BYTES)
                            .getInt() != NONCE_RESERVATION_VERSION
                    || !MessageDigest.isEqual(storeId, expectedStoreId) || prefix != expectedPrefix
                    || highWater < MIN_NONCE_HIGH_WATER) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            return highWater;
        } finally {
            wipe(image);
            wipe(authenticated);
            wipe(actualTag);
            wipe(expectedTag);
        }
    }

    private static byte[] encodeNonceReservation(byte[] storeId, int prefix, long highWater) {
        return ByteBuffer
                .allocate(NONCE_RESERVATION_MAGIC.length + Integer.BYTES + UUID_BYTES + Integer.BYTES + Long.BYTES)
                .put(NONCE_RESERVATION_MAGIC).putInt(NONCE_RESERVATION_VERSION).put(storeId).putInt(prefix)
                .putLong(highWater).array();
    }

    private static byte[] hmac(byte[] key, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(input);
    }

    private void writeSidecarAtomically(Path target, byte[] image) throws IOException {
        writeAtomically(Target.NONCE_RESERVATION, target, image);
    }

    private byte[] encodeImage(Map<String, EncryptedEntry> candidate, byte[] manifestNonce, byte[] manifestCipher)
            throws IOException, KeyringException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC);
            out.writeInt(FORMAT_VERSION);
            out.write(storeId);
            out.writeByte(KDF_PBKDF2_SHA256);
            out.writeInt(iterations);
            writeFixed(out, salt, SALT_BYTES);
            out.writeInt(KEK_BYTES);
            out.writeByte(AEAD_AES_256_GCM);
            writeFixed(out, masterWrapNonce, NONCE_BYTES);
            writeBoundedBytes(out, wrappedMasterKey, MASTER_KEY_BYTES + GCM_TAG_BYTES);
            out.writeInt(candidate.size());
            for (EncryptedEntry entry : candidate.values()) {
                out.write(entry.entryId);
                out.write(entry.nonce);
                writeBoundedBytes(out, entry.ciphertext, MAX_ENTRY_CIPHERTEXT_BYTES);
                if (bytes.size() > MAX_FILE_BYTES) {
                    throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
                }
            }
            out.write(manifestNonce);
            writeBoundedBytes(out, manifestCipher, MAX_FILE_BYTES);
            out.flush();
        }
        byte[] result = bytes.toByteArray();
        if (result.length > MAX_FILE_BYTES) {
            wipe(result);
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
        return result;
    }

    private byte[] encodeManifest(Map<String, EncryptedEntry> candidate) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(MANIFEST_FORMAT_VERSION);
            out.writeInt(noncePrefix);
            out.writeLong(nonceHighWater);
            out.writeInt(candidate.size());
            for (EncryptedEntry entry : candidate.values()) {
                out.write(entry.entryId);
                out.writeInt(entry.position);
                writeString(out, entry.alias, MAX_ALIAS_BYTES);
                writeString(out, entry.algorithm, MAX_METADATA_BYTES);
                out.writeByte(entry.kind.code);
                out.writeByte(entry.encoding.code);
                out.writeByte(entry.hmacVariant.code());
                out.write(entry.nonce);
                out.writeInt(entry.ciphertext.length);
                out.write(entry.digest);
            }
        }
        return bytes.toByteArray();
    }

    @SuppressWarnings({ "PMD.NcssCount", "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace",
            "PMD.ExceptionAsFlowControl", "PMD.AvoidCatchingGenericException" })
    private static Decoded decodeImage(byte[] image, KeyringPassword password, KeyringProtection protection)
            throws IOException, GeneralSecurityException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(image))) {
            byte[] magic = readFixed(in, MAGIC.length);
            if (!MessageDigest.isEqual(MAGIC, magic)) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            int version = in.readInt();
            if (version != FORMAT_VERSION) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            byte[] storeId = readFixed(in, UUID_BYTES);
            requireCode(in.readUnsignedByte(), KDF_PBKDF2_SHA256);
            int iterations = in.readInt();
            validateIterations(iterations, protection);
            byte[] salt = readFixed(in, SALT_BYTES);
            if (in.readInt() != KEK_BYTES) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            requireCode(in.readUnsignedByte(), AEAD_AES_256_GCM);
            byte[] wrapNonce = readFixed(in, NONCE_BYTES);
            if (wrapNonce[0] != MASTER_WRAP_NONCE_DOMAIN) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            byte[] wrapped = readBoundedBytes(in, MASTER_KEY_BYTES + GCM_TAG_BYTES, MASTER_KEY_BYTES + GCM_TAG_BYTES);
            if (wrapped.length != MASTER_KEY_BYTES + GCM_TAG_BYTES) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            Header header = new Header(storeId, iterations, salt, wrapNonce, wrapped);
            byte[] kek = null;
            byte[] wrapAad = null;
            byte[] masterKey = null;
            try {
                kek = deriveKek(password, salt, iterations);
                wrapAad = masterWrapAad(header);
                try {
                    masterKey = crypt(Cipher.DECRYPT_MODE, kek, wrapNonce, wrapAad, wrapped);
                } catch (AEADBadTagException exception) {
                    throw new KeyringException(Code.KEYRING_UNLOCK_FAILED);
                }
                if (masterKey.length != MASTER_KEY_BYTES) {
                    throw new KeyringException(Code.KEYRING_UNLOCK_FAILED);
                }
            } finally {
                wipe(kek);
                wipe(wrapAad);
            }
            try {
                int count = in.readInt();
                if (count < 0 || count > MAX_ENTRY_COUNT) {
                    throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
                }
                List<EncryptedWireEntry> wireEntries = new ArrayList<>(count);
                for (int index = 0; index < count; index++) {
                    byte[] entryId = readFixed(in, UUID_BYTES);
                    byte[] nonce = readFixed(in, NONCE_BYTES);
                    byte[] ciphertext = readBoundedBytes(in, MAX_ENTRY_CIPHERTEXT_BYTES, MAX_ENTRY_CIPHERTEXT_BYTES);
                    wireEntries.add(new EncryptedWireEntry(entryId, nonce, ciphertext));
                }
                byte[] manifestNonce = readFixed(in, NONCE_BYTES);
                byte[] manifestCipher = readBoundedBytes(in, MAX_FILE_BYTES, MAX_FILE_BYTES);
                if (in.read() != -1) {
                    throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
                }
                byte[] aad = null;
                byte[] manifestPlain = null;
                try {
                    aad = manifestAad(storeId, count);
                    try {
                        manifestPlain = crypt(Cipher.DECRYPT_MODE, masterKey, manifestNonce, aad, manifestCipher);
                    } catch (AEADBadTagException exception) {
                        throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
                    }
                    Manifest manifest = decodeManifest(manifestPlain, count);
                    Map<String, EncryptedEntry> entries = bindManifest(manifest, wireEntries, manifestNonce);
                    return new Decoded(header, masterKey, manifest, entries);
                } finally {
                    wipe(aad);
                    wipe(manifestPlain);
                    wipe(manifestNonce);
                    wipe(manifestCipher);
                }
            } catch (IOException | GeneralSecurityException | RuntimeException failure) {
                wipe(masterKey);
                throw failure;
            }
        } catch (EOFException exception) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static Manifest decodeManifest(byte[] plaintext, int expectedCount) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plaintext))) {
            if (in.readInt() != MANIFEST_FORMAT_VERSION) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            int prefix = in.readInt();
            long highWater = in.readLong();
            if (highWater < MIN_NONCE_HIGH_WATER) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            int count = in.readInt();
            if (count != expectedCount) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            List<ManifestEntry> descriptors = new ArrayList<>(count);
            for (int index = 0; index < count; index++) {
                byte[] entryId = readFixed(in, UUID_BYTES);
                int position = in.readInt();
                String alias = readString(in, MAX_ALIAS_BYTES);
                String algorithm = readString(in, MAX_METADATA_BYTES);
                Kind kind = Kind.fromCode(in.readUnsignedByte());
                Encoding encoding = Encoding.fromCode(in.readUnsignedByte());
                KeyringImportRegistry.HmacVariant hmacVariant = KeyringImportRegistry.HmacVariant
                        .fromCode(in.readUnsignedByte());
                byte[] nonce = readFixed(in, NONCE_BYTES);
                int length = in.readInt();
                if (length < GCM_TAG_BYTES || length > MAX_ENTRY_CIPHERTEXT_BYTES) {
                    throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
                }
                byte[] digest = readFixed(in, SHA256_BYTES);
                descriptors.add(new ManifestEntry(entryId, position, alias, algorithm, kind, encoding, hmacVariant,
                        nonce, length, digest));
            }
            if (in.read() != -1) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            return new Manifest(prefix, highWater, descriptors);
        } catch (EOFException exception) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static Map<String, EncryptedEntry> bindManifest(Manifest manifest, List<EncryptedWireEntry> wireEntries,
            byte[] manifestNonce) throws KeyringException {
        if (manifest.entries.size() != wireEntries.size()) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
        Set<String> aliases = new HashSet<>();
        Set<UUID> ids = new HashSet<>();
        Set<Nonce> nonces = new HashSet<>();
        validateNonce(manifestNonce, manifest.noncePrefix, manifest.highWater);
        nonces.add(new Nonce(manifestNonce));
        Map<String, EncryptedEntry> result = new LinkedHashMap<>();
        for (int index = 0; index < wireEntries.size(); index++) {
            ManifestEntry descriptor = manifest.entries.get(index);
            EncryptedWireEntry wire = wireEntries.get(index);
            if (descriptor.position != index || !MessageDigest.isEqual(descriptor.entryId, wire.entryId)
                    || !MessageDigest.isEqual(descriptor.nonce, wire.nonce)
                    || descriptor.ciphertextLength != wire.ciphertext.length
                    || !MessageDigest.isEqual(descriptor.digest, digest(wire.ciphertext))) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            validateNonce(wire.nonce, manifest.noncePrefix, manifest.highWater);
            if (!aliases.add(descriptor.alias) || !ids.add(uuid(descriptor.entryId))
                    || !nonces.add(new Nonce(wire.nonce))) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            KeyringImportRegistry.validateMapping(descriptor.algorithm, descriptor.kind, descriptor.encoding,
                    descriptor.hmacVariant);
            result.put(descriptor.alias,
                    new EncryptedEntry(wire.entryId, index, descriptor.alias, descriptor.algorithm, descriptor.kind,
                            descriptor.encoding, descriptor.hmacVariant, wire.nonce, wire.ciphertext,
                            descriptor.digest));
        }
        return result;
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static byte[] encodeEntryPlaintext(String alias, String algorithm, Kind kind, Encoding encoding,
            KeyringImportRegistry.HmacVariant hmacVariant, byte[] encoded) throws KeyringException {
        if (encoded.length <= 0 || encoded.length > MAX_ENTRY_CIPHERTEXT_BYTES - GCM_TAG_BYTES) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
        byte[] aliasBytes = alias.getBytes(StandardCharsets.UTF_8);
        byte[] algorithmBytes = algorithm.getBytes(StandardCharsets.UTF_8);
        try {
            int size = Math.addExact(Integer.BYTES + 3, Math.addExact(lengthPrefixedSize(aliasBytes),
                    Math.addExact(lengthPrefixedSize(algorithmBytes), lengthPrefixedSize(encoded))));
            if (size > MAX_ENTRY_CIPHERTEXT_BYTES - GCM_TAG_BYTES) {
                throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
            }
            ByteBuffer buffer = ByteBuffer.allocate(size);
            buffer.putInt(ENTRY_FORMAT_VERSION);
            putLengthPrefixed(buffer, aliasBytes);
            putLengthPrefixed(buffer, algorithmBytes);
            buffer.put((byte) kind.code);
            buffer.put((byte) encoding.code);
            buffer.put((byte) hmacVariant.code());
            putLengthPrefixed(buffer, encoded);
            return buffer.array();
        } catch (ArithmeticException exception) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        } finally {
            wipe(aliasBytes);
            wipe(algorithmBytes);
        }
    }

    private static int lengthPrefixedSize(byte[] value) {
        return Math.addExact(Integer.BYTES, value.length);
    }

    private static void putLengthPrefixed(ByteBuffer buffer, byte[] value) {
        buffer.putInt(value.length);
        buffer.put(value);
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static EntryPlain decodeEntryPlaintext(byte[] plaintext) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plaintext))) {
            if (in.readInt() != ENTRY_FORMAT_VERSION) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            String alias = readString(in, MAX_ALIAS_BYTES);
            String algorithm = readString(in, MAX_METADATA_BYTES);
            Kind kind = Kind.fromCode(in.readUnsignedByte());
            Encoding encoding = Encoding.fromCode(in.readUnsignedByte());
            KeyringImportRegistry.HmacVariant hmacVariant = KeyringImportRegistry.HmacVariant
                    .fromCode(in.readUnsignedByte());
            byte[] encoded = readBoundedBytes(in, MAX_ENTRY_CIPHERTEXT_BYTES - GCM_TAG_BYTES,
                    MAX_ENTRY_CIPHERTEXT_BYTES - GCM_TAG_BYTES);
            if (in.read() != -1) {
                wipe(encoded);
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            return new EntryPlain(alias, algorithm, kind, encoding, hmacVariant, encoded);
        } catch (EOFException exception) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    private static void validateEntryBinding(EncryptedEntry entry, EntryPlain decoded) throws KeyringException {
        if (!entry.alias.equals(decoded.alias) || !entry.algorithm.equals(decoded.algorithm)
                || entry.kind != decoded.kind || entry.encoding != decoded.encoding
                || entry.hmacVariant != decoded.hmacVariant) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    private static byte[] masterWrapAad(Header header) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC);
            out.writeInt(FORMAT_VERSION);
            out.write(header.storeId);
            out.writeByte(KDF_PBKDF2_SHA256);
            out.writeInt(header.iterations);
            out.write(header.salt);
            out.writeInt(KEK_BYTES);
            out.writeByte(AEAD_AES_256_GCM);
        }
        return bytes.toByteArray();
    }

    private byte[] entryAad(byte[] entryId, int position) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC);
            out.writeInt(FORMAT_VERSION);
            out.write(storeId);
            out.write(entryId);
            out.writeInt(position);
            out.writeInt(ENTRY_FORMAT_VERSION);
        }
        return bytes.toByteArray();
    }

    private byte[] manifestAad(int count) throws IOException {
        return manifestAad(storeId, count);
    }

    private static byte[] manifestAad(byte[] storeId, int count) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC);
            out.writeInt(FORMAT_VERSION);
            out.write(storeId);
            out.writeInt(MANIFEST_FORMAT_VERSION);
            out.writeInt(count);
        }
        return bytes.toByteArray();
    }

    private byte[] nextNonce() throws IOException, GeneralSecurityException {
        if (nonceHighWater == Long.MAX_VALUE) {
            poisoned = true;
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
        long reserved = nonceHighWater + 1;
        writeNonceReservation(reserved);
        nonceHighWater = reserved;
        ByteBuffer buffer = ByteBuffer.allocate(NONCE_BYTES);
        buffer.put(ENTRY_NONCE_DOMAIN);
        putThreeBytePrefix(buffer, noncePrefix);
        buffer.putLong(nonceHighWater);
        return buffer.array();
    }

    private static void validateNonce(byte[] nonce, int prefix, long highWater) throws KeyringException {
        if (nonce.length != NONCE_BYTES) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
        ByteBuffer buffer = ByteBuffer.wrap(nonce);
        if (buffer.get() != ENTRY_NONCE_DOMAIN) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
        int actualPrefix = readThreeBytePrefix(buffer);
        long counter = buffer.getLong();
        if (actualPrefix != prefix || counter <= 0 || counter > highWater) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    private static int randomPrefix(KeyringRandomBytes random) {
        byte[] prefix = new byte[3];
        try {
            random.nextBytes(prefix);
            return (Byte.toUnsignedInt(prefix[0]) << 16) | (Byte.toUnsignedInt(prefix[1]) << 8)
                    | Byte.toUnsignedInt(prefix[2]);
        } finally {
            wipe(prefix);
        }
    }

    private static void fillMasterWrapNonce(KeyringRandomBytes random, byte[] nonce) {
        byte[] randomPart = new byte[NONCE_BYTES - 1];
        try {
            random.nextBytes(randomPart);
            nonce[0] = MASTER_WRAP_NONCE_DOMAIN;
            System.arraycopy(randomPart, 0, nonce, 1, randomPart.length);
        } finally {
            wipe(randomPart);
        }
    }

    private static void putThreeBytePrefix(ByteBuffer buffer, int prefix) {
        buffer.put((byte) (prefix >>> 16));
        buffer.put((byte) (prefix >>> 8));
        buffer.put((byte) prefix);
    }

    private static int readThreeBytePrefix(ByteBuffer buffer) {
        return (Byte.toUnsignedInt(buffer.get()) << 16) | (Byte.toUnsignedInt(buffer.get()) << 8)
                | Byte.toUnsignedInt(buffer.get());
    }

    private static byte[] deriveKek(KeyringPassword password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        char[] chars = password.copy();
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, KEK_BYTES * Byte.SIZE);
        Arrays.fill(chars, '\0');
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static byte[] digest(byte[] value) throws KeyringException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException exception) {
            throw new KeyringException(Code.KEYRING_IO_FAILED);
        }
    }

    private static void validateIterations(int iterations, KeyringProtection protection) throws KeyringException {
        if (iterations < KeyringProtection.CREATION_ITERATIONS || iterations > KeyringProtection.MAX_DECODED_ITERATIONS
                || iterations > protection.operationalIterationMaximum()) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
    }

    private static boolean matchesFormat(String actual, Encoding encoding) {
        return switch (encoding) {
            case X509 -> "X.509".equalsIgnoreCase(actual);
            case PKCS8 -> "PKCS#8".equalsIgnoreCase(actual);
            case RAW -> "RAW".equalsIgnoreCase(actual);
        };
    }

    private static int positionFor(Map<String, EncryptedEntry> values, String alias) {
        int index = 0;
        for (String current : values.keySet()) {
            if (current.equals(alias)) {
                return index;
            }
            index++;
        }
        return values.size();
    }

    private static String withPublicSuffix(String alias) {
        requireAlias(alias);
        return alias.endsWith(SUFFIX_PUBLIC) ? alias : alias + SUFFIX_PUBLIC;
    }

    private static String withPrivateSuffix(String alias) {
        requireAlias(alias);
        return alias.endsWith(SUFFIX_PRIVATE) ? alias : alias + SUFFIX_PRIVATE;
    }

    private static String stripKnownSuffix(String alias) {
        if (alias.endsWith(SUFFIX_PUBLIC)) {
            return alias.substring(0, alias.length() - SUFFIX_PUBLIC.length());
        }
        if (alias.endsWith(SUFFIX_PRIVATE)) {
            return alias.substring(0, alias.length() - SUFFIX_PRIVATE.length());
        }
        return alias;
    }

    private static void requireAlias(String alias) {
        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException("alias must not be blank");
        }
    }

    private static void validateString(String value, int maximumBytes) throws KeyringException {
        if (value == null || value.isBlank() || value.getBytes(StandardCharsets.UTF_8).length > maximumBytes) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
    }

    private void ensureOpen() throws KeyringException {
        if (destroyed.get() || poisoned) {
            throw new KeyringException(Code.KEYRING_CLOSED);
        }
    }

    private void ensureOpenUnchecked() {
        if (destroyed.get() || poisoned) {
            throw new IllegalStateException(Code.KEYRING_CLOSED.name());
        }
    }

    private static void writeFixed(DataOutputStream out, byte[] value, int expected)
            throws IOException, KeyringException {
        if (value.length != expected) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
        out.write(value);
    }

    private static void writeBoundedBytes(DataOutputStream out, byte[] value, int maximum)
            throws IOException, KeyringException {
        if (value.length < 0 || value.length > maximum) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
        out.writeInt(value.length);
        out.write(value);
    }

    private static byte[] readFixed(DataInputStream in, int length) throws IOException {
        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }

    private static byte[] readBoundedBytes(DataInputStream in, int maximum, int exactOrMaximum) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > maximum || exactOrMaximum < maximum && length != exactOrMaximum) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }

    private static void writeString(DataOutputStream out, String value, int maximum)
            throws IOException, KeyringException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            writeBoundedBytes(out, encoded, maximum);
        } finally {
            wipe(encoded);
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static String readString(DataInputStream in, int maximum) throws IOException {
        byte[] encoded = readBoundedBytes(in, maximum, maximum);
        try {
            try {
                return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(encoded)).toString();
            } catch (CharacterCodingException exception) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
        } finally {
            wipe(encoded);
        }
    }

    private static void requireCode(int actual, int expected) throws KeyringException {
        if (actual != expected) {
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
    }

    private static UUID uuid(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static Path nonceReservationPath(Path keyring) {
        return keyring.resolveSibling(keyring.getFileName() + ".nonce");
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static byte[] readStoreImage(Path source) throws IOException {
        try (FileChannel channel = FileChannel.open(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            long size = channel.size();
            if (size <= 0 || size > MAX_FILE_BYTES) {
                throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
            }
            byte[] image = new byte[Math.toIntExact(size)];
            ByteBuffer target = ByteBuffer.wrap(image);
            while (target.hasRemaining()) {
                if (channel.read(target) < 0) {
                    wipe(image);
                    throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
                }
            }
            ByteBuffer trailing = ByteBuffer.allocate(1);
            if (channel.read(trailing) >= 0) {
                wipe(image);
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            return image;
        } catch (ArithmeticException exception) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
    }

    private static byte[] readFixedImage(Path source, int expected) throws IOException {
        byte[] image = readStoreImage(source);
        if (image.length != expected) {
            wipe(image);
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
        return image;
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static Path securePath(Path requested, boolean createParent) throws IOException {
        Objects.requireNonNull(requested, "path must not be null");
        Path absolute = requested.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent == null) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        if (!Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
            if (!createParent) {
                throw new KeyringException(Code.KEYRING_IO_FAILED);
            }
            try {
                Files.createDirectories(parent, DIRECTORY_ATTRIBUTE);
            } catch (UnsupportedOperationException exception) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        }
        if (Files.isSymbolicLink(parent)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        FileStore store = Files.getFileStore(parent);
        if (!store.supportsFileAttributeView(PosixFileAttributeView.class)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        validateOwnerOnly(parent, true);
        if (Files.isSymbolicLink(absolute)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        return absolute;
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static void validateExistingFile(Path file, UserPrincipal expectedOwner) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        validateOwnerOnly(file, false);
        PosixFileAttributes attributes = Files.readAttributes(file, PosixFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.owner().equals(expectedOwner)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        try {
            Object links = Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
            if (!(links instanceof Number number) || number.longValue() != 1L) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        } catch (UnsupportedOperationException exception) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
    }

    private static void validateOwnerOnly(Path path, boolean directory) throws IOException {
        PosixFileAttributes attributes = Files.readAttributes(path, PosixFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        Set<PosixFilePermission> expected = directory ? DIRECTORY_PERMISSIONS : FILE_PERMISSIONS;
        if (!attributes.permissions().equals(expected)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static void destroyTemporarySpec(zeroecho.core.spec.AlgorithmKeySpec spec, Throwable primary)
            throws GeneralSecurityException {
        if (!(spec instanceof Destroyable destroyable)) {
            return;
        }
        try {
            if (!destroyable.isDestroyed()) {
                destroyable.destroy();
            }
        } catch (DestroyFailedException failure) {
            if (primary != null) {
                primary.addSuppressed(failure);
            } else {
                throw new GeneralSecurityException("Temporary key specification destruction failed");
            }
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record Header(byte[] storeId, int iterations, byte[] salt, byte[] masterWrapNonce,
            byte[] wrappedMasterKey) {
    }

    private record Manifest(int noncePrefix, long highWater, List<ManifestEntry> entries) {
    }

    private record ManifestEntry(byte[] entryId, int position, String alias, String algorithm, Kind kind,
            Encoding encoding, KeyringImportRegistry.HmacVariant hmacVariant, byte[] nonce, int ciphertextLength,
            byte[] digest) {
    }

    private record EncryptedWireEntry(byte[] entryId, byte[] nonce, byte[] ciphertext) {
    }

    /** Immutable encrypted entry retained while the store is open. */
    private static final class EncryptedEntry {
        private final byte[] entryId;
        private final int position;
        private final String alias;
        private final String algorithm;
        private final Kind kind;
        private final Encoding encoding;
        private final KeyringImportRegistry.HmacVariant hmacVariant;
        private final byte[] nonce;
        private final byte[] ciphertext;
        private final byte[] digest;

        private EncryptedEntry(byte[] entryId, int position, String alias, String algorithm, Kind kind,
                Encoding encoding, KeyringImportRegistry.HmacVariant hmacVariant, byte[] nonce, byte[] ciphertext,
                byte[] digest) {
            this.entryId = entryId.clone();
            this.position = position;
            this.alias = alias;
            this.algorithm = algorithm;
            this.kind = kind;
            this.encoding = encoding;
            this.hmacVariant = hmacVariant;
            this.nonce = nonce.clone();
            this.ciphertext = ciphertext.clone();
            this.digest = digest.clone();
        }
    }

    private record EntryPlain(String alias, String algorithm, Kind kind, Encoding encoding,
            KeyringImportRegistry.HmacVariant hmacVariant, byte[] encoded) {
    }

    private record Imported(String algorithm, Key key) {
    }

    private record Decoded(Header header, byte[] masterKey, Manifest manifest, Map<String, EncryptedEntry> entries) {
    }

    /** Value-semantic nonce used only for duplicate detection. */
    private static final class Nonce {
        private final byte[] bytes;

        private Nonce(byte[] bytes) {
            this.bytes = bytes.clone();
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Nonce nonce && Arrays.equals(bytes, nonce.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }
    }

    /** Process-lifetime ownership of the sibling lock file. */
    private static final class Ownership implements AutoCloseable {
        private final FileChannel channel;
        private final FileLock lock;
        private final UserPrincipal owner;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Ownership(FileChannel channel, FileLock lock, UserPrincipal owner) {
            this.channel = channel;
            this.lock = lock;
            this.owner = owner;
        }

        @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.ExceptionAsFlowControl",
                "PMD.AvoidCatchingGenericException" })
        /* default */ static Ownership acquire(Path keyring) throws IOException {
            Path lockPath = keyring.resolveSibling(keyring.getFileName() + ".lock");
            try {
                UserPrincipal expectedOwner = Files
                        .readAttributes(lockPath.getParent(), PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                        .owner();
                if (!Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)) {
                    try {
                        Files.createFile(lockPath, FILE_ATTRIBUTE);
                    } catch (java.nio.file.FileAlreadyExistsException ignored) {
                        // A concurrent creator won; validate the existing file below.
                    }
                }
                validateExistingFile(lockPath, expectedOwner);
                FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                try {
                    FileLock lock;
                    try {
                        lock = channel.tryLock();
                    } catch (OverlappingFileLockException exception) {
                        lock = null;
                    }
                    if (lock == null) {
                        channel.close();
                        throw new KeyringException(Code.KEYRING_ALREADY_OPEN);
                    }
                    return new Ownership(channel, lock, expectedOwner);
                } catch (IOException | RuntimeException exception) {
                    if (channel.isOpen()) {
                        channel.close();
                    }
                    throw exception;
                }
            } catch (KeyringException exception) {
                throw exception;
            } catch (IOException exception) {
                throw new KeyringException(Code.KEYRING_IO_FAILED);
            }
        }

        private UserPrincipal owner() {
            return owner;
        }

        @Override
        public void close() throws IOException {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            IOException failure = null;
            try {
                lock.release();
            } catch (IOException exception) {
                failure = exception;
            }
            try {
                channel.close();
            } catch (IOException exception) {
                if (failure == null) {
                    failure = exception;
                } else {
                    failure.addSuppressed(exception);
                }
            }
            if (failure != null) {
                throw new KeyringException(Code.KEYRING_IO_FAILED);
            }
        }
    }
}
