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
package zeroecho.core.storage;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Human-editable keyring persisted in a simple UTF-8 text format.
 *
 * <h2>File format</h2> Each file starts with a magic header followed by one or
 * more entries. Lines starting with the hash character are comments. A blank
 * line terminates the current entry. Keys belonging to the key-spec payload are
 * prefixed with "s." to avoid collisions with top-level metadata.
 *
 * <pre>{@code
 * # KeyringStore v1
 * &#64;entry
 * alias=my-rsa
 * algorithm=RSA
 * kind=public|private|secret
 * spec=zeroecho.core.alg.rsa.RsaPublicKeySpec
 * s.x509B64=MIIBIjANBgkqh...
 * s.note=optional
 *
 * &#64;entry
 * ...
 * }</pre>
 *
 * <h2>Reading and writing</h2> Use {@link #save(java.nio.file.Path)} to write
 * the keyring to disk and {@link #load(ZeroEchoSession, java.nio.file.Path)} to
 * read it back.
 * The loader tolerates the presence of the header and comment lines but
 * requires the magic header for the v1 format.
 *
 * <h2>Spec marshaling</h2> A record holds a fully qualified spec class name and
 * a key-value payload. The store relies on a pair of static utility methods
 * that must be implemented by each spec type:
 * <ul>
 * <li>{@code static PairSeq marshal(SpecType spec)}</li>
 * <li>{@code static SpecType unmarshal(PairSeq pairs)}</li>
 * </ul>
 * These are discovered and invoked via reflection. See
 * {@link #marshalSpec(AlgorithmKeySpec)} and
 * {@link #unmarshalSpec(Class, PairSeq)} for details.
 *
 * <h2>Basic usage</h2> <pre>{@code
 * ZeroEchoSession session = new ZeroEchoSession();
 * KeyringStore ks = new KeyringStore(session);
 * ks.putPublic("site-signing", "Ed25519", myEd25519PublicSpec);
 * ks.putPrivate("site-signing", "Ed25519", myEd25519PrivateSpec);
 * ks.save(Path.of("keyring.txt"));
 *
 * KeyringStore reloaded = KeyringStore.load(session, Path.of("keyring.txt"));
 * PublicKey pub = reloaded.getPublic("site-signing");
 * }</pre>
 */
public final class KeyringStore { // NOPMD

    private static final String MAGIC_HEADER = "# KeyringStore v1";
    private static final String ENTRY_MARKER = "@entry";
    private static final String PREFIX_SPEC = "s."; // marks spec payload keys

    /** Suffix used for persisted public key aliases. */
    private static final String SUFFIX_PUBLIC = ".pub";

    /** Suffix used for persisted private key aliases. */
    private static final String SUFFIX_PRIVATE = ".priv";

    private final Map<String, Record> byAlias = new LinkedHashMap<>();
    private final ZeroEchoSession session;

    /**
     * Creates an empty keyring bound to a runtime session.
     *
     * @param session explicit runtime configuration
     * @throws NullPointerException if {@code session} is {@code null}
     */
    public KeyringStore(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Immutable entry in a {@link KeyringStore}.
     *
     * <p>
     * Each record represents one alias-bound key with its algorithm metadata and
     * serialized specification payload. Records are immutable value objects and
     * provide structural equality and stable hashing.
     * </p>
     *
     * @param alias       alias that identifies the entry. It must be unique within
     *                    the store.
     * @param algorithm   algorithm identifier such as {@code "RSA"},
     *                    {@code "Ed25519"}, {@code "HMAC"}, or {@code "AES"}. The
     *                    value is passed to the crypto catalog when materializing
     *                    keys.
     * @param kind        type of key stored in this record
     * @param specClass   fully qualified class name of the key-spec used to
     *                    materialize the key
     * @param specPayload specification payload represented as alternating key and
     *                    value pairs. Keys appear in the file with the {@code "s."}
     *                    prefix but are stored here without the prefix.
     */
    public record Record(String alias, String algorithm, Kind kind, String specClass, PairSeq specPayload) {

        /**
         * Enumeration of supported key kinds.
         *
         * <ul>
         * <li>{@link #PUBLIC_KEY} - public key material</li>
         * <li>{@link #PRIVATE_KEY} - private key material</li>
         * <li>{@link #SECRET_KEY} - symmetric key material</li>
         * </ul>
         */
        public enum Kind {
            PUBLIC_KEY, PRIVATE_KEY, SECRET_KEY
        }
    }

    /**
     * Adds or replaces a public-key entry under the given alias.
     *
     * @param alias       the unique alias to store under; must not be null or blank
     * @param algorithmId algorithm identifier understood by the crypto catalog
     * @param importSpec  the algorithm-specific spec carrying public key material
     * @throws IllegalArgumentException if any argument is invalid
     */
    public void putPublic(String alias, String algorithmId, AlgorithmKeySpec importSpec) {
        put(withPublicSuffix(alias), algorithmId, Record.Kind.PUBLIC_KEY, importSpec);
    }

    /**
     * Adds or replaces a private-key entry under the given alias.
     *
     * @param alias       the unique alias to store under; must not be null or blank
     * @param algorithmId algorithm identifier understood by the crypto catalog
     * @param importSpec  the algorithm-specific spec carrying private key material
     * @throws IllegalArgumentException if any argument is invalid
     */
    public void putPrivate(String alias, String algorithmId, AlgorithmKeySpec importSpec) {
        put(withPrivateSuffix(alias), algorithmId, Record.Kind.PRIVATE_KEY, importSpec);
    }

    /**
     * Adds or replaces a secret-key entry under the given alias.
     *
     * @param alias       the unique alias to store under; must not be null or blank
     * @param algorithmId algorithm identifier understood by the crypto catalog
     * @param importSpec  the algorithm-specific spec carrying secret key material
     * @throws IllegalArgumentException if any argument is invalid
     */
    public void putSecret(String alias, String algorithmId, AlgorithmKeySpec importSpec) {
        put(alias, algorithmId, Record.Kind.SECRET_KEY, importSpec);
    }

    /**
     * Checks whether an entry with the given alias exists.
     *
     * @param alias the alias to test
     * @return true if an entry exists for the alias, false otherwise
     */
    public boolean contains(String alias) {
        if (alias == null) {
            return false;
        }
        if (byAlias.containsKey(alias)) {
            return true;
        }
        return byAlias.containsKey(withPublicSuffix(alias)) || byAlias.containsKey(withPrivateSuffix(alias));
    }

    /**
     * Returns all aliases currently present in insertion order.
     *
     * @return a new list of aliases; the returned list is mutable but independent
     */
    public List<String> aliases() {
        List<String> out = new ArrayList<>(byAlias.size());
        for (String a : byAlias.keySet()) {
            out.add(stripKnownSuffix(a));
        }
        return out;
    }

    /**
     * PublicWithId pairs the algorithm identifier with a resolved public key.
     *
     * <h2>Usage</h2> <pre>{@code
     * KeyringStore ks = KeyringStore.load(session, path);
     * KeyringStore.PublicWithId r = ks.getPublicWithId("alice");
     * String algId = r.algorithm();
     * PublicKey pub = r.key();
     * }</pre>
     */
    public record PublicWithId(String algorithm, PublicKey key) {
    }

    /**
     * PrivateWithId pairs the algorithm identifier with a resolved private key.
     *
     * <h2>Usage</h2> <pre>{@code
     * KeyringStore ks = KeyringStore.load(session, path);
     * KeyringStore.PrivateWithId r = ks.getPrivateWithId("alice");
     * String algId = r.algorithm();
     * PrivateKey prv = r.key();
     * }</pre>
     */
    public record PrivateWithId(String algorithm, PrivateKey key) {
    }

    /**
     * SecretWithId pairs the algorithm identifier with a resolved secret key.
     *
     * <h2>Usage</h2> <pre>{@code
     * KeyringStore ks = KeyringStore.load(session, path);
     * KeyringStore.SecretWithId r = ks.getSecretWithId("hmac-key");
     * String algId = r.algorithm();
     * SecretKey sk = r.key();
     * }</pre>
     */
    public record SecretWithId(String algorithm, SecretKey key) {
    }

    /**
     * Resolves a public key together with its algorithm identifier.
     *
     * <p>
     * The method mirrors {@link #getPublic(String)} but returns the algorithm id
     * stored in the record along with the materialized key so that callers can
     * route to algorithm-specific processing without asking the user to repeat it.
     * </p>
     *
     * @param alias the alias of a {@link Record.Kind#PUBLIC_KEY} entry
     * @return a pair containing the algorithm id and the resolved public key
     * @throws GeneralSecurityException if spec unmarshaling or key construction
     *                                  fails
     * @throws IllegalArgumentException if alias is missing or not a public key
     */
    public PublicWithId getPublicWithId(String alias) throws GeneralSecurityException {
        Record r = require(withPublicSuffix(alias), Record.Kind.PUBLIC_KEY);
        AlgorithmKeySpec spec = unmarshalRecord(r);
        PublicKey key = session.keyBuilders().asymmetric().importPublic(r.algorithm, spec);
        return new PublicWithId(r.algorithm, key);
    }

    /**
     * Resolves a private key together with its algorithm identifier.
     *
     * @param alias the alias of a {@link Record.Kind#PRIVATE_KEY} entry
     * @return a pair containing the algorithm id and the resolved private key
     * @throws GeneralSecurityException if spec unmarshaling or key construction
     *                                  fails
     * @throws IllegalArgumentException if alias is missing or not a private key
     */
    public PrivateWithId getPrivateWithId(String alias) throws GeneralSecurityException {
        Record r = require(withPrivateSuffix(alias), Record.Kind.PRIVATE_KEY);
        AlgorithmKeySpec spec = unmarshalRecord(r);
        Throwable failure = null;
        try {
            PrivateKey key = session.keyBuilders().asymmetric().importPrivate(r.algorithm, spec);
            return new PrivateWithId(r.algorithm, key);
        } catch (GeneralSecurityException | RuntimeException | Error exception) { // NOPMD - retain primary failure
            failure = exception;
            throw exception;
        } finally {
            destroyTemporarySpec(spec, failure);
        }
    }

    /**
     * Resolves a secret key together with its algorithm identifier.
     *
     * @param alias the alias of a {@link Record.Kind#SECRET_KEY} entry
     * @return a pair containing the algorithm id and the resolved secret key
     * @throws GeneralSecurityException if spec unmarshaling or key construction
     *                                  fails
     * @throws IllegalArgumentException if alias is missing or not a secret key
     */
    public SecretWithId getSecretWithId(String alias) throws GeneralSecurityException {
        Record r = require(alias, Record.Kind.SECRET_KEY);
        AlgorithmKeySpec spec = unmarshalRecord(r);
        Throwable failure = null;
        try {
            SecretKey key = session.keyBuilders().symmetric().importKey(r.algorithm, spec);
            return new SecretWithId(r.algorithm, key);
        } catch (GeneralSecurityException | RuntimeException | Error exception) { // NOPMD - retain primary failure
            failure = exception;
            throw exception;
        } finally {
            destroyTemporarySpec(spec, failure);
        }
    }

    /**
     * Resolves the public key bound to the alias.
     *
     * <p>
     * The stored spec class is loaded and unmarshaled via
     * {@link #unmarshalSpec(Class, PairSeq)}, and the key is materialized via the
     * crypto catalog.
     * </p>
     *
     * @param alias the alias of a {@link Record.Kind#PUBLIC_KEY} entry
     * @return a public key instance created from the stored spec
     * @throws GeneralSecurityException if spec unmarshaling or key construction
     *                                  fails
     * @throws IllegalArgumentException if the alias is missing or the entry is not
     *                                  a public key
     */
    public PublicKey getPublic(String alias) throws GeneralSecurityException {
        Record r = require(withPublicSuffix(alias), Record.Kind.PUBLIC_KEY);
        AlgorithmKeySpec spec = unmarshalRecord(r);
        return session.keyBuilders().asymmetric().importPublic(r.algorithm, spec);
    }

    /**
     * Resolves the private key bound to the alias.
     *
     * @param alias the alias of a {@link Record.Kind#PRIVATE_KEY} entry
     * @return a private key instance created from the stored spec
     * @throws GeneralSecurityException if spec unmarshaling or key construction
     *                                  fails
     * @throws IllegalArgumentException if the alias is missing or the entry is not
     *                                  a private key
     */
    public PrivateKey getPrivate(String alias) throws GeneralSecurityException {
        Record r = require(withPrivateSuffix(alias), Record.Kind.PRIVATE_KEY);
        AlgorithmKeySpec spec = unmarshalRecord(r);
        Throwable failure = null;
        try {
            return session.keyBuilders().asymmetric().importPrivate(r.algorithm, spec);
        } catch (GeneralSecurityException | RuntimeException | Error exception) { // NOPMD - retain primary failure
            failure = exception;
            throw exception;
        } finally {
            destroyTemporarySpec(spec, failure);
        }
    }

    private static String withPublicSuffix(String baseAlias) {
        if (baseAlias == null || baseAlias.isBlank()) {
            throw new IllegalArgumentException("alias");
        }
        if (baseAlias.endsWith(SUFFIX_PUBLIC)) {
            return baseAlias;
        }
        return baseAlias + SUFFIX_PUBLIC;
    }

    private static String withPrivateSuffix(String baseAlias) {
        if (baseAlias == null || baseAlias.isBlank()) {
            throw new IllegalArgumentException("alias");
        }
        if (baseAlias.endsWith(SUFFIX_PRIVATE)) {
            return baseAlias;
        }
        return baseAlias + SUFFIX_PRIVATE;
    }

    private static String stripKnownSuffix(String alias) {
        if (alias == null) {
            return null;
        }
        if (alias.endsWith(SUFFIX_PUBLIC)) {
            return alias.substring(0, alias.length() - SUFFIX_PUBLIC.length());
        }
        if (alias.endsWith(SUFFIX_PRIVATE)) {
            return alias.substring(0, alias.length() - SUFFIX_PRIVATE.length());
        }
        return alias;
    }

    /**
     * Resolves the secret key bound to the alias.
     *
     * @param alias the alias of a {@link Record.Kind#SECRET_KEY} entry
     * @return a secret key instance created from the stored spec
     * @throws GeneralSecurityException
     * @throws IllegalArgumentException if the alias is missing or the entry is not
     *                                  a secret key
     * @throws GeneralSecurityException if spec unmarshaling or key construction
     *                                  fails
     */
    public SecretKey getSecret(String alias) throws GeneralSecurityException {
        Record r = require(alias, Record.Kind.SECRET_KEY);
        AlgorithmKeySpec spec = unmarshalRecord(r);
        Throwable failure = null;
        try {
            return session.keyBuilders().symmetric().importKey(r.algorithm, spec);
        } catch (GeneralSecurityException | RuntimeException | Error exception) { // NOPMD - retain primary failure
            failure = exception;
            throw exception;
        } finally {
            destroyTemporarySpec(spec, failure);
        }
    }

    /**
     * Saves the entire keyring to a UTF-8 text file.
     *
     * @param path destination path
     * @throws IOException if writing fails
     */
    public void save(Path path) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writeAll(w, byAlias.values());
        }
    }

    /**
     * Loads a keyring from a UTF-8 text file.
     *
     * @param session explicit runtime configuration
     * @param path source path
     * @return a new store populated with entries from the file
     * @throws IOException if reading fails or the format is not supported
     */
    public static KeyringStore load(ZeroEchoSession session, Path path) throws IOException {
        try (BufferedReader r = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            List<Record> recs = readAll(r, /* requireHeader */ true);
            KeyringStore store = new KeyringStore(session);
            recs.forEach(rec -> store.byAlias.put(rec.alias, rec));
            return store;
        }
    }

    /**
     * Exports the specified aliases as a versioned, line-oriented text snippet.
     *
     * @param aliases aliases to export; each alias must exist in this store
     * @return UTF-8 text beginning with the magic header
     * @throws IllegalArgumentException if an alias is not present
     */
    public String exportText(Collection<String> aliases) {
        StringWriter out = new StringWriter(256);
        List<Record> recs = new ArrayList<>(aliases.size());
        for (String a : aliases) {
            Record r = byAlias.get(a);
            if (r == null) {
                throw new IllegalArgumentException("Missing alias: " + a);
            }
            recs.add(r);
        }
        try {
            writeAll(out, recs);
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
        return out.toString();
    }

    /**
     * Imports a versioned, line-oriented snippet into this store.
     *
     * @param text      snippet text
     * @param overwrite whether collisions are allowed
     * @throws IOException              if the header is missing/unsupported or the
     *                                  body is malformed
     * @throws IllegalArgumentException if {@code overwrite} is false and a
     *                                  collision occurs
     */
    public void importText(String text, boolean overwrite) throws IOException {
        if (text == null) {
            throw new IOException("Snippet is null");
        }
        try (BufferedReader r = new BufferedReader(new StringReader(text))) {
            List<Record> recs = readAll(r, /* requireHeader */ true);
            for (Record rec : recs) {
                if (!overwrite && byAlias.containsKey(rec.alias)) {
                    throw new IllegalArgumentException("Alias already exists: " + rec.alias);
                }
                byAlias.put(rec.alias, rec);
            }
        }
    }

    // ---------------------------------------------------------------------
    // Shared IO helpers (used by save/load and export/import)
    // ---------------------------------------------------------------------

    /**
     * Writes the magic header and all records to {@code w}.
     */
    private static void writeAll(Writer w, Collection<Record> records) throws IOException {
        w.write(MAGIC_HEADER);
        w.write('\n');
        for (Record r : records) {
            writeRecord(w, r);
        }
    }

    /**
     * Writes a single record in the canonical line-oriented format.
     */
    private static void writeRecord(Writer w, Record r) throws IOException {
        w.write(ENTRY_MARKER);
        w.write('\n');
        w.write("alias=");
        w.write(r.alias);
        w.write('\n');
        w.write("algorithm=");
        w.write(r.algorithm);
        w.write('\n');
        w.write("kind=");
        w.write(r.kind.name());
        w.write('\n');
        w.write("spec=");
        w.write(r.specClass);
        w.write('\n');

        PairSeq.Cursor c = r.specPayload.cursor();
        while (c.next()) {
            w.write(PREFIX_SPEC);
            w.write(c.key());
            w.write('=');
            w.write(c.value());
            w.write('\n');
        }
        w.write('\n'); // end of entry
    }

    /**
     * Reads and returns all records from {@code r}. When {@code requireHeader} is
     * true the first non-empty line must equal the magic header.
     */
    private static List<Record> readAll(BufferedReader r, boolean requireHeader) throws IOException { // NOPMD
        List<Record> recs = new ArrayList<>();
        String line;

        // header
        while ((line = r.readLine()) != null && line.isBlank()) { // NOPMD
            /* skip leading blanks */
        }
        if (requireHeader && line == null || !MAGIC_HEADER.equals(line.trim())) {
            throw new IOException("Unsupported keyring header. Expected: " + MAGIC_HEADER);
        }

        String alias;
        String algorithm;
        Record.Kind kind;
        String spec;
        List<String> payload;

        alias = algorithm = spec = null;
        kind = null;
        payload = new ArrayList<>();

        while ((line = r.readLine()) != null) {
            if (line.isEmpty()) {
                if (alias != null) {
                    recs.add(new Record(alias, algorithm, kind, spec, PairSeq.of(payload.toArray(String[]::new))));
                }
                alias = algorithm = spec = null;
                kind = null;
                payload = new ArrayList<>(); // NOPMD
                continue;
            }
            if (line.startsWith("#")) {
                continue;
            }

            if (ENTRY_MARKER.equals(line)) {
                if (alias != null) {
                    recs.add(new Record(alias, algorithm, kind, spec, PairSeq.of(payload.toArray(String[]::new))));
                }
                alias = algorithm = spec = null;
                kind = null;
                payload = new ArrayList<>(); // NOPMD
                continue;
            }

            int eq = line.indexOf('=');
            if (eq <= 0) {
                throw new IOException("Malformed line: " + line);
            }
            String k = line.substring(0, eq);
            String v = line.substring(eq + 1);

            switch (k) {
                case "alias" -> alias = v;
                case "algorithm" -> algorithm = v;
                case "kind" -> kind = Record.Kind.valueOf(v);
                case "spec" -> spec = v;
                default -> {
                    if (k.startsWith(PREFIX_SPEC)) {
                        String sk = k.substring(PREFIX_SPEC.length());
                        payload.add(sk);
                        payload.add(v);
                    }
                }
            }
        }

        if (alias != null) {
            recs.add(new Record(alias, algorithm, kind, spec, PairSeq.of(payload.toArray(String[]::new))));
        }
        return recs;
    }

    private void put(String alias, String algorithmId, Record.Kind kind, AlgorithmKeySpec importSpec) {
        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException("alias");
        }
        if (algorithmId == null || algorithmId.isBlank()) {
            throw new IllegalArgumentException("algorithmId");
        }
        if (importSpec == null) {
            throw new IllegalArgumentException("importSpec");
        }
        registeredSpecClass(algorithmId, kind, importSpec.getClass().getName());

        PairSeq payload = marshalSpec(importSpec);

        Record r = new Record(alias, algorithmId, kind, importSpec.getClass().getName(), payload);

        byAlias.put(alias, r);
    }

    private Record require(String alias, Record.Kind kind) {
        Record r = byAlias.get(alias);
        if (r == null) {
            throw new IllegalArgumentException("No entry: " + alias);
        }
        if (r.kind != kind) {
            throw new IllegalArgumentException("Alias '" + alias + "' is not a " + kind);
        }
        return r;
    }

    /**
     * Calls a static {@code marshal(SpecType)} method on the spec class.
     *
     * @param spec the spec instance to marshal
     * @return a pair sequence representing the spec payload
     * @throws IllegalStateException if the spec class does not expose a compatible
     *                               static method
     */
    private static PairSeq marshalSpec(AlgorithmKeySpec spec) {
        try {
            Method m = spec.getClass().getMethod("marshal", spec.getClass());
            Object out = m.invoke(null, spec);
            return (PairSeq) out;
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Spec class lacks static marshal(Spec): " + spec.getClass().getName(), e);
        } catch (IllegalAccessException | InvocationTargetException | SecurityException e) {
            throw new IllegalStateException("Spec marshal failed: " + spec.getClass().getName(), e);
        }
    }

    /**
     * Calls a static {@code unmarshal(PairSeq)} method on the spec class.
     *
     * @param <S>       spec type
     * @param specClass registered specification class
     * @param p         the pair sequence to unmarshal
     * @return the reconstructed spec instance
     * @throws IllegalStateException if reflection fails or the method is absent
     */
    @SuppressWarnings("unchecked")
    private static <S extends AlgorithmKeySpec> S unmarshalSpec(Class<S> specClass, PairSeq p) {
        try {
            Method m = specClass.getMethod("unmarshal", PairSeq.class);
            Object out = m.invoke(null, p);
            return (S) out;
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
            throw new IllegalStateException("Spec unmarshal failed for " + specClass.getName(), e);
        }
    }

    private AlgorithmKeySpec unmarshalRecord(Record record) {
        Class<? extends AlgorithmKeySpec> specClass = registeredSpecClass(record.algorithm, record.kind,
                record.specClass);
        return unmarshalSpec(specClass, record.specPayload);
    }

    private Class<? extends AlgorithmKeySpec> registeredSpecClass(String algorithmId, Record.Kind kind,
            String persistedClassName) {
        if (persistedClassName == null || persistedClassName.isBlank()) {
            throw new IllegalArgumentException("Missing key specification class");
        }
        CryptoAlgorithm algorithm = session.require(algorithmId);
        KeyOperation expectedOperation = switch (kind) {
            case PUBLIC_KEY -> KeyOperation.ASYMMETRIC_PUBLIC_IMPORT;
            case PRIVATE_KEY -> KeyOperation.ASYMMETRIC_PRIVATE_IMPORT;
            case SECRET_KEY -> KeyOperation.SYMMETRIC_IMPORT;
        };
        return algorithm.keyOperations().stream()
                .filter(info -> info.operation() == expectedOperation)
                .map(KeyOperationInfo::specType)
                .filter(type -> type.getName().equals(persistedClassName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Specification class is not registered for " + algorithmId + " " + kind));
    }

    /* default */ static void destroyTemporarySpec(AlgorithmKeySpec spec, Throwable primary)
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
                return;
            }
            throw new GeneralSecurityException("Temporary key specification destruction failed", failure);
        } catch (RuntimeException failure) { // NOPMD - preserve cleanup failure and primary failure
            if (primary != null) {
                primary.addSuppressed(failure);
                return;
            }
            throw failure;
        }
    }
}
