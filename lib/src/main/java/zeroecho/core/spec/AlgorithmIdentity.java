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
package zeroecho.core.spec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Provider-independent identity of one exact cryptographic operation or key
 * type.
 *
 * <p>
 * An identity contains no provider, implementation class, key material, or
 * X.509 representation. Families are namespaced so trusted installed
 * extensions can add typed parameter models without modifying a central enum.
 * The parameter object is responsible for family-specific validation and a
 * deterministic canonical component.
 * </p>
 *
 * <p>
 * Instances are immutable. Equality and hashing use the complete canonical
 * semantics, including the role, family, and parameters.
 * </p>
 */
public final class AlgorithmIdentity {

    private static final Pattern COMPONENT = Pattern.compile("[a-z][a-z0-9._-]{0,63}");
    private static final AlgorithmIdentityCodec BUILTIN_CODEC = new BuiltInCodec();
    private static final String NO_PARAMETERS = "none";
    private static final int RSA_PSS_COMPONENT_COUNT = 5;
    private static final int REQUIRED_TRAILER_FIELD = 1;
    private static final int UTF8_ONE_BYTE_LIMIT = 0x7f;
    private static final int UTF8_TWO_BYTE_LIMIT = 0x7ff;

    private final Kind kind;
    private final Family family;
    private final AlgorithmIdentityCodec codec;
    private final byte[] parameterSnapshot;
    private final String canonicalForm;

    /**
     * Semantic role represented by an identity.
     */
    public enum Kind {
        /** Message digest. */
        DIGEST,
        /** Mask-generation function. */
        MASK_GENERATION,
        /** Signature scheme, independent of a particular key parameter set. */
        SIGNATURE,
        /** Public-key algorithm and its exact key parameter set. */
        PUBLIC_KEY,
        /** Key-encapsulation mechanism. */
        KEM,
        /** Key-agreement mechanism. */
        AGREEMENT
    }

    /**
     * Stable namespaced algorithm family name.
     *
     * @param namespace namespace owned by the built-in catalog or trusted
     *                  extension
     * @param name      family name within that namespace
     */
    public record Family(String namespace, String name) {

        /**
         * Creates a validated family name.
         *
         * @throws IllegalArgumentException if either component is not a lowercase
         *                                  canonical identifier
         */
        public Family {
            namespace = requireComponent(namespace, "namespace");
            name = requireComponent(name, "name");
        }

        /**
         * Returns the deterministic family representation.
         *
         * @return namespace and family separated by {@code /}
         */
        public String canonicalForm() {
            return namespace + "/" + name;
        }
    }

    /**
     * Typed, immutable family parameters.
     *
     * <p>
     * Implementations supplied by trusted code must validate their complete
     * family-specific semantics during construction. The canonical component is
     * persistent identity data and therefore must never depend on a provider,
     * locale, insertion order, or display alias.
     * </p>
     */
    public interface Parameters {

        /**
         * Returns the deterministic parameter representation.
         *
         * @return non-blank lowercase canonical component
         */
        String canonicalForm();

        /**
         * Returns an independently owned immutable copy.
         *
         * <p>
         * Trusted extension implementations must not return mutable caller-owned
         * state. Immutable records may return {@code this}.
         * </p>
         *
         * @return immutable owned parameters
         */
        Parameters immutableCopy();
    }

    /**
     * Parameters for an unparameterized family.
     */
    public enum NoParameters implements Parameters {
        /** Singleton empty-parameter value. */
        INSTANCE;

        @Override
        public String canonicalForm() {
            return "none";
        }

        @Override
        public Parameters immutableCopy() {
            return this;
        }
    }

    /**
     * Digest-qualified signature parameters.
     *
     * @param digest exact digest identity
     */
    public record DigestParameters(AlgorithmIdentity digest) implements Parameters {

        /**
         * Creates digest-qualified parameters.
         *
         * @throws IllegalArgumentException if {@code digest} is not a digest
         *                                  identity
         */
        public DigestParameters {
            Objects.requireNonNull(digest, "digest");
            if (digest.kind() != Kind.DIGEST) {
                throw new IllegalArgumentException("digest must have DIGEST kind");
            }
        }

        @Override
        public String canonicalForm() {
            return "digest=" + digest.family().namespace() + "." + digest.family().name() + "."
                    + digest.parameters().canonicalForm();
        }

        @Override
        public Parameters immutableCopy() {
            return this;
        }
    }

    /**
     * Exact RSA-PSS parameters.
     *
     * @param hash         message digest identity
     * @param mask         mask-generation identity
     * @param maskHash     mask-generation digest identity
     * @param saltLength   non-negative salt length in bytes
     * @param trailerField trailer field; PKCS#1 currently defines value {@code 1}
     */
    public record RsaPssParameters(AlgorithmIdentity hash, AlgorithmIdentity mask, AlgorithmIdentity maskHash,
            int saltLength, int trailerField) implements Parameters {

        /**
         * Creates a validated exact RSA-PSS parameter tuple.
         *
         * @throws IllegalArgumentException if roles or numeric parameters are
         *                                  contradictory
         */
        public RsaPssParameters {
            Objects.requireNonNull(hash, "hash");
            Objects.requireNonNull(mask, "mask");
            Objects.requireNonNull(maskHash, "maskHash");
            if (hash.kind() != Kind.DIGEST || maskHash.kind() != Kind.DIGEST) {
                throw new IllegalArgumentException("RSA-PSS hashes must have DIGEST kind");
            }
            if (mask.kind() != Kind.MASK_GENERATION) {
                throw new IllegalArgumentException("RSA-PSS mask must have MASK_GENERATION kind");
            }
            if (saltLength < 0) {
                throw new IllegalArgumentException("RSA-PSS salt length must not be negative");
            }
            if (trailerField != REQUIRED_TRAILER_FIELD) {
                throw new IllegalArgumentException("RSA-PSS trailer field must be 1");
            }
        }

        @Override
        public String canonicalForm() {
            return "hash=" + shortName(hash) + ",mask=" + shortName(mask) + ",maskhash=" + shortName(maskHash)
                    + ",salt=" + saltLength + ",trailer=" + trailerField;
        }

        @Override
        public Parameters immutableCopy() {
            return this;
        }
    }

    /**
     * Exact named parameter set, such as an elliptic-curve name.
     *
     * @param parameterSet stable namespaced parameter-set identifier
     */
    public record NamedParameters(Family parameterSet) implements Parameters {

        /**
         * Creates named parameters.
         *
         * @throws NullPointerException if {@code parameterSet} is {@code null}
         */
        public NamedParameters {
            Objects.requireNonNull(parameterSet, "parameterSet");
        }

        @Override
        public String canonicalForm() {
            return "set=" + parameterSet.namespace() + "." + parameterSet.name();
        }

        @Override
        public Parameters immutableCopy() {
            return this;
        }
    }

    /**
     * Creates one exact algorithm identity.
     *
     * @param kind       semantic role
     * @param family     stable namespaced family
     * @param parameters validated typed parameters
     * @throws NullPointerException     if an argument is {@code null}
     * @throws IllegalArgumentException if the parameter canonical form is not
     *                                  deterministic syntax
     */
    public AlgorithmIdentity(Kind kind, Family family, Parameters parameters) {
        this(kind, family, parameters, BUILTIN_CODEC);
    }

    /**
     * Creates one exact algorithm identity using a trusted typed codec.
     *
     * @param kind       semantic role
     * @param family     stable namespaced family
     * @param parameters validated typed parameters
     * @param codec      immutable canonical parameter codec
     */
    public AlgorithmIdentity(Kind kind, Family family, Parameters parameters, AlgorithmIdentityCodec codec) {
        this.kind = Objects.requireNonNull(kind, "kind");
        this.family = Objects.requireNonNull(family, "family");
        this.codec = Objects.requireNonNull(codec, "codec");
        requireComponent(codec.id(), "codec.id");
        byte[] encoded = codec.encode(Objects.requireNonNull(parameters, "parameters"));
        this.parameterSnapshot = Objects.requireNonNull(encoded, "encoded parameters").clone();
        Parameters decoded = Objects.requireNonNull(codec.decode(parameterSnapshot.clone()), "decoded parameters");
        byte[] roundTrip = codec.encode(decoded);
        if (!java.util.Arrays.equals(parameterSnapshot, roundTrip)) {
            throw new IllegalArgumentException("Algorithm parameter codec is not canonical");
        }
        this.canonicalForm = "zealg:2:" + field(kind.name().toLowerCase(Locale.ROOT)) + field(family.namespace())
                + field(family.name()) + field(codec.id())
                + field(Base64.getUrlEncoder().withoutPadding().encodeToString(parameterSnapshot));
    }

    /**
     * Returns the semantic identity kind.
     *
     * @return identity kind
     */
    public Kind kind() {
        return kind;
    }

    /**
     * Returns the stable family.
     *
     * @return namespaced family
     */
    public Family family() {
        return family;
    }

    /**
     * Returns the immutable typed parameters.
     *
     * @return family parameters
     */
    public Parameters parameters() {
        return codec.decode(parameterSnapshot.clone());
    }

    /**
     * Parses a complete version-two canonical identity with installed codecs.
     *
     * @param canonicalForm canonical identity
     * @param codecs        trusted installed codecs
     * @return exact decoded identity
     * @throws IllegalArgumentException if syntax, version, codec, or canonical
     *                                  round-trip validation fails
     */
    public static AlgorithmIdentity parse(String canonicalForm, Collection<AlgorithmIdentityCodec> codecs) {
        Objects.requireNonNull(canonicalForm, "canonicalForm");
        Objects.requireNonNull(codecs, "codecs");
        if (!canonicalForm.startsWith("zealg:2:")) {
            throw new IllegalArgumentException("Unsupported canonical algorithm identity version");
        }
        Map<String, AlgorithmIdentityCodec> byId = new HashMap<>();
        byId.put(BUILTIN_CODEC.id(), BUILTIN_CODEC);
        for (AlgorithmIdentityCodec candidate : codecs) {
            AlgorithmIdentityCodec previous = byId.putIfAbsent(candidate.id(), candidate);
            if (previous != null && !previous.id().equals(candidate.id())) {
                throw new IllegalArgumentException("Algorithm identity codec collision");
            }
        }
        Cursor cursor = new Cursor(canonicalForm, "zealg:2:".length());
        Kind parsedKind;
        try {
            parsedKind = Kind.valueOf(cursor.field().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Unknown algorithm identity kind", exception);
        }
        Family parsedFamily = new Family(cursor.field(), cursor.field());
        String codecId = cursor.field();
        String encodedParameters = cursor.field();
        cursor.requireEnd();
        AlgorithmIdentityCodec selected = byId.get(codecId);
        if (selected == null) {
            throw new IllegalArgumentException("Unknown algorithm identity codec");
        }
        byte[] bytes;
        try {
            bytes = Base64.getUrlDecoder().decode(encodedParameters);
        } catch (IllegalArgumentException malformed) {
            throw new IllegalArgumentException("Malformed canonical algorithm parameters", malformed);
        }
        AlgorithmIdentity identity = new AlgorithmIdentity(parsedKind, parsedFamily, selected.decode(bytes), selected);
        if (!canonicalForm.equals(identity.canonicalForm())) {
            throw new IllegalArgumentException("Non-canonical algorithm identity");
        }
        return identity;
    }

    /**
     * Returns the deterministic provider-independent representation.
     *
     * @return complete canonical identity
     */
    public String canonicalForm() {
        return canonicalForm;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof AlgorithmIdentity identity && canonicalForm.equals(identity.canonicalForm);
    }

    @Override
    public int hashCode() {
        return canonicalForm.hashCode();
    }

    @Override
    public String toString() {
        return canonicalForm;
    }

    private static String requireComponent(String value, String field) {
        Objects.requireNonNull(value, field);
        if (!COMPONENT.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " must be a lowercase canonical identifier");
        }
        return value;
    }

    private static String shortName(AlgorithmIdentity identity) {
        return identity.family.namespace() + "." + identity.family.name() + "."
                + identity.parameters().canonicalForm();
    }

    private static String field(String value) {
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        return utf8.length + ":" + value;
    }

    /** Strict cursor for the length-prefixed canonical representation. */
    private static final class Cursor {

        private final String value;
        private int offset;

        private Cursor(String value, int offset) {
            this.value = value;
            this.offset = offset;
        }

        private String field() {
            int separator = value.indexOf(':', offset);
            if (separator < 0 || separator == offset) {
                throw new IllegalArgumentException("Malformed canonical algorithm identity");
            }
            int length;
            try {
                length = Integer.parseInt(value.substring(offset, separator));
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Malformed canonical algorithm identity length", exception);
            }
            if (length < 0) {
                throw new IllegalArgumentException("Negative canonical algorithm identity length");
            }
            int start = separator + 1;
            int index = start;
            int bytes = 0;
            while (index < value.length() && bytes < length) {
                int codePoint = value.codePointAt(index);
                bytes += utf8Length(codePoint);
                index += Character.charCount(codePoint);
            }
            if (bytes != length) {
                throw new IllegalArgumentException("Truncated canonical algorithm identity field");
            }
            offset = index;
            return value.substring(start, index);
        }

        private void requireEnd() {
            if (offset != value.length()) {
                throw new IllegalArgumentException("Trailing canonical algorithm identity data");
            }
        }

        private static int utf8Length(int codePoint) {
            if (codePoint <= UTF8_ONE_BYTE_LIMIT) {
                return 1;
            }
            if (codePoint <= UTF8_TWO_BYTE_LIMIT) {
                return 2;
            }
            return codePoint <= 0xffff ? 3 : 4;
        }
    }

    /** Canonical codec for the built-in closed parameter records. */
    private static final class BuiltInCodec implements AlgorithmIdentityCodec {

        @Override
        public String id() {
            return "zeroecho.builtin";
        }

        @Override
        public byte[] encode(Parameters parameters) {
            if (!isKnown(parameters)) {
                throw new IllegalArgumentException("Built-in codec cannot encode extension parameters");
            }
            return parameters.canonicalForm().getBytes(StandardCharsets.US_ASCII);
        }

        @Override
        public Parameters decode(byte[] encoded) {
            String value = new String(encoded.clone(), StandardCharsets.US_ASCII);
            if (!java.util.Arrays.equals(encoded, value.getBytes(StandardCharsets.US_ASCII))) {
                throw new IllegalArgumentException("Built-in parameters are not ASCII");
            }
            if (NO_PARAMETERS.equals(value)) {
                return NoParameters.INSTANCE;
            }
            if (value.startsWith("digest=")) {
                return new DigestParameters(parseShort(value.substring(7), Kind.DIGEST));
            }
            if (value.startsWith("set=")) {
                return new NamedParameters(parseFamily(value.substring(4)));
            }
            if (value.startsWith("hash=")) {
                String[] components = value.split(",");
                if (components.length != RSA_PSS_COMPONENT_COUNT) {
                    throw new IllegalArgumentException("Malformed RSA-PSS parameters");
                }
                AlgorithmIdentity hash = parseShort(requirePair(components[0], "hash"), Kind.DIGEST);
                AlgorithmIdentity mask = parseShort(requirePair(components[1], "mask"), Kind.MASK_GENERATION);
                AlgorithmIdentity maskHash = parseShort(requirePair(components[2], "maskhash"), Kind.DIGEST);
                int salt = parseInteger(requirePair(components[3], "salt"));
                int trailer = parseInteger(requirePair(components[4], "trailer"));
                return new RsaPssParameters(hash, mask, maskHash, salt, trailer);
            }
            throw new IllegalArgumentException("Unknown built-in algorithm parameters");
        }

        private static boolean isKnown(Parameters parameters) {
            return parameters instanceof NoParameters || parameters instanceof DigestParameters
                    || parameters instanceof RsaPssParameters || parameters instanceof NamedParameters;
        }

        private static AlgorithmIdentity parseShort(String value, Kind kind) {
            int first = value.indexOf('.');
            int second = value.indexOf('.', first + 1);
            if (first <= 0 || second <= first + 1) {
                throw new IllegalArgumentException("Malformed nested algorithm identity");
            }
            Family family = new Family(value.substring(0, first), value.substring(first + 1, second));
            String parameters = value.substring(second + 1);
            return new AlgorithmIdentity(kind, family, decodeStatic(parameters));
        }

        private static Parameters decodeStatic(String value) {
            return new BuiltInCodec().decode(value.getBytes(StandardCharsets.US_ASCII));
        }

        private static Family parseFamily(String value) {
            int separator = value.indexOf('.');
            if (separator <= 0 || separator == value.length() - 1) {
                throw new IllegalArgumentException("Malformed named parameter set");
            }
            return new Family(value.substring(0, separator), value.substring(separator + 1));
        }

        private static String requirePair(String value, String name) {
            String prefix = name + "=";
            if (!value.startsWith(prefix)) {
                throw new IllegalArgumentException("Malformed RSA-PSS parameters");
            }
            return value.substring(prefix.length());
        }

        private static int parseInteger(String value) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Malformed integer algorithm parameter", exception);
            }
        }
    }
}
