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

package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.spi.store.MetadataKey;

/**
 * Strict big-endian version-1 metadata: magic/version/record type, scope digest,
 * length-framed canonical name and SPKI, then the typed record body. Serial
 * content is minimal positive signed DER INTEGER content (at most 20 octets).
 * Hashes are fixed 32 octets; variable fields use signed 32-bit lengths checked
 * before allocation. Decoding owns a bounded input snapshot and rejects trailing
 * bytes. No migration, store transaction, reservation lifecycle or recovery is
 * implemented here. Local time and auxiliary memory are O(N + K + I), for
 * bounded name, SPKI and owner identifier bytes, plus JDK name canonicalization
 * on decode.
 * Counter records instead contain only the fixed scope digest and a minimal
 * unsigned 1–20-octet next number (zero is one zero octet). Counter decoding
 * binds that digest to the supplied metadata key; its time and memory are O(1).
 */
final class CrlScopeMetadataCodec { // NOPMD - CyclomaticComplexity totals independent dispatch/codec branches; method-level checks remain enabled.
    private static final int SHA256_HEX_LENGTH = 64;
    /**
     * Inclusive maximum identifier length in UTF-8 bytes.
     */
    /* default */ static final int MAXIMUM_ID_BYTES = 4096;
    /**
     * Inclusive maximum encoded record length in bytes.
     */
    /* default */ static final int MAXIMUM_ENCODED_BYTES = 12 + 32 + 4 + CrlScope.MAXIMUM_NAME_BYTES
            + 4 + CrlScope.MAXIMUM_SPKI_BYTES + 4 + 20 + 4 + 4 + MAXIMUM_ID_BYTES + 32;
    /**
     * Inclusive maximum encoded CRL scope counter length in bytes.
     */
    /* default */ static final int MAXIMUM_COUNTER_ENCODED_BYTES = 12 + 32 + 4 + 20; // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.
    private static final int MAGIC = 0x5a454353; // ZECS
    private static final int VERSION = 1;
    private static final int OWNER = 1;
    private static final int RESERVATION = 2;
    private static final int COUNTER = 3;
    private static final int SIGNING = 1;
    private static final int IMPORTED = 2;
    private static final HexFormat HEX = HexFormat.of();

    private CrlScopeMetadataCodec() { }

    /**
     * Derives the exact metadata identity of the structural scope ownership claim.
     *
     * @param owner structural scope ownership claim
     * @return canonical metadata key without accessing storage
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey key(CrlScopeOwner owner) {
        return ownerKey(Objects.requireNonNull(owner, "owner").scope());
    }

    /**
     * Derives the ownership metadata key for an exact structural CRL scope.
     *
     * @param scope immutable structural CRL scope
     * @return scope-digest key in the CRL scope ownership namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey ownerKey(CrlScope scope) {
        return new MetadataKey("io.zeroecho.pki.crl-scope-owner", Objects.requireNonNull(scope, "scope").digest());
    }

    /**
     * Derives the exact metadata identity of the permanent scope and serial reservation.
     *
     * @param reservation permanent scope and serial reservation
     * @return canonical metadata key without accessing storage
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey key(ScopeSerialReservation reservation) {
        Objects.requireNonNull(reservation, "reservation");
        return reservationKey(reservation.scope(), reservation.serial());
    }

    /**
     * Derives a scope-wide serial reservation key with canonical hexadecimal serial framing.
     *
     * @param scope immutable structural CRL scope
     * @param serial positive certificate serial of at most 159 bits
     * @return exact scope and serial reservation metadata key
     * @throws NullPointerException if a required argument is null
     * @throws IllegalArgumentException if the serial is nonpositive or exceeds 159 bits
     */
    /* default */ static MetadataKey reservationKey(CrlScope scope, BigInteger serial) {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(serial, "serial");
        if (serial.signum() <= 0 || serial.bitLength() > 159) {
            throw new IllegalArgumentException("Invalid scope serial");
        }
        // Fixed-width scope digest, separator outside the hex alphabet, canonical serial.
        return new MetadataKey("io.zeroecho.pki.scope-serial",
                scope.digest() + ":" + HEX.formatHex(serial.toByteArray()));
    }

    /**
     * Derives the exact metadata identity of the scope digest and next-number counter.
     *
     * @param counter scope digest and next-number counter
     * @return canonical metadata key without accessing storage
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey key(CrlScopeCounter counter) {
        return counterKey(Objects.requireNonNull(counter, "counter").scopeDigest());
    }

    /**
     * Derives the next-number counter key for an exact structural CRL scope.
     *
     * @param scope immutable structural CRL scope
     * @return scope-digest key in the CRL counter namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey counterKey(CrlScope scope) {
        return counterKey(Objects.requireNonNull(scope, "scope").digest());
    }

    private static MetadataKey counterKey(String scopeDigest) {
        requireHash(scopeDigest);
        return new MetadataKey("io.zeroecho.pki.crl-scope-counter", scopeDigest);
    }

    /**
     * Encodes the scope digest and next unissued CRL number in the current bounded binary format.
     *
     * @param counter validated immutable scope digest and next unissued CRL number
     * @return newly allocated complete metadata record
     * @throws NullPointerException if the value is null
     * @throws IllegalArgumentException if a bounded identifier or canonical commitment is invalid
     */
    /* default */ static byte[] encode(CrlScopeCounter counter) {
        Objects.requireNonNull(counter, "counter");
        byte[] signed = counter.nextNumber().toByteArray();
        int start = signed.length > 1 && signed[0] == 0 ? 1 : 0;
        int length = signed.length - start;
        ByteBuffer output = ByteBuffer.allocate(12 + 32 + 4 + length);
        output.putInt(MAGIC).putInt(VERSION).putInt(COUNTER).put(HEX.parseHex(counter.scopeDigest()));
        output.putInt(length).put(signed, start, length);
        return output.array();
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  /**
                   * Decodes a canonical CRL counter and requires its derived metadata key to match.
                   *
                   * @param key exact persisted metadata identity
                   * @param encoded complete bounded counter record
                   * @return validated scope digest and next-number state
                   * @throws IOException if identity, size, integer representation, version or trailing data is invalid
                   */
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static CrlScopeCounter decodeCounter(MetadataKey key, byte[] encoded) throws IOException {
        if (key == null || encoded == null || encoded.length > MAXIMUM_COUNTER_ENCODED_BYTES) {
            throw malformed();
        }
        try {
            ByteBuffer input = input(encoded, COUNTER);
            String scopeDigest = hash(input);
            byte[] number = bytes(input, 20);
            if (number.length == 0 || number.length > 1 && number[0] == 0) {
                throw malformed();
            }
            CrlScopeCounter counter = new CrlScopeCounter(scopeDigest, new BigInteger(1, number));
            requireEnd(input);
            if (!key(counter).equals(key)) {
                throw malformed();
            }
            return counter;
        } catch (BufferUnderflowException | IllegalArgumentException invalid) {
            throw malformed();
        }
    }

    /**
     * Encodes the structural scope and owning authority in the current bounded binary format.
     *
     * @param owner validated immutable structural scope and owning authority
     * @return newly allocated complete metadata record
     * @throws NullPointerException if the value is null
     * @throws IllegalArgumentException if a bounded identifier or canonical commitment is invalid
     */
    /* default */ static byte[] encode(CrlScopeOwner owner) {
        Objects.requireNonNull(owner, "owner");
        byte[] id = utf8(owner.authorityId().value(), MAXIMUM_ID_BYTES);
        ByteBuffer output = header(owner.scope(), OWNER, framedSize(id));
        field(output, id);
        return output.array();
    }

    /**
     * Encodes the structural scope, serial and exact issuance owner in the current bounded binary format.
     *
     * @param reservation validated immutable structural scope, serial and exact issuance owner
     * @return newly allocated complete metadata record
     * @throws NullPointerException if the value is null
     * @throws IllegalArgumentException if a bounded identifier or canonical commitment is invalid
     */
    /* default */ static byte[] encode(ScopeSerialReservation reservation) {
        Objects.requireNonNull(reservation, "reservation");
        byte[] serial = reservation.serial().toByteArray();
        byte[] id = switch (reservation.issuanceOwner()) {
            case ScopeSerialReservation.SigningOwner signing -> utf8(signing.operationId().value(), MAXIMUM_ID_BYTES);
            case ScopeSerialReservation.ImportedCertificateOwner ignored -> null;
        };
        int ownerSize = Math.addExact(Integer.BYTES, 32);
        if (id != null) {
            ownerSize = Math.addExact(ownerSize, framedSize(id));
        }
        ByteBuffer output = header(reservation.scope(), RESERVATION, Math.addExact(framedSize(serial), ownerSize));
        field(output, serial);
        switch (reservation.issuanceOwner()) {
            case ScopeSerialReservation.SigningOwner signing -> {
                output.putInt(SIGNING);
                field(output, id);
                output.put(HEX.parseHex(signing.commandCommitment()));
            }
            case ScopeSerialReservation.ImportedCertificateOwner imported -> {
                output.putInt(IMPORTED).put(HEX.parseHex(imported.certificateCommitment()));
            }
        }
        return output.array();
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  /**
                   * Decodes one exact structural CRL scope ownership record.
                   *
                   * @param encoded complete bounded ownership record
                   * @return validated scope and owning authority claim
                   * @throws IOException if framing, structural scope, authority identity or trailing data is invalid
                   */
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static CrlScopeOwner decodeOwner(byte[] encoded) throws IOException {
        try {
            ByteBuffer input = input(encoded, OWNER);
            CrlScope scope = scope(input);
            CrlScopeOwner result = new CrlScopeOwner(scope, new PkiId(text(input, MAXIMUM_ID_BYTES)));
            requireEnd(input);
            return result;
        } catch (BufferUnderflowException | IllegalArgumentException invalid) {
            throw malformed();
        }
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  /**
                   * Decodes a canonical scope-wide serial reservation and its closed owner variant.
                   *
                   * @param encoded complete bounded reservation record
                   * @return validated structural scope, positive serial and exact issuance owner
                   * @throws IOException if framing, serial canonicality, scope, owner code, identifiers or trailing data is invalid
                   */
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static ScopeSerialReservation decodeReservation(byte[] encoded) throws IOException {
        try {
            ByteBuffer input = input(encoded, RESERVATION);
            CrlScope scope = scope(input);
            byte[] serialBytes = bytes(input, 20);
            BigInteger serial = new BigInteger(serialBytes);
            if (!Arrays.equals(serialBytes, serial.toByteArray())) {
                throw malformed();
            }
            ScopeSerialReservation.IssuanceOwner owner = switch (input.getInt()) {
                case SIGNING -> new ScopeSerialReservation.SigningOwner(new PkiId(text(input, MAXIMUM_ID_BYTES)), hash(input));
                case IMPORTED -> new ScopeSerialReservation.ImportedCertificateOwner(hash(input));
                default -> throw malformed();
            };
            ScopeSerialReservation result = new ScopeSerialReservation(scope, serial, owner);
            requireEnd(input);
            return result;
        } catch (BufferUnderflowException | IllegalArgumentException invalid) {
            throw malformed();
        }
    }

    /**
     * Requires a bounded strict UTF-8 scope metadata identifier.
     *
     * @param id logical identifier with an encoded length of at most 4,096 bytes
     * @throws NullPointerException if the identifier is null
     * @throws IllegalArgumentException if it is blank, malformed Unicode or exceeds its encoded byte bound
     */
    /* default */ static void requireId(PkiId id) {
        utf8(Objects.requireNonNull(id, "id").value(), MAXIMUM_ID_BYTES);
    }

    /**
     * Requires the canonical lowercase hexadecimal representation of a SHA-256 commitment.
     *
     * @param hash exact 64-character lowercase hexadecimal commitment
     * @throws NullPointerException if the commitment is null
     * @throws IllegalArgumentException if its length or alphabet is invalid
     */
    /* default */ static void requireHash(String hash) {
        Objects.requireNonNull(hash, "commitment");
        if (hash.length() != SHA256_HEX_LENGTH) {
            throw new IllegalArgumentException("Invalid SHA-256 commitment");
        }
        for (int index = 0; index < hash.length(); index++) {
            char digit = hash.charAt(index);
            if (!(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f')) {
                throw new IllegalArgumentException("Invalid SHA-256 commitment");
            }
        }
    }

    private static ByteBuffer header(CrlScope scope, int type, int bodySize) {
        byte[] name = utf8(scope.canonicalIssuerName(), CrlScope.MAXIMUM_NAME_BYTES);
        byte[] key = scope.subjectPublicKeyInfoDer();
        int size = Math.addExact(12 + 32, Math.addExact(framedSize(name), framedSize(key)));
        size = Math.addExact(size, bodySize);
        if (size > MAXIMUM_ENCODED_BYTES) {
            throw new IllegalArgumentException("CRL scope metadata exceeds size limit");
        }
        ByteBuffer output = ByteBuffer.allocate(size);
        output.putInt(MAGIC).putInt(VERSION).putInt(type).put(HEX.parseHex(scope.digest()));
        field(output, name);
        field(output, key);
        return output;
    }

    private static ByteBuffer input(byte[] encoded, int expectedType) throws IOException {
        if (encoded == null || encoded.length < 12 || encoded.length > MAXIMUM_ENCODED_BYTES) {
            throw malformed();
        }
        ByteBuffer input = ByteBuffer.wrap(encoded.clone()).asReadOnlyBuffer();
        if (input.getInt() != MAGIC || input.getInt() != VERSION || input.getInt() != expectedType) {
            throw malformed();
        }
        return input;
    }

    private static CrlScope scope(ByteBuffer input) throws IOException {
        String digest = hash(input);
        String name = text(input, CrlScope.MAXIMUM_NAME_BYTES);
        byte[] key = bytes(input, CrlScope.MAXIMUM_SPKI_BYTES);
        return CrlScope.restore(name, key, digest);
    }

    private static byte[] bytes(ByteBuffer input, int maximum) throws IOException {
        int size = input.getInt();
        if (size < 0 || size > maximum || size > input.remaining()) {
            throw malformed();
        }
        byte[] result = new byte[size];
        input.get(result);
        return result;
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private static String text(ByteBuffer input, int maximum) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes(input, maximum))).toString();
        } catch (CharacterCodingException invalid) {
            throw malformed();
        }
    }

    private static String hash(ByteBuffer input) {
        byte[] hash = new byte[32];
        input.get(hash);
        return HEX.formatHex(hash);
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private static byte[] utf8(String value, int maximum) {
        if (value.length() > maximum) {
            throw new IllegalArgumentException("CRL scope metadata text exceeds size limit");
        }
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
            if (encoded.remaining() > maximum) {
                throw new IllegalArgumentException("CRL scope metadata text exceeds size limit");
            }
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        } catch (CharacterCodingException invalid) {
            throw new IllegalArgumentException("Invalid CRL scope metadata text");
        }
    }

    private static int framedSize(byte[] value) { return Math.addExact(Integer.BYTES, value.length); }

    private static void field(ByteBuffer output, byte[] value) { output.putInt(value.length).put(value); }

    private static void requireEnd(ByteBuffer input) throws IOException {
        if (input.hasRemaining()) {
            throw malformed();
        }
    }

    private static IOException malformed() { return new IOException("Malformed CRL scope metadata"); }
}
