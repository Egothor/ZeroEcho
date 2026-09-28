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

package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.spi.store.MetadataKey;

class CrlScopeMetadataCodecTest {
    private static final String HASH = "ab".repeat(32);

    @Test
    void counterIncludesZeroMaximumIssuedAndExhaustedSentinelWithMinimalUnsignedBytes() throws IOException {
        for (BigInteger number : new BigInteger[] {BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(127),
                BigInteger.valueOf(128), CrlScopeCounter.EXHAUSTED.subtract(BigInteger.ONE), CrlScopeCounter.EXHAUSTED}) {
            CrlScopeCounter counter = new CrlScopeCounter(scope().digest(), number);
            byte[] encoded = CrlScopeMetadataCodec.encode(counter);
            int length = Math.max(1, (number.bitLength() + 7) / 8);
            assertEquals(48 + length, encoded.length);
            assertEquals(length, ByteBuffer.wrap(encoded).getInt(44));
            assertEquals(counter, CrlScopeMetadataCodec.decodeCounter(CrlScopeMetadataCodec.key(counter), encoded));
            assertEquals(CrlScopeMetadataCodec.counterKey(scope()), CrlScopeMetadataCodec.key(counter));
            assertArrayEquals(encoded, CrlScopeMetadataCodec.encode(counter));
        }
        byte[] exhausted = CrlScopeMetadataCodec.encode(new CrlScopeCounter(scope().digest(), CrlScopeCounter.EXHAUSTED));
        assertEquals((byte) 0x80, exhausted[48]);
        assertEquals(CrlScopeMetadataCodec.MAXIMUM_COUNTER_ENCODED_BYTES, exhausted.length);
        assertThrows(IllegalArgumentException.class, () -> new CrlScopeCounter(HASH, BigInteger.ONE.negate()));
        assertThrows(IllegalArgumentException.class,
                () -> new CrlScopeCounter(HASH, CrlScopeCounter.EXHAUSTED.add(BigInteger.ONE)));
        assertThrows(IllegalArgumentException.class, () -> new CrlScopeCounter("bad", BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new CrlScopeCounter(HASH.toUpperCase(), BigInteger.ZERO));
        assertThrows(NullPointerException.class, () -> new CrlScopeCounter(HASH, null));
    }

    @Test
    void counterBindsItsKeyAndOwnsDecodedInput() throws IOException {
        CrlScopeCounter counter = new CrlScopeCounter(scope().digest(), BigInteger.valueOf(128));
        byte[] encoded = CrlScopeMetadataCodec.encode(counter);
        MetadataKey key = CrlScopeMetadataCodec.key(counter);
        CrlScopeCounter decoded = CrlScopeMetadataCodec.decodeCounter(key, encoded);
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(
                CrlScopeMetadataCodec.key(new CrlScopeCounter(HASH, BigInteger.ONE)), encoded));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(
                CrlScopeMetadataCodec.ownerKey(scope()), encoded));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(
                CrlScopeMetadataCodec.reservationKey(scope(), BigInteger.ONE), encoded));
        byte[] mutatedDigest = encoded.clone();
        mutatedDigest[12] ^= 1;
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, mutatedDigest));
        Arrays.fill(encoded, (byte) 0);
        assertEquals(counter, decoded);
        assertNotEquals(encoded[0], CrlScopeMetadataCodec.encode(decoded)[0]);
    }

    @Test
    void counterRejectsTruncationTrailingLegacyVersionsTypesAndNoncanonicalUnsignedNumbers() {
        CrlScopeCounter counter = new CrlScopeCounter(scope().digest(), BigInteger.valueOf(128));
        MetadataKey key = CrlScopeMetadataCodec.key(counter);
        byte[] encoded = CrlScopeMetadataCodec.encode(counter);
        for (int size = 0; size < encoded.length; size++) {
            byte[] truncated = Arrays.copyOf(encoded, size);
            assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, truncated));
        }
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, null));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(null, encoded));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key,
                new byte[CrlScopeMetadataCodec.MAXIMUM_COUNTER_ENCODED_BYTES + 1]));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key,
                Arrays.copyOf(encoded, encoded.length + 1)));
        for (int offset : new int[] {0, 4, 8}) {
            for (int invalid : new int[] {0, 99}) {
                byte[] changed = encoded.clone();
                ByteBuffer.wrap(changed).putInt(offset, invalid);
                assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, changed));
            }
        }
        byte[] redundantZero = Arrays.copyOf(encoded, encoded.length + 1);
        ByteBuffer.wrap(redundantZero).putInt(44, 2);
        redundantZero[48] = 0;
        redundantZero[49] = (byte) 0x80;
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, redundantZero));
        for (int length : new int[] {-1, 0, 21, Integer.MAX_VALUE}) {
            byte[] changed = encoded.clone();
            ByteBuffer.wrap(changed).putInt(44, length);
            assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, changed));
        }
        byte[] tooLarge = CrlScopeMetadataCodec.encode(new CrlScopeCounter(scope().digest(), CrlScopeCounter.EXHAUSTED));
        tooLarge[tooLarge.length - 1] = 1;
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, tooLarge));
        byte[] owner = CrlScopeMetadataCodec.encode(new CrlScopeOwner(scope(), new PkiId("authority")));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeCounter(key, owner));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeOwner(encoded));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeReservation(encoded));
    }

    @Test
    void principalEqualityDefinesScopeAcrossCaseWhitespaceStringTypesAndRdnOrdering() {
        X500Principal first = new X500Principal("CN=Example  CA+OU=Trust,O=Example");
        X500Principal second = new X500Principal("ou=trust+cn=example ca,o=example");
        assertEquals(first, second);
        assertEquals(CrlScope.of(first.getEncoded(), spki()), CrlScope.of(second.getEncoded(), spki()));
        byte[] printable = new X500Principal("CN=Example").getEncoded();
        byte[] utf8 = printable.clone();
        for (int index = 0; index < utf8.length; index++) {
            if (utf8[index] == 0x13) { utf8[index] = 0x0c; break; }
        }
        assertEquals(CrlScope.of(printable, spki()), CrlScope.of(utf8, spki()));
    }

    @Test
    void identityIncludesNameAndKeyAndOwnsAllArrays() {
        byte[] name = new X500Principal("CN=Example").getEncoded();
        byte[] key = spki();
        CrlScope scope = CrlScope.of(name, key);
        name[0] = 0;
        key[key.length - 1] ^= 1;
        assertNotEquals(scope, CrlScope.of(new X500Principal("CN=Other").getEncoded(), spki()));
        assertNotEquals(scope, CrlScope.of(new X500Principal("CN=Example").getEncoded(), key));
        byte[] returned = scope.subjectPublicKeyInfoDer();
        returned[0] = 0;
        assertArrayEquals(spki(), scope.subjectPublicKeyInfoDer());
        assertEquals(scope, scope());
        assertEquals(scope.hashCode(), scope().hashCode());
    }

    @Test
    void digestUsesIndependentLengthFramedDomainNameAndKey() throws NoSuchAlgorithmException {
        byte[] domain = "zeroecho:pki:crl-scope:v1".getBytes(StandardCharsets.US_ASCII);
        byte[] name = "cn=example".getBytes(StandardCharsets.UTF_8);
        byte[] key = spki();
        ByteBuffer reference = ByteBuffer.allocate(12 + domain.length + name.length + key.length);
        reference.putInt(domain.length).put(domain).putInt(name.length).put(name).putInt(key.length).put(key);
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(reference.array())),
                scope().digest());
    }

    @Test
    void rejectsMalformedNamesKeysAndNoncanonicalStoredIdentity() {
        assertThrows(IllegalArgumentException.class, () -> CrlScope.of(new byte[] { 1 }, spki()));
        assertThrows(IllegalArgumentException.class, () -> CrlScope.of(
                new X500Principal("CN=Example").getEncoded(), new byte[] { 0x30, 0 }));
        byte[] invalidUtf8 = HexFormat.of().parseHex("300d310b300906035504030c02c080");
        assertThrows(IllegalArgumentException.class, () -> CrlScope.of(invalidUtf8, spki()));
        assertThrows(IllegalArgumentException.class, () -> CrlScope.restore("CN=Example", spki(), scope().digest()));
        assertThrows(IllegalArgumentException.class, () -> CrlScope.restore("cn=example", spki(), "00".repeat(32)));
        assertThrows(IllegalArgumentException.class, () -> CrlScope.restore("cn=example", spki(), HASH.toUpperCase()));
        assertThrows(IllegalArgumentException.class, () -> CrlScope.restore("1.2.3=#0c02c080", spki(), HASH));
        byte[] malformedAlgorithm = HexFormat.of().parseHex("3006300003020001");
        assertThrows(IllegalArgumentException.class, () -> CrlScope.of(
                new X500Principal("CN=Example").getEncoded(), malformedAlgorithm));
    }

    @Test
    void recordsRoundTripWithBothClosedOwnerTypesAndDistinctKeys() throws IOException {
        CrlScopeOwner owner = new CrlScopeOwner(scope(), new PkiId("authority"));
        assertEquals(owner, CrlScopeMetadataCodec.decodeOwner(CrlScopeMetadataCodec.encode(owner)));
        for (ScopeSerialReservation.IssuanceOwner issuance : new ScopeSerialReservation.IssuanceOwner[] {
                new ScopeSerialReservation.SigningOwner(new PkiId("op:one"), HASH),
                new ScopeSerialReservation.ImportedCertificateOwner(HASH) }) {
            ScopeSerialReservation reservation = new ScopeSerialReservation(scope(), BigInteger.valueOf(128), issuance);
            assertEquals(reservation, CrlScopeMetadataCodec.decodeReservation(CrlScopeMetadataCodec.encode(reservation)));
            assertNotEquals(CrlScopeMetadataCodec.key(owner), CrlScopeMetadataCodec.key(reservation));
            assertNotEquals(CrlScopeMetadataCodec.key(reservation), CrlScopeMetadataCodec.key(
                    new ScopeSerialReservation(scope(), BigInteger.valueOf(129), issuance)));
        }
        CrlScopeOwner changedAuthority = new CrlScopeOwner(scope(), new PkiId("authority:two"));
        assertEquals(CrlScopeMetadataCodec.key(owner), CrlScopeMetadataCodec.key(changedAuthority));
    }

    @Test
    void serialIsPositiveAndFitsTwentySignedDerContentOctets() {
        ScopeSerialReservation.IssuanceOwner owner = new ScopeSerialReservation.ImportedCertificateOwner(HASH);
        for (BigInteger invalid : new BigInteger[] {BigInteger.ZERO, BigInteger.ONE.negate(), BigInteger.ONE.shiftLeft(159)}) {
            assertThrows(IllegalArgumentException.class, () -> new ScopeSerialReservation(scope(), invalid, owner));
        }
        new ScopeSerialReservation(scope(), BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE), owner);
    }

    @Test
    void ownersRejectMalformedAndOversizeIdentifiersAndCommitments() {
        assertThrows(IllegalArgumentException.class, () -> new CrlScopeOwner(scope(), new PkiId("a".repeat(4097))));
        assertThrows(IllegalArgumentException.class, () -> new CrlScopeOwner(scope(), new PkiId("\ud800")));
        assertThrows(IllegalArgumentException.class, () -> new ScopeSerialReservation.SigningOwner(new PkiId("x"), "a"));
        assertThrows(IllegalArgumentException.class, () -> new ScopeSerialReservation.SigningOwner(new PkiId("x".repeat(4097)), HASH));
        assertThrows(IllegalArgumentException.class, () -> new ScopeSerialReservation.ImportedCertificateOwner(HASH.toUpperCase()));
        assertThrows(IllegalArgumentException.class, () -> new CrlScopeOwner(scope(), new PkiId("é".repeat(2049))));
    }

    @Test
    void enforcesFiniteInputBoundsAndDecodedMutationIsolation() throws IOException {
        byte[] name = new X500Principal("CN=Example").getEncoded();
        assertThrows(IllegalArgumentException.class, () -> CrlScope.of(new byte[CrlScope.MAXIMUM_NAME_BYTES + 1], spki()));
        assertThrows(IllegalArgumentException.class, () -> CrlScope.of(name, new byte[CrlScope.MAXIMUM_SPKI_BYTES + 1]));
        assertThrows(IllegalArgumentException.class, () -> CrlScope.restore("a".repeat(CrlScope.MAXIMUM_NAME_BYTES + 1), spki(), HASH));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeOwner(new byte[CrlScopeMetadataCodec.MAXIMUM_ENCODED_BYTES + 1]));
        CrlScopeOwner original = new CrlScopeOwner(scope(), new PkiId("é".repeat(2048)));
        byte[] encoded = CrlScopeMetadataCodec.encode(original);
        CrlScopeOwner decoded = CrlScopeMetadataCodec.decodeOwner(encoded);
        Arrays.fill(encoded, (byte) 0);
        assertEquals(original, decoded);
        assertArrayEquals(spki(), decoded.scope().subjectPublicKeyInfoDer());
    }

    @Test
    void codecRejectsAllTruncationsTrailingUnknownVersionsTypesAndMutatedConstituents() {
        byte[] owner = CrlScopeMetadataCodec.encode(new CrlScopeOwner(scope(), new PkiId("authority")));
        byte[] reservation = CrlScopeMetadataCodec.encode(new ScopeSerialReservation(scope(), BigInteger.ONE,
                new ScopeSerialReservation.SigningOwner(new PkiId("op"), HASH)));
        for (byte[] encoded : new byte[][] {owner, reservation}) {
            for (int size = 0; size < encoded.length; size++) {
                byte[] truncated = Arrays.copyOf(encoded, size);
                assertThrows(IOException.class, () -> decode(truncated, encoded == owner));
            }
            assertThrows(IOException.class, () -> decode(Arrays.copyOf(encoded, encoded.length + 1), encoded == owner));
            for (int offset : new int[] {0, 4, 8}) {
                byte[] mutated = encoded.clone();
                ByteBuffer.wrap(mutated).putInt(offset, 99);
                assertThrows(IOException.class, () -> decode(mutated, encoded == owner));
            }
            byte[] changedDigest = encoded.clone();
            changedDigest[12] ^= 1;
            assertThrows(IOException.class, () -> decode(changedDigest, encoded == owner));
            byte[] malformedLength = encoded.clone();
            ByteBuffer.wrap(malformedLength).putInt(44, Integer.MAX_VALUE);
            assertThrows(IOException.class, () -> decode(malformedLength, encoded == owner));
            byte[] changedName = encoded.clone();
            changedName[48] = (byte) 0xff;
            assertThrows(IOException.class, () -> decode(changedName, encoded == owner));
            byte[] mismatchedName = encoded.clone();
            mismatchedName[51] = 'z';
            assertThrows(IOException.class, () -> decode(mismatchedName, encoded == owner));
            byte[] mismatchedKey = encoded.clone();
            int keyEnd = 48 + scope().canonicalIssuerName().getBytes(StandardCharsets.UTF_8).length + 4 + spki().length;
            mismatchedKey[keyEnd - 1] ^= 1;
            assertThrows(IOException.class, () -> decode(mismatchedKey, encoded == owner));
        }
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeOwner(reservation));
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeReservation(owner));
    }

    @Test
    void reservationRejectsNoncanonicalSerialAndUnknownOwnerDiscriminator() {
        byte[] encoded = CrlScopeMetadataCodec.encode(new ScopeSerialReservation(scope(), BigInteger.valueOf(128),
                new ScopeSerialReservation.ImportedCertificateOwner(HASH)));
        int serialOffset = 44 + 4 + scope().canonicalIssuerName().getBytes(StandardCharsets.UTF_8).length
                + 4 + spki().length;
        byte[] redundantZero = encoded.clone();
        redundantZero[serialOffset + 5] = 1;
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeReservation(redundantZero));
        byte[] negative = encoded.clone();
        negative[serialOffset + 4] = (byte) 0xff;
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeReservation(negative));
        byte[] unknownOwner = encoded.clone();
        ByteBuffer.wrap(unknownOwner).putInt(serialOffset + 6, 99);
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeReservation(unknownOwner));
        for (int length : new int[] {-1, 0, 21, Integer.MAX_VALUE}) {
            byte[] invalidLength = encoded.clone();
            ByteBuffer.wrap(invalidLength).putInt(serialOffset, length);
            assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeReservation(invalidLength));
        }
        byte[] zero = CrlScopeMetadataCodec.encode(new ScopeSerialReservation(scope(), BigInteger.ONE,
                new ScopeSerialReservation.ImportedCertificateOwner(HASH)));
        zero[serialOffset + 4] = 0;
        assertThrows(IOException.class, () -> CrlScopeMetadataCodec.decodeReservation(zero));
    }

    private static Object decode(byte[] encoded, boolean owner) throws IOException {
        return owner ? CrlScopeMetadataCodec.decodeOwner(encoded) : CrlScopeMetadataCodec.decodeReservation(encoded);
    }

    private static CrlScope scope() {
        return CrlScope.of(new X500Principal("CN=Example").getEncoded(), spki());
    }

    private static byte[] spki() {
        return HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32));
    }
}
