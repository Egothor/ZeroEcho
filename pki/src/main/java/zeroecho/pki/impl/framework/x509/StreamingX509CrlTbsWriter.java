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

package zeroecho.pki.impl.framework.x509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pkix.Pkix;

/**
 * Two-pass definite-length DER writer for a full RFC 5280 v2 TBSCertList.
 * A first pass validates and measures entries without retaining their encodings;
 * a second pass opens a new cursor and emits the same schema. Only individual
 * entries and fixed issuer/algorithm/time fields are buffered. Each pass takes
 * O(R + B) time and O(1) per-entry auxiliary memory, excluding the source and
 * bounded header fields. Aggregate lengths and counts use checked {@code long}
 * arithmetic, with no arbitrary aggregate size or entry-count ceiling.
 *
 * <p>The caller owns the restartable source and output. Every opened cursor is
 * closed by this writer, including on failure. The source must supply the same
 * immutable ordered entries on both passes. Length/count disagreement fails
 * closed; these checks are not a replacement for snapshot stability. Fractional
 * entry times are truncated to whole seconds, as required by X.509 DER time.
 * Update times must already be whole seconds.</p>
 */
public final class StreamingX509CrlTbsWriter {
    private static final DateTimeFormatter UTC_TIME = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'", Locale.ROOT)
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter GENERAL_TIME = DateTimeFormatter.ofPattern("uuuuMMddHHmmss'Z'", Locale.ROOT)
            .withZone(ZoneOffset.UTC);
    private final byte[] algorithm;
    private final byte[] issuer;
    private final byte[] thisUpdate;
    private final byte[] nextUpdate;
    private final byte[] authorityKeyIdentifier;
    private final long headerLength;
    private final Optional<BigInteger> baseNumber;

    /**
     * Captures the exact selected algorithm and issuer Name.
     * @param signature exact authorized inner signature AlgorithmIdentifier
     * @param issuerNameDer canonical DER issuer Name
     * @param keyIdentifier nonempty issuer key identifier, defensively captured
     * @param thisUpdate inclusive current update, normalized to seconds
     * @param nextUpdate later next update, normalized to seconds
     * @throws IOException if the Name or an encoded field is malformed
     * @throws IllegalArgumentException if the times or Name are invalid
     */
    public StreamingX509CrlTbsWriter(X509AlgorithmIdentifier signature, byte[] issuerNameDer, byte[] keyIdentifier,
            Instant thisUpdate, Instant nextUpdate) throws IOException {
        this(signature, issuerNameDer, keyIdentifier, thisUpdate, nextUpdate, Optional.empty());
    }

    /**
     * Captures full or delta CRL fields before either streaming pass.
     * @param signature exact authorized signature identifier
     * @param issuerNameDer canonical DER issuer Name
     * @param keyIdentifier nonempty issuer key identifier
     * @param thisUpdate inclusive whole-second update time
     * @param nextUpdate later whole-second update time
     * @param baseNumber signed full CRL number for a delta, empty for a full CRL
     * @throws IOException if an encoded field is malformed
     * @throws IllegalArgumentException if a field is outside its X.509 range
     */
    public StreamingX509CrlTbsWriter(X509AlgorithmIdentifier signature, byte[] issuerNameDer, byte[] keyIdentifier,
            Instant thisUpdate, Instant nextUpdate, Optional<BigInteger> baseNumber) throws IOException {
        this.baseNumber = Objects.requireNonNull(baseNumber, "baseNumber");
        if (baseNumber.filter(number -> number.signum() < 0 || number.bitLength() > 159).isPresent()) {
            throw new IllegalArgumentException("Base CRL number is outside the issued range");
        }
        Objects.requireNonNull(thisUpdate, "thisUpdate");
        Objects.requireNonNull(nextUpdate, "nextUpdate");
        if (thisUpdate.getNano() != 0 || nextUpdate.getNano() != 0 || !nextUpdate.isAfter(thisUpdate)) {
            throw new IllegalArgumentException("CRL update times must be increasing whole seconds");
        }
        this.issuer = Objects.requireNonNull(issuerNameDer, "issuerNameDer").clone();
        new X500Principal(this.issuer);
        new StreamingDerReader().validate(this.issuer, this.issuer.length);
        this.algorithm = Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(signature));
        byte[] identifier = Objects.requireNonNull(keyIdentifier, "keyIdentifier").clone();
        if (identifier.length == 0) { throw new IllegalArgumentException("Issuer key identifier must not be empty"); }
        this.authorityKeyIdentifier = extension(35, tlv(0x30, tlv(0x80, identifier)));
        this.thisUpdate = time(thisUpdate);
        this.nextUpdate = time(nextUpdate);
        this.headerLength = Math.addExact(3L, Math.addExact(this.algorithm.length,
                Math.addExact(this.issuer.length, Math.addExact(this.thisUpdate.length, this.nextUpdate.length))));
    }

    /**
     * Validates and measures a complete first pass, without reserving a number.
     * @param source stable restartable entry source, not closed by this method
     * @param cancellation cancellation signal
     * @return only aggregate encoded-entry bytes and emitted count
     * @throws IOException if traversal, validation, cancellation or closing fails
     * @throws ArithmeticException if aggregate accounting overflows
     */
    public Measurement measure(CrlEntrySource source, CancellationSignal cancellation) throws IOException {
        cancellation.throwIfCancelled();
        long bytes = 0;
        long count = 0;
        try (CrlEntrySource.Cursor cursor = source.openCursor()) {
            while (cursor.next()) {
                cancellation.throwIfCancelled();
                bytes = Math.addExact(bytes, entry(cursor.current()).length);
                count = Math.incrementExact(count);
            }
        }
        cancellation.throwIfCancelled();
        return new Measurement(bytes, count);
    }

    /**
     * Computes the exact complete TBS size for the subsequently reserved number.
     * @param measured completed first-pass measurement
     * @param crlNumber non-negative issued number of at most 159 bits
     * @return complete definite-length TBS byte count
     * @throws IOException if encoding fails
     * @throws IllegalArgumentException if the number is outside the issued range
     * @throws ArithmeticException if the total is not representable as a long
     */
    public long encodedLength(Measurement measured, BigInteger crlNumber) throws IOException {
        return StreamingDerWriter.encodedLength(bodyLength(measured, extensions(crlNumber).length));
    }

    /**
     * Streams the second pass and verifies exact entry byte and count totals.
     * @param source same stable source used for measurement
     * @param measured first-pass result
     * @param crlNumber durably reserved number
     * @param output caller-owned sequential output
     * @param cancellation cancellation signal
     * @return exact complete TBS byte count
     * @throws IOException if a pass diverges, traversal/writing/closing fails or cancellation occurs
     * @throws ArithmeticException if accounting overflows
     */
    public long write(CrlEntrySource source, Measurement measured, BigInteger crlNumber,
            OutputStream output, CancellationSignal cancellation) throws IOException {
        cancellation.throwIfCancelled();
        byte[] extensions = extensions(crlNumber);
        long body = bodyLength(measured, extensions.length);
        StreamingDerWriter.writeTagAndLength(output, 0x30, body);
        output.write(new byte[] {0x02, 0x01, 0x01});
        output.write(algorithm);
        output.write(issuer);
        output.write(thisUpdate);
        output.write(nextUpdate);
        if (measured.entryCount() != 0) {
            StreamingDerWriter.writeTagAndLength(output, 0x30, measured.entryBytes());
        }
        long bytes = 0;
        long count = 0;
        try (CrlEntrySource.Cursor cursor = source.openCursor()) {
            while (cursor.next()) {
                cancellation.throwIfCancelled();
                byte[] encoded = entry(cursor.current());
                bytes = Math.addExact(bytes, encoded.length);
                count = Math.incrementExact(count);
                if (bytes > measured.entryBytes() || count > measured.entryCount()) { throw divergence(); }
                output.write(encoded);
            }
        }
        if (bytes != measured.entryBytes() || count != measured.entryCount()) { throw divergence(); }
        cancellation.throwIfCancelled();
        output.write(extensions);
        cancellation.throwIfCancelled();
        return StreamingDerWriter.encodedLength(body);
    }

    /**
     * Constant-size first-pass evidence, containing no entries or encoded content.
     * @param entryBytes sum of complete DER entry encodings, without the enclosing sequence
     * @param entryCount emitted entry count
     */
    public record Measurement(long entryBytes, long entryCount) {
        /** Rejects negative or inconsistent empty measurements. */
        public Measurement {
            if (entryBytes < 0 || entryCount < 0 || (entryBytes == 0) != (entryCount == 0)) {
                throw new IllegalArgumentException("Invalid CRL measurement");
            }
        }
    }

    private long bodyLength(Measurement measured, long extensions) {
        long entries = measured.entryCount() == 0 ? 0 : StreamingDerWriter.encodedLength(measured.entryBytes());
        return Math.addExact(headerLength, Math.addExact(entries, extensions));
    }

    private byte[] entry(CrlEntry entry) throws IOException {
        if (baseNumber.isEmpty() && entry.reason() == RevocationReason.REMOVE_FROM_CRL) {
            throw new IOException("REMOVE_FROM_CRL is invalid in a full CRL");
        }
        if (entry.serialNumber().signum() <= 0 || entry.serialNumber().bitLength() > 159) {
            throw new IOException("Full CRL serial is outside the issued X.509 range");
        }
        byte[] serial = tlv(0x02, entry.serialNumber().toByteArray());
        byte[] date = time(entry.transitionTime());
        byte[] reason = tlv(0x30, extension(21, tlv(0x0a, new byte[] {(byte) reasonCode(entry.reason())})));
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        StreamingDerWriter.writeTagAndLength(encoded, 0x30, Math.addExact(serial.length, Math.addExact(date.length, reason.length)));
        encoded.write(serial);
        encoded.write(date);
        encoded.write(reason);
        return encoded.toByteArray();
    }

    private byte[] extensions(BigInteger number) throws IOException {
        Objects.requireNonNull(number, "crlNumber");
        if (number.signum() < 0 || number.bitLength() > 159) {
            throw new IllegalArgumentException("CRL number is outside the issued range");
        }
        byte[] numberExtension = extension(20, tlv(0x02, number.toByteArray()));
        ByteArrayOutputStream values = new ByteArrayOutputStream();
        values.write(authorityKeyIdentifier);
        values.write(numberExtension);
        if (baseNumber.isPresent()) {
            values.write(extension(27, tlv(0x02, baseNumber.orElseThrow().toByteArray()), true));
        }
        return tlv(0xa0, tlv(0x30, values.toByteArray()));
    }

    private static byte[] extension(int oidLastArc, byte[] value) throws IOException {
        return extension(oidLastArc, value, false);
    }

    private static byte[] extension(int oidLastArc, byte[] value, boolean critical) throws IOException {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        StreamingDerWriter.writeTagAndLength(encoded, 0x30, Math.addExact(critical ? 8 : 5, StreamingDerWriter.encodedLength(value.length)));
        // Closed RFC 5280 extension schema: CRL number, reason, authority key identifier.
        encoded.write(new byte[] {0x06, 0x03, 0x55, 0x1d, (byte) oidLastArc});
        if (critical) { encoded.write(new byte[] {0x01, 0x01, (byte) 0xff}); }
        encoded.write(tlv(0x04, value));
        return encoded.toByteArray();
    }

    private static byte[] time(Instant instant) throws IOException {
        int year;
        try { year = instant.atOffset(ZoneOffset.UTC).getYear(); }
        catch (java.time.DateTimeException invalid) { throw new IOException("CRL time is not representable", invalid); }
        if (year < 1 || year > 9999) { throw new IOException("CRL time is outside the X.509 year range"); }
        boolean utc = year >= 1950 && year <= 2049;
        byte[] value = (utc ? UTC_TIME : GENERAL_TIME).format(instant).getBytes(StandardCharsets.US_ASCII);
        return tlv(utc ? 0x17 : 0x18, value);
    }

    private static byte[] tlv(int tag, byte[] value) throws IOException {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        StreamingDerWriter.writeTagAndLength(encoded, tag, value.length);
        encoded.write(value);
        return encoded.toByteArray();
    }

    private static int reasonCode(RevocationReason reason) throws IOException {
        return switch (reason) {
            case UNSPECIFIED -> 0;
            case KEY_COMPROMISE -> 1;
            case CA_COMPROMISE -> 2;
            case AFFILIATION_CHANGED -> 3;
            case SUPERSEDED -> 4;
            case CESSATION_OF_OPERATION -> 5;
            case CERTIFICATE_HOLD -> 6;
            case PRIVILEGE_WITHDRAWN -> 9;
            case AA_COMPROMISE -> 10;
            case REMOVE_FROM_CRL -> 8;
        };
    }

    private static IOException divergence() { return new IOException("Full CRL source diverged between passes"); }
}
