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
package zeroecho.pki.impl.framework.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/**
 * Focused incremental canonical-DER structural validator.
 *
 * <p>
 * Validation consumes exactly one object, rejects indefinite and non-minimal
 * lengths, and checks canonical primitive forms without materializing aggregate
 * content. Aggregate offsets and lengths use {@code long}. The fixed structural
 * depth is an X.509 adapter capability, not an aggregate byte or cardinality
 * limit.
 * </p>
 *
 * <p>
 * Canonical SET ordering uses two monotonic comparison readers per active,
 * fixed-bounded structure depth. Each reader moves forward only, so validation
 * is {@code O(B)} for encoded size {@code B} with auxiliary heap bounded by the
 * fixed depth and comparison-buffer size.
 * </p>
 */
// The aggregate branches implement one closed canonical-DER grammar.
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.NPathComplexity", "PMD.AvoidLiteralsInIfCondition",
        "PMD.CommentDefaultAccessModifier" })
public final class StreamingDerReader {

    private static final int BUFFER_BYTES = 16 * 1024;
    private static final int MAXIMUM_X509_STRUCTURE_DEPTH = 64;
    private static final int HIGH_TAG_NUMBER = 0x1f;
    private static final int CONTINUATION_BIT = 0x80;
    private static final long SHORT_LENGTH_LIMIT = 128L;

    /** Creates a stateless canonical-DER reader. */
    public StreamingDerReader() {
        // Stateless.
    }

    /**
     * Validates one complete canonical DER object held in an explicitly bounded
     * byte array.
     *
     * <p>
     * This convenience entry point is intended for individual adapter values such
     * as PKCS#10 requests and subject-public-key information. The caller-selected
     * {@code maximumBytes} is enforced before parsing. Repeatable stream sources,
     * especially aggregate CRLs, should use
     * {@link #validate(RepeatableContent, CancellationSignal)} instead.
     * </p>
     *
     * @param encoded complete DER object
     * @param maximumBytes positive caller-selected element limit in bytes
     * @return exact encoded length
     * @throws NullPointerException if {@code encoded} is {@code null}
     * @throws IllegalArgumentException if {@code maximumBytes} is not positive
     * @throws IOException if the input exceeds {@code maximumBytes}, is malformed,
     *                     non-canonical, truncated, or contains trailing data
     */
    public int validate(byte[] encoded, int maximumBytes) throws IOException {
        Objects.requireNonNull(encoded, "encoded");
        if (maximumBytes <= 0) {
            throw new IllegalArgumentException("maximumBytes must be positive");
        }
        if (encoded.length > maximumBytes) {
            throw new IOException("DER object exceeds adapter element limit: code=ADAPTER_ELEMENT_LIMIT_EXCEEDED");
        }
        long length = validate(new ByteArrayContent(encoded), CancellationSignal.NONE);
        try {
            return Math.toIntExact(length);
        } catch (ArithmeticException exception) {
            throw new IOException("DER length overflow: code=CONTENT_LENGTH_OVERFLOW", exception);
        }
    }

    /**
     * Validates one canonical DER {@code SubjectPublicKeyInfo} value, including
     * the X.509 requirement that its public-key BIT STRING have zero unused bits.
     *
     * @param encoded complete DER subject-public-key information
     * @param maximumBytes positive caller-selected element limit in bytes
     * @return exact encoded length
     * @throws NullPointerException if {@code encoded} is {@code null}
     * @throws IllegalArgumentException if {@code maximumBytes} is not positive
     * @throws IOException if the value exceeds the limit or is not one canonical
     *                     {@code SubjectPublicKeyInfo}
     */
    public int validateSubjectPublicKeyInfo(byte[] encoded, int maximumBytes) throws IOException {
        int length = validate(encoded, maximumBytes);
        try (CountedInput input = new CountedInput(new ByteArrayInputStream(encoded))) {
            Header root = HeaderReader.read(input);
            requireSequence(root);
            long rootEnd = checkedAdd(input.position(), root.length());
            Header algorithm = HeaderReader.read(input);
            requireSequence(algorithm);
            skip(input, algorithm.length(), CancellationSignal.NONE);
            Header publicKey = HeaderReader.read(input);
            if (!publicKey.universal() || publicKey.tagNumber() != 3 || publicKey.constructed()
                    || publicKey.length() < 1L || input.readRequired() != 0) {
                throw new IOException("Malformed SubjectPublicKeyInfo BIT STRING");
            }
            skip(input, publicKey.length() - 1L, CancellationSignal.NONE);
            if (input.position() != rootEnd || input.position() != length) {
                throw new IOException("Malformed SubjectPublicKeyInfo structure");
            }
        }
        return length;
    }

    /**
     * Validates one complete canonical DER object.
     *
     * @param content repeatable original content
     * @param cancellation cancellation signal
     * @return exact encoded length
     * @throws IOException if input fails, is malformed, non-canonical, truncated,
     *                     or has trailing data
     */
    public long validate(RepeatableContent content, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(cancellation, "cancellation");
        try (CountedInput input = new CountedInput(content.openStream());
                OrderingContext ordering = new OrderingContext(content)) {
            Header root = HeaderReader.read(input);
            readValue(input, root, 0, cancellation, ordering);
            if (input.read() >= 0) {
                throw new IOException("Trailing DER data: code=TRAILING_DER_DATA");
            }
            long length = input.position();
            if (content.length().isPresent() && length != content.length().getAsLong()) {
                throw new IOException("DER length mismatch: code=NON_CANONICAL_DER");
            }
            return length;
        }
    }

    /**
     * Validates bounded canonical DER and locates the signature algorithm and SPKI
     * in one complete unsigned certificate TBS. This structural inspection does
     * not validate certificate policy, names, validity semantics or signatures.
     * The returned spans refer to the original bytes without reencoding them.
     *
     * @param encoded complete unsigned TBSCertificate DER, borrowed for this call
     * @param maximumBytes positive caller-selected element bound
     * @return immutable offsets and lengths within the supplied TBS
     * @throws NullPointerException if the input is null
     * @throws IllegalArgumentException if the bound is not positive
     * @throws IOException if DER, certificate field tags or span bounds are invalid
     */
    public CertificateTbsLayout inspectUnsignedCertificateTbs(byte[] encoded, int maximumBytes) throws IOException {
        int length = validate(encoded, maximumBytes);
        try (CountedInput input = new CountedInput(new ByteArrayInputStream(encoded))) {
            Header tbs = HeaderReader.read(input);
            requireSequence(tbs);
            if (checkedAdd(tbs.valueOffset(), tbs.length()) != length) {
                throw new IOException("Unsigned certificate TBS has trailing data");
            }
            AlgorithmAndKey fields = inspectTbs(new ByteArrayContent(encoded), SignedObjectKind.CERTIFICATE,
                    tbs, CancellationSignal.NONE, null);
            return new CertificateTbsLayout(length, Math.toIntExact(fields.algorithmOffset()),
                    Math.toIntExact(fields.algorithmLength()), Math.toIntExact(fields.spkiOffset()),
                    Math.toIntExact(fields.spkiLength()));
        }
    }

    /**
     * Validates and locates the signed portions of one certificate or CRL.
     *
     * @param content original repeatable DER
     * @param kind signed-object grammar
     * @param cancellation cancellation signal
     * @return immutable long-offset layout
     * @throws IOException if structure or canonicality is invalid
     */
    public SignedObjectLayout inspectSignedObject(RepeatableContent content, SignedObjectKind kind,
            CancellationSignal cancellation) throws IOException {
        return inspectSignedObject(content, kind, cancellation, null);
    }

    /**
     * Inspects one canonical CRL and its CRL-level number extensions without materialization.
     * Requires one noncritical CRL number and permits at most one critical delta indicator.
     * Each recognized extension contains exactly one nonnegative canonical DER INTEGER
     * of at most 159 bits; entry extensions do not provide these coordinates. This
     * does not verify a signature, issuer identity, content ownership or base eligibility.
     * Work is O(B) over encoded bytes with fixed-bounded streaming memory.
     * @param content repeatable complete CRL content
     * @param cancellation cancellation checked during traversal
     * @return structural layout and exact bounded semantic numbers
     * @throws IOException if DER or recognized extensions are invalid, missing, duplicated,
     *         incorrectly critical, truncated, or cancellation is requested
     */
    public CrlSemanticLayout inspectCrlSemantics(RepeatableContent content, CancellationSignal cancellation)
            throws IOException {
        CrlNumbers numbers = new CrlNumbers();
        SignedObjectLayout layout = inspectSignedObject(content, SignedObjectKind.CRL, cancellation, numbers);
        if (numbers.crlNumber == null) { throw new IOException("CRL number extension is missing"); }
        cancellation.throwIfCancelled();
        return new CrlSemanticLayout(layout, numbers.crlNumber, Optional.ofNullable(numbers.deltaIndicator));
    }

    /**
     * Resource-free semantic projection of a structurally valid CRL.
     * @param layout exact signed-object spans and update times
     * @param crlNumber required nonnegative CRL number, at most 159 bits
     * @param deltaIndicator optional nonnegative base number, at most 159 bits
     */
    public record CrlSemanticLayout(SignedObjectLayout layout, BigInteger crlNumber,
            Optional<BigInteger> deltaIndicator) {
        /** Validates the immutable bounded projection. */
        public CrlSemanticLayout {
            Objects.requireNonNull(layout, "layout");
            Objects.requireNonNull(crlNumber, "crlNumber");
            Objects.requireNonNull(deltaIndicator, "deltaIndicator");
            if (crlNumber.signum() < 0 || crlNumber.bitLength() > 159
                    || deltaIndicator.filter(value -> value.signum() < 0 || value.bitLength() > 159).isPresent()) {
                throw new IllegalArgumentException("CRL semantic number is outside its bound");
            }
        }
    }

    /** Per-inspection CRL extension values used to validate number relationships. */
    private static final class CrlNumbers {
        private BigInteger crlNumber;
        private BigInteger deltaIndicator;
    }

    private SignedObjectLayout inspectSignedObject(RepeatableContent content, SignedObjectKind kind,
            CancellationSignal cancellation, CrlNumbers numbers) throws IOException {
        validate(content, cancellation);
        try (CountedInput input = new CountedInput(content.openStream())) {
            Header outer = HeaderReader.read(input);
            requireSequence(outer);
            long outerEnd = checkedAdd(input.position(), outer.length());
            Header tbs = HeaderReader.read(input);
            requireSequence(tbs);
            long tbsTotalLength = tbs.encodedLength();
            AlgorithmAndKey inner = inspectTbs(content, kind, tbs, cancellation, numbers);
            skip(input, tbs.length(), cancellation);
            Header outerAlgorithm = HeaderReader.read(input);
            requireSequence(outerAlgorithm);
            skip(input, outerAlgorithm.length(), cancellation);
            Header signature = HeaderReader.read(input);
            if (!signature.universal() || signature.tagNumber() != 3 || signature.constructed()
                    || signature.length() < 1L) {
                throw new IOException("Malformed signed-object signature BIT STRING");
            }
            int unused = input.readRequired();
            if (unused != 0) {
                throw new IOException("Signed-object signature has unused bits");
            }
            long signatureOffset = input.position();
            skip(input, signature.length() - 1L, cancellation);
            if (input.position() != outerEnd || input.read() >= 0) {
                throw new IOException("Signed object has trailing data");
            }
            return new SignedObjectLayout(tbs.start(), tbsTotalLength, inner.algorithmOffset(),
                    inner.algorithmLength(), outerAlgorithm.start(), outerAlgorithm.encodedLength(),
                    inner.spkiOffset(), inner.spkiLength(), signatureOffset, signature.length() - 1L,
                    inner.issuerOffset(), inner.issuerLength(), inner.thisUpdate(), inner.nextUpdate());
        }
    }

    private static AlgorithmAndKey inspectTbs(RepeatableContent content, SignedObjectKind kind, Header tbs,
            CancellationSignal cancellation, CrlNumbers numbers) throws IOException {
        try (CountedInput input = new CountedInput(content.openStream())) {
            skip(input, tbs.valueOffset(), cancellation);
            long tbsEnd = checkedAdd(tbs.valueOffset(), tbs.length());
            Header child = kind == SignedObjectKind.CERTIFICATE
                    ? readWithin(input, tbsEnd) : HeaderReader.read(input);
            if (kind == SignedObjectKind.CERTIFICATE) {
                if (child.contextSpecific(0)) {
                    skip(input, child.length(), cancellation);
                    child = readWithin(input, tbsEnd);
                }
                requireUniversal(child, 2);
                skip(input, child.length(), cancellation);
                child = readWithin(input, tbsEnd);
            } else {
                return inspectCrlTbs(input, tbs, child, cancellation, numbers);
            }
            requireSequence(child);
            long algorithmOffset = child.start();
            long algorithmLength = child.encodedLength();
            skip(input, child.length(), cancellation);
            for (int index = 0; index < 3; index++) {
                Header field = readWithin(input, tbsEnd);
                requireSequence(field);
                skip(input, field.length(), cancellation);
            }
            Header spki = readWithin(input, tbsEnd);
            requireSequence(spki);
            return new AlgorithmAndKey(algorithmOffset, algorithmLength, spki.start(), spki.encodedLength(),
                    -1L, 0L, Optional.empty(), Optional.empty());
        }
    }

    private static AlgorithmAndKey inspectCrlTbs(CountedInput input, Header tbs, Header firstChild,
            CancellationSignal cancellation, CrlNumbers numbers) throws IOException {
        long tbsEnd = checkedAdd(tbs.valueOffset(), tbs.length());
        Header child = firstChild;
        boolean v2 = false;
        if (child.universal() && child.tagNumber() == 2) {
            requireCrlVersion(input, child, cancellation);
            v2 = true;
            child = readWithin(input, tbsEnd);
        }

        requireAlgorithmIdentifier(input, child, cancellation);
        long algorithmOffset = child.start();
        long algorithmLength = child.encodedLength();

        Header issuer = readWithin(input, tbsEnd);
        requireSequence(issuer);
        if (issuer.length() == 0L) {
            throw new IOException("TBSCertList issuer Name must not be empty");
        }
        skip(input, issuer.length(), cancellation);

        Header thisUpdateHeader = readWithin(input, tbsEnd);
        Instant thisUpdate = readCrlTime(input, thisUpdateHeader);
        Optional<Instant> nextUpdate = Optional.empty();
        Header optional = input.position() < tbsEnd ? readWithin(input, tbsEnd) : null;
        if (optional != null && isTime(optional)) {
            Instant parsedNextUpdate = readCrlTime(input, optional);
            if (!parsedNextUpdate.isAfter(thisUpdate)) {
                throw new IOException("CRL nextUpdate must follow thisUpdate");
            }
            nextUpdate = Optional.of(parsedNextUpdate);
            optional = input.position() < tbsEnd ? readWithin(input, tbsEnd) : null;
        }
        if (optional != null && optional.universal() && optional.tagNumber() == 16) {
            readRevokedCertificates(input, optional, v2, cancellation);
            optional = input.position() < tbsEnd ? readWithin(input, tbsEnd) : null;
        }
        if (optional != null && optional.contextSpecific(0)) {
            if (!v2) {
                throw new IOException("CRL extensions require TBSCertList v2");
            }
            readExplicitExtensions(input, optional, cancellation, numbers);
            optional = input.position() < tbsEnd ? readWithin(input, tbsEnd) : null;
        }
        if (optional != null || input.position() != tbsEnd) {
            throw new IOException("Malformed TBSCertList optional fields");
        }
        return new AlgorithmAndKey(algorithmOffset, algorithmLength, -1L, 0L, issuer.start(),
                issuer.encodedLength(), Optional.of(thisUpdate), nextUpdate);
    }

    private static void requireCrlVersion(CountedInput input, Header version, CancellationSignal cancellation)
            throws IOException {
        requireUniversal(version, 2);
        if (version.constructed() || version.length() != 1L || input.readRequired() != 1) {
            throw new IOException("TBSCertList version must be canonical v2(1)");
        }
        skip(input, version.length() - 1L, cancellation);
    }

    private static void requireAlgorithmIdentifier(CountedInput input, Header algorithm,
            CancellationSignal cancellation) throws IOException {
        requireSequence(algorithm);
        long end = checkedAdd(algorithm.valueOffset(), algorithm.length());
        Header oid = readWithin(input, end);
        requirePrimitiveUniversal(oid, 6);
        PrimitiveReader.read(input, oid, cancellation);
        if (input.position() < end) {
            Header parameters = readWithin(input, end);
            skip(input, parameters.length(), cancellation);
        }
        if (input.position() != end) {
            throw new IOException("Malformed AlgorithmIdentifier");
        }
    }

    private static Instant readCrlTime(CountedInput input, Header time) throws IOException {
        if (!isTime(time) || time.constructed()) {
            throw new IOException("Expected TBSCertList Time");
        }
        return PrimitiveReader.readTime(input, time.length(), time.tagNumber() == 24).toInstant(ZoneOffset.UTC);
    }

    private static boolean isTime(Header header) {
        return header.universal() && (header.tagNumber() == 23 || header.tagNumber() == 24);
    }

    private static void readRevokedCertificates(CountedInput input, Header revokedCertificates, boolean v2,
            CancellationSignal cancellation) throws IOException {
        requireSequence(revokedCertificates);
        long end = checkedAdd(revokedCertificates.valueOffset(), revokedCertificates.length());
        while (input.position() < end) {
            cancellation.throwIfCancelled();
            Header entry = readWithin(input, end);
            requireSequence(entry);
            readRevokedCertificate(input, entry, v2, cancellation);
        }
        if (input.position() != end) {
            throw new IOException("Malformed revokedCertificates");
        }
    }

    private static void readRevokedCertificate(CountedInput input, Header entry, boolean v2,
            CancellationSignal cancellation) throws IOException {
        long end = checkedAdd(entry.valueOffset(), entry.length());
        Header serial = readWithin(input, end);
        readPositiveSerial(input, serial, cancellation);
        Header revocationDate = readWithin(input, end);
        readCrlTime(input, revocationDate);
        if (input.position() < end) {
            if (!v2) {
                throw new IOException("CRL entry extensions require TBSCertList v2");
            }
            Header extensions = readWithin(input, end);
            readExtensions(input, extensions, cancellation);
        }
        if (input.position() != end) {
            throw new IOException("Malformed revoked certificate entry");
        }
    }

    private static void readPositiveSerial(CountedInput input, Header serial, CancellationSignal cancellation)
            throws IOException {
        requirePrimitiveUniversal(serial, 2);
        if (serial.length() == 0L || serial.length() > 20L) {
            throw new IOException("CRL serial number must be positive");
        }
        int first = input.readRequired();
        if ((first & CONTINUATION_BIT) != 0 || first == 0 && serial.length() == 1L) {
            throw new IOException("CRL serial number must be positive");
        }
        skip(input, serial.length() - 1L, cancellation);
    }

    private static void readExplicitExtensions(CountedInput input, Header explicit,
            CancellationSignal cancellation, CrlNumbers numbers) throws IOException {
        if (!explicit.constructed()) {
            throw new IOException("CRL extensions must be [0] EXPLICIT");
        }
        long end = checkedAdd(explicit.valueOffset(), explicit.length());
        Header extensions = readWithin(input, end);
        readExtensions(input, extensions, cancellation, numbers);
        if (input.position() != end) {
            throw new IOException("Malformed explicit CRL extensions");
        }
    }

    private static void readExtensions(CountedInput input, Header extensions, CancellationSignal cancellation)
            throws IOException {
        readExtensions(input, extensions, cancellation, null);
    }

    private static void readExtensions(CountedInput input, Header extensions, CancellationSignal cancellation,
            CrlNumbers numbers) throws IOException {
        requireSequence(extensions);
        long end = checkedAdd(extensions.valueOffset(), extensions.length());
        if (input.position() == end) {
            throw new IOException("Extensions must contain at least one Extension");
        }
        while (input.position() < end) {
            cancellation.throwIfCancelled();
            Header extension = readWithin(input, end);
            requireSequence(extension);
            readExtension(input, extension, cancellation, numbers);
        }
        if (input.position() != end) {
            throw new IOException("Malformed Extensions");
        }
    }

    private static void readExtension(CountedInput input, Header extension, CancellationSignal cancellation,
            CrlNumbers numbers) throws IOException {
        long end = checkedAdd(extension.valueOffset(), extension.length());
        Header oid = readWithin(input, end);
        requirePrimitiveUniversal(oid, 6);
        int recognized = 0;
        if (numbers != null && oid.length() == 3L) {
            // The preceding canonical-DER pass already validated this OID encoding.
            int first = input.readRequired();
            int second = input.readRequired();
            int last = input.readRequired();
            if (first == 0x55 && second == 0x1d && (last == 20 || last == 27)) { recognized = last; }
        } else {
            PrimitiveReader.read(input, oid, cancellation);
        }
        boolean critical = false;
        Header value = readWithin(input, end);
        if (value.universal() && value.tagNumber() == 1) {
            requirePrimitiveUniversal(value, 1);
            if (value.length() != 1L || input.readRequired() != 0xff) {
                throw new IOException("Extension critical DEFAULT FALSE must be omitted");
            }
            critical = true;
            value = readWithin(input, end);
        }
        requirePrimitiveUniversal(value, 4);
        if (recognized == 0) {
            skip(input, value.length(), cancellation);
        } else {
            if (critical != (recognized == 27)
                    || recognized == 20 && numbers.crlNumber != null
                    || recognized == 27 && numbers.deltaIndicator != null) {
                throw new IOException("CRL number extension is duplicated or incorrectly critical");
            }
            BigInteger number = readCrlNumber(input, value, cancellation);
            if (recognized == 20) { numbers.crlNumber = number; }
            else { numbers.deltaIndicator = number; }
        }
        if (input.position() != end) {
            throw new IOException("Malformed Extension");
        }
    }

    private static BigInteger readCrlNumber(CountedInput input, Header octets, CancellationSignal cancellation)
            throws IOException {
        cancellation.throwIfCancelled();
        // A 159-bit nonnegative INTEGER needs at most 20 value bytes and two TLV bytes.
        if (octets.length() < 3L || octets.length() > 22L) {
            throw new IOException("CRL number encoding exceeds its bound");
        }
        long end = checkedAdd(octets.valueOffset(), octets.length());
        Header integer = readWithin(input, end);
        requirePrimitiveUniversal(integer, 2);
        if (integer.length() < 1L || integer.length() > 20L
                || checkedAdd(integer.valueOffset(), integer.length()) != end) {
            throw new IOException("CRL number must contain one bounded INTEGER");
        }
        byte[] bytes = new byte[(int) integer.length()];
        for (int index = 0; index < bytes.length; index++) { bytes[index] = (byte) input.readRequired(); }
        if ((bytes[0] & 0x80) != 0 || bytes.length > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0) {
            throw new IOException("CRL number INTEGER is negative or noncanonical");
        }
        BigInteger number = new BigInteger(bytes);
        if (number.bitLength() > 159) { throw new IOException("CRL number exceeds 159 bits"); }
        return number;
    }

    private static Header readWithin(CountedInput input, long end) throws IOException {
        if (input.position() >= end) {
            throw new IOException("Missing required DER field");
        }
        Header header = HeaderReader.read(input);
        if (checkedAdd(input.position(), header.length()) > end) {
            throw new IOException("DER field exceeds enclosing structure");
        }
        return header;
    }

    private static void requirePrimitiveUniversal(Header header, int tagNumber) throws IOException {
        requireUniversal(header, tagNumber);
        if (header.constructed()) {
            throw new IOException("Expected primitive DER field");
        }
    }

    private static void requireSequence(Header header) throws IOException {
        requireUniversal(header, 16);
        if (!header.constructed()) {
            throw new IOException("Expected constructed DER SEQUENCE");
        }
    }

    private static void requireUniversal(Header header, int tagNumber) throws IOException {
        if (!header.universal() || header.tagNumber() != tagNumber) {
            throw new IOException("Unexpected signed-object DER field");
        }
    }

    private static void readValue(CountedInput input, Header header, int depth, CancellationSignal cancellation,
            OrderingContext ordering) throws IOException {
        if (depth >= MAXIMUM_X509_STRUCTURE_DEPTH) {
            throw new IOException("DER nesting exceeds X.509 adapter capability");
        }
        long end = checkedAdd(input.position(), header.length());
        if (header.constructed()) {
            requireConstructedForm(header);
            SetOrdering setOrdering = header.universal() && header.tagNumber() == 17
                    ? ordering.begin(depth, header.valueOffset(), cancellation)
                    : null;
            while (input.position() < end) {
                cancellation.throwIfCancelled();
                Header child = HeaderReader.read(input);
                long childEnd = checkedAdd(input.position(), child.length());
                if (childEnd > end) {
                    throw new IOException("DER child exceeds parent: code=MALFORMED_SIGNED_OBJECT");
                }
                readValue(input, child, depth + 1, cancellation, ordering);
                if (setOrdering != null && setOrdering.accept(child.encodedLength(), cancellation) > 0) {
                    throw new IOException("Non-canonical DER SET ordering: code=NON_CANONICAL_DER");
                }
            }
            if (setOrdering != null) {
                setOrdering.finish(cancellation);
            }
        } else {
            requirePrimitiveForm(header);
            PrimitiveReader.read(input, header, cancellation);
        }
        if (input.position() != end) {
            throw new IOException("DER value length mismatch: code=MALFORMED_SIGNED_OBJECT");
        }
    }

    private static void requireConstructedForm(Header header) throws IOException {
        if (header.universal() && header.tagNumber() != 16 && header.tagNumber() != 17) {
            throw new IOException("Constructed primitive is not canonical DER");
        }
    }

    private static void requirePrimitiveForm(Header header) throws IOException {
        if (header.universal() && (header.tagNumber() == 16 || header.tagNumber() == 17)) {
            throw new IOException("Primitive container is not canonical DER");
        }
    }

    private static void skip(CountedInput input, long length, CancellationSignal cancellation) throws IOException {
        long remaining = length;
        if (remaining == 0L) {
            return;
        }
        byte[] buffer = input.scratch();
        while (remaining != 0L) {
            cancellation.throwIfCancelled();
            int read = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (read < 0) {
                throw new IOException("Truncated DER value");
            }
            if (read == 0) {
                input.readRequired();
                remaining--;
            } else {
                remaining -= read;
            }
        }
    }

    private static long checkedAdd(long left, long right) throws IOException {
        try {
            return Math.addExact(left, right);
        } catch (ArithmeticException exception) {
            throw new IOException("DER length overflow: code=CONTENT_LENGTH_OVERFLOW", exception);
        }
    }

    /**
     * Supported signed-object grammar.
     */
    public enum SignedObjectKind {
        /** X.509 Certificate. */
        CERTIFICATE,
        /** X.509 CertificateList (CRL). */
        CRL
    }

    /**
     * Exact offsets into the validated original DER.
     *
     * @param tbsOffset complete TBS TLV offset
     * @param tbsLength complete TBS TLV length
     * @param tbsAlgorithmOffset TBS AlgorithmIdentifier TLV offset
     * @param tbsAlgorithmLength TBS AlgorithmIdentifier TLV length
     * @param outerAlgorithmOffset outer AlgorithmIdentifier TLV offset
     * @param outerAlgorithmLength outer AlgorithmIdentifier TLV length
     * @param subjectPublicKeyInfoOffset SPKI TLV offset, or {@code -1} for CRLs
     * @param subjectPublicKeyInfoLength SPKI TLV length, or zero for CRLs
     * @param signatureOffset signature octets offset
     * @param signatureLength signature octets length
     * @param issuerOffset issuer Name TLV offset, or {@code -1} for certificates
     * @param issuerLength issuer Name TLV length, or zero for certificates
     * @param thisUpdate exact CRL {@code thisUpdate}, or empty for certificates
     * @param nextUpdate exact optional CRL {@code nextUpdate}, or empty when absent
     *                   and for certificates
     */
    public record SignedObjectLayout(long tbsOffset, long tbsLength, long tbsAlgorithmOffset,
            long tbsAlgorithmLength, long outerAlgorithmOffset, long outerAlgorithmLength,
            long subjectPublicKeyInfoOffset, long subjectPublicKeyInfoLength, long signatureOffset,
            long signatureLength, long issuerOffset, long issuerLength, Optional<Instant> thisUpdate,
            Optional<Instant> nextUpdate) {
        /**
         * Creates an immutable layout for one validated signed object.
         *
         * @throws NullPointerException if either time container is {@code null}
         */
        public SignedObjectLayout {
            Objects.requireNonNull(thisUpdate, "thisUpdate");
            Objects.requireNonNull(nextUpdate, "nextUpdate");
        }
    }

    /**
     * Immutable complete-TLV spans within one validated unsigned certificate TBS.
     *
     * @param encodedLength complete TBS length
     * @param algorithmOffset signature AlgorithmIdentifier TLV offset
     * @param algorithmLength signature AlgorithmIdentifier TLV length
     * @param subjectPublicKeyInfoOffset SPKI TLV offset
     * @param subjectPublicKeyInfoLength SPKI TLV length
     */
    public record CertificateTbsLayout(int encodedLength, int algorithmOffset, int algorithmLength,
            int subjectPublicKeyInfoOffset, int subjectPublicKeyInfoLength) {
        /**
         * Validates positive lengths and overflow-safe containment of both spans.
         * @throws IllegalArgumentException if a length is not positive
         * @throws IndexOutOfBoundsException if either span lies outside the TBS
         */
        public CertificateTbsLayout {
            if (encodedLength <= 0 || algorithmLength <= 0 || subjectPublicKeyInfoLength <= 0) {
                throw new IllegalArgumentException("Certificate TBS span length must be positive");
            }
            Objects.checkFromIndexSize(algorithmOffset, algorithmLength, encodedLength);
            Objects.checkFromIndexSize(subjectPublicKeyInfoOffset, subjectPublicKeyInfoLength, encodedLength);
        }
    }

    private record AlgorithmAndKey(long algorithmOffset, long algorithmLength, long spkiOffset, long spkiLength,
            long issuerOffset, long issuerLength, Optional<Instant> thisUpdate, Optional<Instant> nextUpdate) {
    }

    private record Header(int firstTag, int tagNumber, long length, long start, long valueOffset) {
        private boolean constructed() {
            return (firstTag & 0x20) != 0;
        }

        private boolean universal() {
            return (firstTag & 0xc0) == 0;
        }

        private boolean contextSpecific(int expectedTag) {
            return (firstTag & 0xc0) == 0x80 && tagNumber == expectedTag;
        }

        private long encodedLength() throws IOException {
            return checkedAdd(valueOffset - start, length);
        }
    }

    /** Canonical DER tag and length decoder. */
    private static final class HeaderReader {
        private static Header read(CountedInput input) throws IOException {
            long start = input.position();
            int firstTag = input.readRequired();
            if (firstTag == 0) {
                throw new IOException("DER end-of-contents is forbidden");
            }
            int tagNumber = readTagNumber(input, firstTag);
            long length = readLength(input);
            return new Header(firstTag, tagNumber, length, start, input.position());
        }

        private static int readTagNumber(CountedInput input, int firstTag) throws IOException {
            int tagNumber = firstTag & HIGH_TAG_NUMBER;
            if (tagNumber == HIGH_TAG_NUMBER) {
                int octet = input.readRequired();
                if ((octet & 0x7f) == 0) {
                    throw new IOException("Non-minimal DER high tag");
                }
                tagNumber = 0;
                while (true) {
                    if (tagNumber > (Integer.MAX_VALUE >>> 7)) {
                        throw new IOException("DER tag number overflow: code=CONTENT_LENGTH_OVERFLOW");
                    }
                    tagNumber = (tagNumber << 7) | (octet & 0x7f);
                    if ((octet & CONTINUATION_BIT) == 0) {
                        break;
                    }
                    octet = input.readRequired();
                }
                if (tagNumber < HIGH_TAG_NUMBER) {
                    throw new IOException("Non-minimal DER high tag");
                }
            }
            return tagNumber;
        }

        private static long readLength(CountedInput input) throws IOException {
            int firstLength = input.readRequired();
            if (firstLength < CONTINUATION_BIT) {
                return firstLength;
            }
            int octets = firstLength & 0x7f;
            if (octets == 0) {
                throw new IOException("Indefinite DER length: code=NON_CANONICAL_DER");
            }
            if (octets > Long.BYTES) {
                throw new IOException("DER length is not representable");
            }
            int first = input.readRequired();
            if (first == 0) {
                throw new IOException("Non-minimal DER length: code=NON_CANONICAL_DER");
            }
            long length = first;
            for (int index = 1; index < octets; index++) {
                if (length > (Long.MAX_VALUE >>> Byte.SIZE)) {
                    throw new IOException("DER length overflow: code=CONTENT_LENGTH_OVERFLOW");
                }
                length = (length << Byte.SIZE) | input.readRequired();
            }
            if (length < SHORT_LENGTH_LIMIT) {
                throw new IOException("Non-minimal DER length: code=NON_CANONICAL_DER");
            }
            return length;
        }
    }

    /** Fixed-depth owner of monotonic comparison streams for DER SET values. */
    private static final class OrderingContext implements AutoCloseable {
        private final RepeatableContent content;
        private final SetOrdering[] levels = new SetOrdering[MAXIMUM_X509_STRUCTURE_DEPTH];

        private OrderingContext(RepeatableContent content) {
            this.content = content;
        }

        private SetOrdering begin(int depth, long valueOffset, CancellationSignal cancellation) throws IOException {
            SetOrdering ordering = levels[depth];
            if (ordering == null) {
                ordering = new SetOrdering(content);
                levels[depth] = ordering;
            }
            ordering.begin(valueOffset, cancellation);
            return ordering;
        }

        @Override
        public void close() throws IOException {
            IOException failure = null;
            for (SetOrdering ordering : levels) {
                if (ordering == null) {
                    continue;
                }
                try {
                    ordering.closeStreams();
                } catch (IOException exception) {
                    if (failure == null) {
                        failure = exception;
                    } else {
                        failure.addSuppressed(exception);
                    }
                }
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /** Adjacent-child comparator whose two source passes only move forward. */
    private static final class SetOrdering {
        private static final long NO_PREVIOUS_VALUE = -1L;

        private final CountedInput left;
        private final CountedInput right;
        private final byte[] leftBuffer = new byte[BUFFER_BYTES];
        private final byte[] rightBuffer = new byte[BUFFER_BYTES];
        private long previousLength = NO_PREVIOUS_VALUE;

        private SetOrdering(RepeatableContent content) throws IOException {
            left = new CountedInput(content.openStream());
            try {
                right = new CountedInput(content.openStream());
            } catch (IOException exception) {
                left.close();
                throw exception;
            }
        }

        private void begin(long valueOffset, CancellationSignal cancellation) throws IOException {
            advanceTo(left, valueOffset, leftBuffer, cancellation);
            advanceTo(right, valueOffset, rightBuffer, cancellation);
            previousLength = NO_PREVIOUS_VALUE;
        }

        private int accept(long currentLength, CancellationSignal cancellation) throws IOException {
            if (previousLength == NO_PREVIOUS_VALUE) {
                skipWithBuffer(right, currentLength, rightBuffer, cancellation);
                previousLength = currentLength;
                return 0;
            }
            int comparison = compare(previousLength, currentLength, cancellation);
            previousLength = currentLength;
            return comparison;
        }

        private void finish(CancellationSignal cancellation) throws IOException {
            if (previousLength != NO_PREVIOUS_VALUE) {
                skipWithBuffer(left, previousLength, leftBuffer, cancellation);
            }
        }

        private int compare(long leftLength, long rightLength, CancellationSignal cancellation) throws IOException {
            long common = Math.min(leftLength, rightLength);
            int comparison = 0;
            long remaining = common;
            while (remaining != 0L) {
                cancellation.throwIfCancelled();
                int count = (int) Math.min(BUFFER_BYTES, remaining);
                readExactly(left, leftBuffer, count);
                readExactly(right, rightBuffer, count);
                if (comparison == 0) {
                    comparison = compareBuffers(leftBuffer, rightBuffer, count);
                }
                remaining -= count;
            }
            skipWithBuffer(left, leftLength - common, leftBuffer, cancellation);
            skipWithBuffer(right, rightLength - common, rightBuffer, cancellation);
            return comparison == 0 ? Long.compare(leftLength, rightLength) : comparison;
        }

        private void closeStreams() throws IOException {
            IOException failure = null;
            try {
                left.close();
            } catch (IOException exception) {
                failure = exception;
            }
            try {
                right.close();
            } catch (IOException exception) {
                if (failure == null) {
                    failure = exception;
                } else {
                    failure.addSuppressed(exception);
                }
            }
            if (failure != null) {
                throw failure;
            }
        }

        private static void advanceTo(CountedInput input, long position, byte[] buffer,
                CancellationSignal cancellation) throws IOException {
            if (input.position() > position) {
                throw new IOException("DER SET comparison stream moved backward");
            }
            skipWithBuffer(input, position - input.position(), buffer, cancellation);
        }

        private static void skipWithBuffer(InputStream input, long length, byte[] buffer,
                CancellationSignal cancellation) throws IOException {
            long remaining = length;
            while (remaining != 0L) {
                cancellation.throwIfCancelled();
                int count = (int) Math.min(buffer.length, remaining);
                readExactly(input, buffer, count);
                remaining -= count;
            }
        }

        private static void readExactly(InputStream input, byte[] buffer, int length) throws IOException {
            int offset = 0;
            while (offset != length) {
                int count = input.read(buffer, offset, length - offset);
                if (count < 0) {
                    throw new IOException("Truncated DER value");
                }
                if (count == 0) {
                    int value = input.read();
                    if (value < 0) {
                        throw new IOException("Truncated DER value");
                    }
                    buffer[offset] = (byte) value;
                    offset++;
                } else {
                    offset += count;
                }
            }
        }

        private static int compareBuffers(byte[] left, byte[] right, int length) {
            for (int index = 0; index < length; index++) {
                int comparison = Integer.compare(Byte.toUnsignedInt(left[index]), Byte.toUnsignedInt(right[index]));
                if (comparison != 0) {
                    return comparison;
                }
            }
            return 0;
        }
    }

    /**
     * Input wrapper retaining an overflow-checked long byte position.
     */
    private static final class CountedInput extends InputStream {
        private final InputStream delegate;
        private long position;
        private byte[] scratch;

        private CountedInput(InputStream delegate) {
            super();
            this.delegate = delegate;
        }

        @Override
        public int read() throws IOException {
            int value = delegate.read();
            if (value >= 0) {
                position = checkedAdd(position, 1L);
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            int count = delegate.read(bytes, offset, length);
            if (count > 0) {
                position = checkedAdd(position, count);
            }
            return count;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        private int readRequired() throws IOException {
            int value = read();
            if (value < 0) {
                throw new IOException("Truncated DER object");
            }
            return value;
        }

        private long position() {
            return position;
        }

        private byte[] scratch() {
            if (scratch == null) {
                scratch = new byte[BUFFER_BYTES];
            }
            return scratch;
        }
    }

    /**
     * Canonical validation for primitive DER values.
     */
    private static final class PrimitiveReader {
        private static final long EMPTY_LENGTH = 0L;
        private static final long SINGLE_OCTET_LENGTH = 1L;

        private static void read(CountedInput input, Header header, CancellationSignal cancellation)
                throws IOException {
            if (!header.universal()) {
                skip(input, header.length(), cancellation);
                return;
            }
            switch (header.tagNumber()) {
                case 1 -> readBoolean(input, header.length());
                case 2, 10 -> readInteger(input, header.length(), cancellation);
                case 3 -> readBitString(input, header.length(), cancellation);
                case 4, 20 -> skip(input, header.length(), cancellation);
                case 5 -> readNull(header.length());
                case 6 -> readOid(input, header.length(), cancellation);
                case 12 -> readUtf8String(input, header.length(), cancellation);
                case 18 -> readRestrictedString(input, header.length(), StringKind.NUMERIC, cancellation);
                case 19 -> readRestrictedString(input, header.length(), StringKind.PRINTABLE, cancellation);
                case 22 -> readRestrictedString(input, header.length(), StringKind.IA5, cancellation);
                case 23 -> readTime(input, header.length(), false);
                case 24 -> readTime(input, header.length(), true);
                case 26 -> readRestrictedString(input, header.length(), StringKind.VISIBLE, cancellation);
                case 28 -> readUniversalString(input, header.length(), cancellation);
                case 30 -> readBmpString(input, header.length(), cancellation);
                default -> throw new IOException("Unsupported universal DER primitive");
            }
        }

        private static void readBoolean(CountedInput input, long length) throws IOException {
            if (length != SINGLE_OCTET_LENGTH) {
                throw new IOException("Malformed DER BOOLEAN");
            }
            int value = input.readRequired();
            if (value != 0 && value != 0xff) {
                throw new IOException("Non-canonical DER BOOLEAN");
            }
        }

        private static void readInteger(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if (length == EMPTY_LENGTH) {
                throw new IOException("Malformed DER INTEGER");
            }
            int first = input.readRequired();
            if (length > SINGLE_OCTET_LENGTH) {
                int second = input.readRequired();
                if ((first == 0 && (second & CONTINUATION_BIT) == 0)
                        || (first == 0xff && (second & CONTINUATION_BIT) != 0)) {
                    throw new IOException("Non-canonical DER INTEGER");
                }
                skip(input, length - 2L, cancellation);
            }
        }

        private static void readBitString(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if (length == EMPTY_LENGTH) {
                throw new IOException("Malformed DER BIT STRING");
            }
            int unused = input.readRequired();
            if (unused > 7 || (length == SINGLE_OCTET_LENGTH && unused != 0)) {
                throw new IOException("Malformed DER BIT STRING");
            }
            long octets = length - SINGLE_OCTET_LENGTH;
            if (octets == EMPTY_LENGTH) {
                return;
            }
            int last = 0;
            for (long index = 0L; index < octets; index++) {
                cancellation.throwIfCancelled();
                last = input.readRequired();
            }
            if (unused != 0 && (last & ((1 << unused) - 1)) != 0) {
                throw new IOException("Non-canonical DER BIT STRING");
            }
        }

        private static void readNull(long length) throws IOException {
            if (length != EMPTY_LENGTH) {
                throw new IOException("Malformed DER NULL");
            }
        }

        private static void readOid(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if (length == EMPTY_LENGTH) {
                throw new IOException("Malformed DER OID");
            }
            boolean atComponentStart = true;
            for (long index = 0L; index < length; index++) {
                cancellation.throwIfCancelled();
                int octet = input.readRequired();
                if (atComponentStart && octet == CONTINUATION_BIT) {
                    throw new IOException("Non-canonical DER OID");
                }
                atComponentStart = (octet & CONTINUATION_BIT) == 0;
            }
            if (!atComponentStart) {
                throw new IOException("Truncated DER OID");
            }
        }

        private static void readUtf8String(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            long remaining = length;
            while (remaining > 0L) {
                cancellation.throwIfCancelled();
                int first = input.readRequired();
                remaining--;
                if (first <= 0x7f) {
                    continue;
                }
                int continuationCount;
                int codePoint;
                int minimum;
                if (first >= 0xc2 && first <= 0xdf) {
                    continuationCount = 1;
                    codePoint = first & 0x1f;
                    minimum = 0x80;
                } else if (first >= 0xe0 && first <= 0xef) {
                    continuationCount = 2;
                    codePoint = first & 0x0f;
                    minimum = 0x800;
                } else if (first >= 0xf0 && first <= 0xf4) {
                    continuationCount = 3;
                    codePoint = first & 0x07;
                    minimum = 0x10000;
                } else {
                    throw new IOException("Malformed DER UTF8String");
                }
                if (remaining < continuationCount) {
                    throw new IOException("Truncated DER UTF8String");
                }
                for (int index = 0; index < continuationCount; index++) {
                    int octet = input.readRequired();
                    if ((octet & 0xc0) != 0x80) {
                        throw new IOException("Malformed DER UTF8String");
                    }
                    codePoint = (codePoint << 6) | (octet & 0x3f);
                }
                remaining -= continuationCount;
                if (codePoint < minimum || codePoint > 0x10ffff
                        || codePoint >= 0xd800 && codePoint <= 0xdfff) {
                    throw new IOException("Non-canonical DER UTF8String");
                }
            }
        }

        private static void readRestrictedString(CountedInput input, long length, StringKind kind,
                CancellationSignal cancellation) throws IOException {
            for (long index = 0L; index < length; index++) {
                cancellation.throwIfCancelled();
                int octet = input.readRequired();
                if (!kind.accepts(octet)) {
                    throw new IOException("Malformed DER " + kind.label());
                }
            }
        }

        private static LocalDateTime readTime(CountedInput input, long length, boolean generalized)
                throws IOException {
            int expectedLength = generalized ? 15 : 13;
            if (length != expectedLength) {
                throw new IOException("Non-canonical DER time");
            }
            byte[] value = new byte[expectedLength];
            for (int index = 0; index < value.length; index++) {
                value[index] = (byte) input.readRequired();
            }
            if (value[value.length - 1] != 'Z') {
                throw new IOException("Non-canonical DER time");
            }
            int digitCount = value.length - 1;
            for (int index = 0; index < digitCount; index++) {
                if (value[index] < '0' || value[index] > '9') {
                    throw new IOException("Malformed DER time");
                }
            }
            int offset;
            int year;
            if (generalized) {
                year = decimal(value, 0, 4);
                offset = 4;
            } else {
                int shortYear = decimal(value, 0, 2);
                year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
                offset = 2;
            }
            try {
                return LocalDateTime.of(year, decimal(value, offset, 2), decimal(value, offset + 2, 2),
                        decimal(value, offset + 4, 2), decimal(value, offset + 6, 2),
                        decimal(value, offset + 8, 2));
            } catch (DateTimeException exception) {
                throw new IOException("Malformed DER time", exception);
            }
        }

        private static int decimal(byte[] value, int offset, int length) {
            int result = 0;
            for (int index = 0; index < length; index++) {
                result = result * 10 + value[offset + index] - '0';
            }
            return result;
        }

        private static void readUniversalString(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if ((length & 3L) != 0L) {
                throw new IOException("Malformed DER UniversalString");
            }
            for (long index = 0L; index < length; index += 4L) {
                cancellation.throwIfCancelled();
                long codePoint = ((long) input.readRequired() << 24) | ((long) input.readRequired() << 16)
                        | ((long) input.readRequired() << 8) | input.readRequired();
                if (codePoint > 0x10ffffL || codePoint >= 0xd800L && codePoint <= 0xdfffL) {
                    throw new IOException("Malformed DER UniversalString");
                }
            }
        }

        private static void readBmpString(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if ((length & 1L) != 0L) {
                throw new IOException("Malformed DER BMPString");
            }
            for (long index = 0L; index < length; index += 2L) {
                cancellation.throwIfCancelled();
                int codeUnit = (input.readRequired() << 8) | input.readRequired();
                if (codeUnit >= 0xd800 && codeUnit <= 0xdfff) {
                    throw new IOException("Malformed DER BMPString");
                }
            }
        }

        /** Supported restricted X.509 character-string alphabets. */
        private enum StringKind {
            NUMERIC("NumericString") {
                @Override
                boolean accepts(int octet) {
                    return octet == ' ' || octet >= '0' && octet <= '9';
                }
            },
            PRINTABLE("PrintableString") {
                @Override
                boolean accepts(int octet) {
                    return octet >= 'A' && octet <= 'Z' || octet >= 'a' && octet <= 'z'
                            || octet >= '0' && octet <= '9' || " '()+,-./:=?".indexOf(octet) >= 0;
                }
            },
            IA5("IA5String") {
                @Override
                boolean accepts(int octet) {
                    return octet <= 0x7f;
                }
            },
            VISIBLE("VisibleString") {
                @Override
                boolean accepts(int octet) {
                    return octet >= 0x20 && octet <= 0x7e;
                }
            };

            private final String label;

            StringKind(String label) {
                this.label = label;
            }

            abstract boolean accepts(int octet);

            private String label() {
                return label;
            }
        }
    }

    /** Non-copying adapter whose lifetime is confined to one synchronous call. */
    private static final class ByteArrayContent implements RepeatableContent {
        private final byte[] encoded;

        private ByteArrayContent(byte[] encoded) {
            this.encoded = encoded;
        }

        @Override
        public InputStream openStream() {
            return new ByteArrayInputStream(encoded);
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(encoded.length);
        }

        @Override
        public String contentId() {
            return "bounded-byte-array";
        }

        @Override
        public void close() {
            // Caller retains ownership of the bounded array.
        }
    }
}
