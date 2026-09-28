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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pkix.Pkix;

class StreamingX509CrlTbsWriterTest {
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final X500Principal NAME = new X500Principal("CN=Issuer");
    private static final X509AlgorithmIdentifier ALGORITHM = X509AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");
    private static final byte[] KEY_ID = new byte[] {1, 2, 3, 4, 5};
    private static KeyPair key;

    @BeforeAll static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
    }

    @Test void emptyAndMultipleEntriesMatchIndependentDerAndVerifyAgainstOriginalTbs() throws Exception {
        for (int size : new int[] {0, 1, 4, 128}) {
            Source source = new Source(size);
            StreamingX509CrlTbsWriter writer = writer(NOW);
            StreamingX509CrlTbsWriter.Measurement measured = writer.measure(source, CancellationSignal.NONE);
            BigInteger number = BigInteger.valueOf(128);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            assertEquals(writer.encodedLength(measured, number), writer.write(source, measured, number, output, CancellationSignal.NONE));
            assertEquals(output.size(), writer.encodedLength(measured, number));
            assertEquals(size, measured.entryCount());
            assertEquals(2, source.opens);
            assertEquals(2, source.closes);
            JcaX509v2CRLBuilder independent = new JcaX509v2CRLBuilder(NAME, Date.from(NOW));
            independent.setNextUpdate(Date.from(NOW.plusSeconds(3600)));
            for (int index = 0; index < size; index++) {
                CrlEntry entry = source.entry(index);
                independent.addCRLEntry(entry.serialNumber(), Date.from(entry.transitionTime()), 6);
            }
            independent.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(KEY_ID));
            independent.addExtension(Extension.cRLNumber, false, new ASN1Integer(number));
            X509CRLHolder expected = independent.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()));
            assertArrayEquals(expected.toASN1Structure().getTBSCertList().getEncoded(), output.toByteArray());
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key.getPrivate());
            signer.update(output.toByteArray());
            byte[] encoded = Pkix.assembleCertificateOrCrl(output.toByteArray(), signer.sign(), true);
            X509CRL parsed = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(encoded));
            parsed.verify(key.getPublic());
            assertEquals(2, parsed.getVersion());
            assertEquals(NAME, parsed.getIssuerX500Principal());
            assertEquals(size, parsed.getRevokedCertificates() == null ? 0 : parsed.getRevokedCertificates().size());
            assertEquals(Date.from(NOW), parsed.getThisUpdate());
            assertEquals(Date.from(NOW.plusSeconds(3600)), parsed.getNextUpdate());
        }
    }

    @Test void allFullReasonsAndX509TimeBoundariesAreCanonical() throws Exception {
        for (Instant date : List.of(Instant.parse("1949-12-31T23:59:59Z"), Instant.parse("1950-01-01T00:00:00Z"),
                Instant.parse("2049-12-31T23:59:59Z"), Instant.parse("2050-01-01T00:00:00Z"))) {
            for (RevocationReason reason : RevocationReason.values()) {
                if (reason == RevocationReason.REMOVE_FROM_CRL) { continue; }
                Source source = new Source(1);
                source.fixed = new CrlEntry(BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE), date.plusNanos(123), reason);
                StreamingX509CrlTbsWriter writer = writer(date);
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                writer.write(source, writer.measure(source, CancellationSignal.NONE), BigInteger.ZERO, output, CancellationSignal.NONE);
                new StreamingDerReader().validate(output.toByteArray(), output.size());
                org.bouncycastle.asn1.x509.TBSCertList tbs = org.bouncycastle.asn1.x509.TBSCertList.getInstance(output.toByteArray());
                assertEquals(Date.from(date), tbs.getRevokedCertificates()[0].getRevocationDate().getDate());
                int expected = switch (reason) {
                    case PRIVILEGE_WITHDRAWN -> 9;
                    case AA_COMPROMISE -> 10;
                    default -> reason.ordinal();
                };
                assertEquals(expected, org.bouncycastle.asn1.ASN1Enumerated.getInstance(tbs.getRevokedCertificates()[0]
                        .getExtensions().getExtensionParsedValue(Extension.reasonCode)).intValueExact());
            }
        }
    }

    @Test void longAggregateAccountingAndLazySecondPassDoNotRequireAggregateBuffers() throws Exception {
        StreamingX509CrlTbsWriter writer = writer(NOW);
        assertTrue(writer.encodedLength(new StreamingX509CrlTbsWriter.Measurement(1L << 33, 1L << 28), BigInteger.ONE) > (1L << 33));
        assertThrows(ArithmeticException.class, () -> writer.encodedLength(
                new StreamingX509CrlTbsWriter.Measurement(Long.MAX_VALUE, 1), BigInteger.ONE));
        Source lazy = new Source(10_000);
        StreamingX509CrlTbsWriter.Measurement measured = writer.measure(lazy, CancellationSignal.NONE);
        long written = writer.write(lazy, measured, BigInteger.ONE, OutputStream.nullOutputStream(), CancellationSignal.NONE);
        assertEquals(writer.encodedLength(measured, BigInteger.ONE), written);
        assertEquals(20_000, lazy.visits);
        assertEquals(2, lazy.closes);
    }

    @Test void deltaWriterIncludesCriticalBaseNumberAndReleaseInExactMeasuredDer() throws Exception {
        Source source = new Source(1);
        source.fixed = new CrlEntry(BigInteger.valueOf(42), NOW.minusSeconds(10), RevocationReason.REMOVE_FROM_CRL);
        BigInteger base = BigInteger.valueOf(128);
        BigInteger number = base.add(BigInteger.ONE);
        StreamingX509CrlTbsWriter writer = new StreamingX509CrlTbsWriter(ALGORITHM, NAME.getEncoded(), KEY_ID,
                NOW, NOW.plusSeconds(3600), java.util.Optional.of(base));
        StreamingX509CrlTbsWriter.Measurement measured = writer.measure(source, CancellationSignal.NONE);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        assertEquals(writer.encodedLength(measured, number), writer.write(source, measured, number, output, CancellationSignal.NONE));
        assertEquals(output.size(), writer.encodedLength(measured, number));
        org.bouncycastle.asn1.x509.TBSCertList tbs = org.bouncycastle.asn1.x509.TBSCertList.getInstance(output.toByteArray());
        assertEquals(number, org.bouncycastle.asn1.ASN1Integer.getInstance(tbs.getExtensions()
                .getExtensionParsedValue(Extension.cRLNumber)).getValue());
        assertEquals(base, org.bouncycastle.asn1.ASN1Integer.getInstance(tbs.getExtensions()
                .getExtensionParsedValue(Extension.deltaCRLIndicator)).getValue());
        assertTrue(tbs.getExtensions().getExtension(Extension.deltaCRLIndicator).isCritical());
        assertTrue(!tbs.getExtensions().getExtension(Extension.cRLNumber).isCritical());
        assertEquals(8, org.bouncycastle.asn1.ASN1Enumerated.getInstance(tbs.getRevokedCertificates()[0]
                .getExtensions().getExtensionParsedValue(Extension.reasonCode)).intValueExact());
        new StreamingDerReader().validate(output.toByteArray(), output.size());
        assertEquals(2, source.opens);
        assertEquals(2, source.closes);
    }

    @Test void fullWriterRejectsReleaseDuringBothPasses() throws Exception {
        StreamingX509CrlTbsWriter writer = writer(NOW);
        Source source = new Source(1);
        StreamingX509CrlTbsWriter.Measurement held = writer.measure(source, CancellationSignal.NONE);
        source.fixed = new CrlEntry(BigInteger.ONE, NOW, RevocationReason.REMOVE_FROM_CRL);
        assertThrows(IOException.class, () -> writer.measure(source, CancellationSignal.NONE));
        assertThrows(IOException.class, () -> writer.write(source, held, BigInteger.ONE,
                OutputStream.nullOutputStream(), CancellationSignal.NONE));
        assertEquals(3, source.closes);
    }

    @Test void rejectsCountAndLengthDivergenceAndClosesEachCursor() throws Exception {
        for (boolean changeCount : new boolean[] {true, false}) {
            Source source = new Source(1);
            StreamingX509CrlTbsWriter writer = writer(NOW);
            StreamingX509CrlTbsWriter.Measurement measured = writer.measure(source, CancellationSignal.NONE);
            if (changeCount) { source.size = 0; }
            else { source.fixed = new CrlEntry(BigInteger.valueOf(128), NOW, RevocationReason.CERTIFICATE_HOLD); }
            assertThrows(IOException.class, () -> writer.write(source, measured, BigInteger.ONE,
                    OutputStream.nullOutputStream(), CancellationSignal.NONE));
            assertEquals(2, source.closes);
        }
    }

    @Test void rejectsInvalidSerialTimeNumberAndCancellation() throws Exception {
        StreamingX509CrlTbsWriter writer = writer(NOW);
        Source source = new Source(1);
        source.fixed = new CrlEntry(BigInteger.ONE.shiftLeft(159), NOW, RevocationReason.KEY_COMPROMISE);
        assertThrows(IOException.class, () -> writer.measure(source, CancellationSignal.NONE));
        source.fixed = new CrlEntry(BigInteger.ONE, Instant.parse("+10000-01-01T00:00:00Z"), RevocationReason.KEY_COMPROMISE);
        assertThrows(IOException.class, () -> writer.measure(source, CancellationSignal.NONE));
        assertThrows(IllegalArgumentException.class, () -> writer.encodedLength(
                new StreamingX509CrlTbsWriter.Measurement(0, 0), BigInteger.ONE.shiftLeft(159)));
        assertThrows(IllegalArgumentException.class, () -> writer(NOW.plusNanos(1)));
        AtomicBoolean cancelled = new AtomicBoolean();
        source.fixed = null;
        source.onVisit = () -> cancelled.set(true);
        assertThrows(IOException.class, () -> writer.measure(source, cancelled::get));
        assertEquals(3, source.closes);
    }

    @Test void authorityKeyIdentifierIsDefensivelyCapturedAndSharesTheExtensionsSequence() throws Exception {
        byte[] identifier = KEY_ID.clone();
        StreamingX509CrlTbsWriter writer = new StreamingX509CrlTbsWriter(ALGORITHM, NAME.getEncoded(), identifier, NOW, NOW.plusSeconds(1));
        identifier[0] = 99;
        Source source = new Source(0);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writer.write(source, writer.measure(source, CancellationSignal.NONE), BigInteger.ONE, output, CancellationSignal.NONE);
        org.bouncycastle.asn1.x509.Extensions extensions = org.bouncycastle.asn1.x509.TBSCertList.getInstance(output.toByteArray()).getExtensions();
        assertEquals(2, extensions.getExtensionOIDs().length);
        assertArrayEquals(KEY_ID, AuthorityKeyIdentifier.getInstance(extensions.getExtensionParsedValue(Extension.authorityKeyIdentifier)).getKeyIdentifier());
        assertTrue(!extensions.getExtension(Extension.authorityKeyIdentifier).isCritical());
        assertTrue(!extensions.getExtension(Extension.cRLNumber).isCritical());
        assertThrows(IllegalArgumentException.class, () -> new StreamingX509CrlTbsWriter(ALGORITHM, NAME.getEncoded(), new byte[0], NOW, NOW.plusSeconds(1)));
    }

    private static StreamingX509CrlTbsWriter writer(Instant date) throws IOException {
        return new StreamingX509CrlTbsWriter(ALGORITHM, NAME.getEncoded(), KEY_ID, date, date.plusSeconds(3600));
    }

    private static final class Source implements CrlEntrySource {
        private int size;
        private int opens;
        private int closes;
        private int visits;
        private CrlEntry fixed;
        private Runnable onVisit = () -> { };
        private Source(int size) { this.size = size; }
        private CrlEntry entry(int index) {
            return fixed == null ? new CrlEntry(BigInteger.valueOf(index + 1L), NOW.minusSeconds(10), RevocationReason.CERTIFICATE_HOLD) : fixed;
        }
        @Override public OptionalLong count() { return OptionalLong.empty(); }
        @Override public void close() { throw new AssertionError("Writer must not close its caller's source"); }
        @Override public Cursor openCursor() {
            opens++;
            return new Cursor() {
                private int index = -1;
                @Override public boolean next() { index++; if (index < size) { visits++; onVisit.run(); return true; } return false; }
                @Override public CrlEntry current() { return entry(index); }
                @Override public long ordinal() { return index; }
                @Override public void close() { closes++; }
            };
        }
    }
}
