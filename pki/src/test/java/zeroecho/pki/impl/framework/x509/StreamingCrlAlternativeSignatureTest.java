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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.UnaryOperator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.impl.framework.x509.bc.BcX509PublicKeyAdapter;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;

/** Interoperability of the qualified BC 1.86 transcript, not an OCSP or live-PKI qualification. */
class StreamingCrlAlternativeSignatureTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final X500Name ISSUER = new X500Name("CN=A");
    private static final byte[] AKI = {1, 2, 3, 4};
    private static final X509AlgorithmIdentifier NATIVE = X509AlgorithmIdentifier.absent("1.2.840.10045.4.3.3");
    private static final X509AlgorithmIdentifier ALTERNATIVE = X509AlgorithmIdentifier.absent("2.16.840.1.101.3.4.3.19");
    private static final String NATIVE_ID = BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm();
    private static final String ALTERNATIVE_ID = BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm();
    private static final X509BindingCatalog BINDINGS = StandardX509Bindings.catalog();
    private static KeyPair primary;
    private static KeyPair alternative;
    private static KeyPair wrongAlternative;

    @BeforeAll static void keys() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        primary = ec.generateKeyPair();
        KeyPairGenerator ml = KeyPairGenerator.getInstance("ML-DSA", "BC");
        ml.initialize(MLDSAParameterSpec.ml_dsa_87);
        alternative = ml.generateKeyPair();
        wrongAlternative = ml.generateKeyPair();
    }

    @Test void completesAndReconstructsIndependentHandTlvFullAndDeltaVectors() throws Exception {
        byte[] placeholder = new byte[4627];
        Arrays.fill(placeholder, (byte) 0xa5);
        for (String name : List.of("empty-full", "entry-full", "entry-delta")) {
            byte[] preTbs = resource(name + "-alternative-pre-tbs.der");
            byte[] expectedNative = resource(name + "-native-tbs-structural.der");
            ByteArrayOutputStream completed = new ByteArrayOutputStream();
            assertEquals(expectedNative.length, StreamingCrlAlternativeSignature.completeTbs(
                    bytes(preTbs), NATIVE, placeholder, completed, CancellationSignal.NONE));
            assertArrayEquals(expectedNative, completed.toByteArray());
            try (RepeatableContent reconstructed = StreamingCrlAlternativeSignature.alternativeTbs(
                    bytes(signed(expectedNative, new byte[] {1, 2})), CancellationSignal.NONE)) {
                assertArrayEquals(preTbs, read(reconstructed));
            }
        }
    }

    @Test void verifiesRealBouncyCastleFullAndDeltaSignaturesAndConfiguredPrivateSpki() throws Exception {
        for (boolean delta : new boolean[] {false, true}) {
            X509CRLHolder crl = independent(delta, true);
            assertEquals(List.of(BigInteger.valueOf(3), BigInteger.TWO), Arrays.stream(crl.toASN1Structure()
                    .getTBSCertList().getRevokedCertificates()).map(entry -> entry.getUserCertificate().getValue()).toList());
            var layout = new StreamingDerReader().inspectAlternativeCrl(bytes(crl.getEncoded()), CancellationSignal.NONE);
            byte[] nativeTbs = crl.toASN1Structure().getTBSCertList().getEncoded("DER");
            assertEquals(sha256(nativeTbs), StreamingCrlSignatureVerifier.verify(bytes(nativeTbs), NATIVE_ID,
                    primary.getPublic().getEncoded(), crl.toASN1Structure().getSignature().getOctets(), BINDINGS, CancellationSignal.NONE));
            try (RepeatableContent preTbs = StreamingCrlAlternativeSignature.alternativeTbs(bytes(crl.getEncoded()), CancellationSignal.NONE)) {
                assertEquals(sha256(read(preTbs)), StreamingCrlSignatureVerifier.verify(preTbs, ALTERNATIVE_ID,
                        alternative.getPublic().getEncoded(), layout.alternativeSignature(), BINDINGS, CancellationSignal.NONE));
                X509BindingCatalog privateCatalog = X509BindingCatalog.extension(List.of(privateSpkiRule()));
                byte[] wrapped = new BcX509PublicKeyAdapter(privateCatalog).wrap(alternative.getPublic().getEncoded(),
                        BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY, "example.crl-private-spki");
                assertEquals(sha256(read(preTbs)), StreamingCrlSignatureVerifier.verify(preTbs, ALTERNATIVE_ID,
                        wrapped, layout.alternativeSignature(), privateCatalog, CancellationSignal.NONE));
                assertThrows(IllegalArgumentException.class, () -> StreamingCrlSignatureVerifier.verify(preTbs,
                        ALTERNATIVE_ID, wrapped, layout.alternativeSignature(), BINDINGS, CancellationSignal.NONE));
            }
            assertEquals(delta ? Optional.of(BigInteger.valueOf(7)) : Optional.empty(), layout.semantic().deltaIndicator());
        }
    }

    @Test void productStreamedFullAndDeltaSignaturesVerifyWithBouncyCastle() throws Exception {
        for (boolean delta : new boolean[] {false, true}) {
            var writer = StreamingX509CrlTbsWriter.forAlternativeSignature(ALTERNATIVE, ISSUER.getEncoded(), AKI,
                    NOW, NOW.plusSeconds(86400), delta ? Optional.of(BigInteger.valueOf(7)) : Optional.empty());
            CrlEntry entry = new CrlEntry(BigInteger.valueOf(delta ? 1 : 128), NOW,
                    delta ? RevocationReason.REMOVE_FROM_CRL : RevocationReason.KEY_COMPROMISE);
            CrlEntrySource source = entries(List.of(entry));
            ByteArrayOutputStream pre = new ByteArrayOutputStream();
            writer.write(source, writer.measure(source, CancellationSignal.NONE), BigInteger.valueOf(delta ? 8 : 7), pre, CancellationSignal.NONE);
            assertArrayEquals(resource((delta ? "entry-delta" : "entry-full") + "-alternative-pre-tbs.der"), pre.toByteArray());
            byte[] altSignature = sign("ML-DSA-87", alternative, pre.toByteArray());
            ByteArrayOutputStream nativeTbs = new ByteArrayOutputStream();
            StreamingCrlAlternativeSignature.completeTbs(bytes(pre.toByteArray()), NATIVE, altSignature, nativeTbs, CancellationSignal.NONE);
            X509CRLHolder crl = new X509CRLHolder(signed(nativeTbs.toByteArray(), sign("SHA384withECDSA", primary, nativeTbs.toByteArray())));
            assertTrue(crl.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(primary.getPublic())));
            assertTrue(crl.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(alternative.getPublic())));
        }
    }

    @Test void rejectsWrongSignerAndTamperedSignedFieldsOrAlternativeValue() throws Exception {
        byte[] original = independent(false, false).getEncoded();
        var originalLayout = new StreamingDerReader().inspectAlternativeCrl(bytes(original), CancellationSignal.NONE);
        try (RepeatableContent transcript = StreamingCrlAlternativeSignature.alternativeTbs(bytes(original), CancellationSignal.NONE)) {
            assertSignatureRejected(transcript, wrongAlternative.getPublic().getEncoded(), originalLayout.alternativeSignature());
            byte[] wrongValue = originalLayout.alternativeSignature();
            wrongValue[0] ^= 1;
            assertSignatureRejected(transcript, alternative.getPublic().getEncoded(), wrongValue);
        }
        for (ASN1ObjectIdentifier oid : List.of(Extension.cRLNumber, Extension.authorityKeyIdentifier, Extension.altSignatureAlgorithm)) {
            byte[] changed = extensions(original, values -> {
                for (int i = 0; i < values.size(); i++) {
                    Extension ext = Extension.getInstance(values.get(i));
                    if (ext.getExtnId().equals(oid)) {
                        try {
                            byte[] value = oid.equals(Extension.cRLNumber) ? new ASN1Integer(9).getEncoded("DER")
                                    : oid.equals(Extension.authorityKeyIdentifier) ? new AuthorityKeyIdentifier(new byte[] {9}).getEncoded("DER")
                                    : new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18")).getEncoded("DER");
                            values.set(i, new Extension(oid, false, value));
                        } catch (IOException failure) { throw new IllegalStateException(failure); }
                    }
                }
                return values;
            });
            try (RepeatableContent transcript = StreamingCrlAlternativeSignature.alternativeTbs(bytes(changed), CancellationSignal.NONE)) {
                assertSignatureRejected(transcript, alternative.getPublic().getEncoded(), originalLayout.alternativeSignature());
            }
        }
        ASN1Sequence outer = ASN1Sequence.getInstance(original);
        ASN1Sequence tbs = ASN1Sequence.getInstance(outer.getObjectAt(0));
        List<ASN1Encodable> changedTbs = copy(tbs);
        changedTbs.set(4, new Time(Date.from(NOW.plusSeconds(86401))));
        byte[] changedTime = outer(new DERSequence(changedTbs.toArray(ASN1Encodable[]::new)), outer);
        try (RepeatableContent transcript = StreamingCrlAlternativeSignature.alternativeTbs(bytes(changedTime), CancellationSignal.NONE)) {
            assertSignatureRejected(transcript, alternative.getPublic().getEncoded(), originalLayout.alternativeSignature());
        }
        ASN1Sequence revoked = ASN1Sequence.getInstance(tbs.getObjectAt(5));
        List<ASN1Encodable> changedEntry = copy(ASN1Sequence.getInstance(revoked.getObjectAt(0)));
        changedEntry.set(0, new ASN1Integer(129));
        List<ASN1Encodable> entryTbs = copy(tbs);
        entryTbs.set(5, new DERSequence(new DERSequence(changedEntry.toArray(ASN1Encodable[]::new))));
        byte[] changedSerial = outer(new DERSequence(entryTbs.toArray(ASN1Encodable[]::new)), outer);
        try (RepeatableContent transcript = StreamingCrlAlternativeSignature.alternativeTbs(bytes(changedSerial), CancellationSignal.NONE)) {
            assertSignatureRejected(transcript, alternative.getPublic().getEncoded(), originalLayout.alternativeSignature());
        }
    }

    @Test void rejectsMalformedHybridExtensionPairsDuplicatesCriticalityAndEntryGrammar() throws Exception {
        byte[] original = independent(false, false).getEncoded();
        List<UnaryOperator<List<ASN1Encodable>>> changes = List.of(
                values -> { values.removeIf(value -> Extension.getInstance(value).getExtnId().equals(Extension.altSignatureAlgorithm)); return values; },
                values -> { values.removeIf(value -> Extension.getInstance(value).getExtnId().equals(Extension.altSignatureValue)); return values; },
                values -> { values.add(0, values.get(0)); return values; },
                values -> { values.add(0, new Extension(new ASN1ObjectIdentifier("1.2.3.4"), true, new byte[] {5, 0})); return values; },
                values -> { values.add(0, new Extension(Extension.subjectAltPublicKeyInfo, false, alternative.getPublic().getEncoded())); return values; },
                values -> { makeCritical(values, Extension.altSignatureAlgorithm); return values; },
                values -> { makeCritical(values, Extension.altSignatureValue); return values; },
                values -> { values.set(values.size() - 1, new Extension(Extension.altSignatureValue, false, new byte[] {3, 2, 1, (byte) 0x80})); return values; });
        for (UnaryOperator<List<ASN1Encodable>> change : changes) {
            byte[] malformed = extensions(original, change);
            assertThrows(IOException.class, () -> new StreamingDerReader().inspectAlternativeCrl(bytes(malformed), CancellationSignal.NONE));
        }
        ASN1Sequence outer = ASN1Sequence.getInstance(original);
        ASN1Sequence tbs = ASN1Sequence.getInstance(outer.getObjectAt(0));
        ASN1Sequence revoked = ASN1Sequence.getInstance(tbs.getObjectAt(5));
        ASN1Sequence entry = ASN1Sequence.getInstance(revoked.getObjectAt(0));
        ASN1EncodableVector emptyExtensionEntry = new ASN1EncodableVector();
        emptyExtensionEntry.add(entry.getObjectAt(0)); emptyExtensionEntry.add(entry.getObjectAt(1)); emptyExtensionEntry.add(new DERSequence());
        List<ASN1Encodable> changedTbs = copy(tbs);
        changedTbs.set(5, new DERSequence(new DERSequence(emptyExtensionEntry)));
        byte[] malformedEntry = outer(new DERSequence(changedTbs.toArray(ASN1Encodable[]::new)), outer);
        assertThrows(IOException.class, () -> new StreamingDerReader().inspectAlternativeCrl(bytes(malformedEntry), CancellationSignal.NONE));
        byte[] oversizedNative = new DERSequence(new ASN1Encodable[] {tbs, outer.getObjectAt(1), new DERBitString(new byte[1024 * 1024 + 1])}).getEncoded("DER");
        assertThrows(IOException.class, () -> new StreamingDerReader().inspectAlternativeCrl(bytes(oversizedNative), CancellationSignal.NONE));
    }

    @Test void borrowedViewsAreRepeatableCloseOnlyOwnedStreamsAndHonorCancellation() throws Exception {
        TrackedContent source = new TrackedContent(independent(false, false).getEncoded());
        AtomicBoolean cancel = new AtomicBoolean();
        RepeatableContent view = StreamingCrlAlternativeSignature.alternativeTbs(source, cancel::get);
        byte[] first = read(view);
        assertArrayEquals(first, read(view));
        assertEquals(source.opens, source.closedStreams);
        view.close();
        assertFalse(source.closed);
        assertArrayEquals(source.data, read(source));
        RepeatableContent cancelledView = StreamingCrlAlternativeSignature.alternativeTbs(source, cancel::get);
        cancel.set(true);
        assertThrows(IOException.class, cancelledView::openStream);
        cancelledView.close();
        assertThrows(IOException.class, () -> StreamingCrlAlternativeSignature.completeTbs(bytes(first), NATIVE,
                new byte[] {1}, OutputStream.nullOutputStream(), cancel::get));
        assertEquals(source.opens, source.closedStreams);
    }

    @Test void lazyLargeCrlTransformsWithoutAggregateReadsAndClosesCancelledStream() throws Exception {
        LazyCrl source = new LazyCrl(100_000);
        AtomicBoolean cancel = new AtomicBoolean();
        try (RepeatableContent view = StreamingCrlAlternativeSignature.alternativeTbs(source, cancel::get)) {
            long expected = source.alternativeLength;
            try (InputStream input = view.openStream()) {
                assertEquals(expected, StreamingDerWriter.copy(input, OutputStream.nullOutputStream(), CancellationSignal.NONE));
            }
            assertEquals(OptionalLong.of(expected), view.length());
            assertTrue(source.length().orElseThrow() > 2_000_000);
            try (InputStream input = view.openStream()) {
                assertTrue(input.readNBytes(128).length == 128);
                cancel.set(true);
                assertThrows(IOException.class, () -> input.readNBytes(128));
            }
        }
        assertEquals(source.opens, source.closedStreams);
        assertFalse(source.closed);
        assertTrue(source.largestRead <= 16 * 1024);
    }

    private static X509CRLHolder independent(boolean delta, boolean unknownNoncritical) throws Exception {
        var builder = new X509v2CRLBuilder(ISSUER, Date.from(NOW));
        builder.setNextUpdate(Date.from(NOW.plusSeconds(86400)));
        // Credential ordering need not be numeric serial ordering; signatures bind the original entry order.
        builder.addCRLEntry(BigInteger.valueOf(3), Date.from(NOW), delta ? 8 : 1);
        builder.addCRLEntry(BigInteger.TWO, Date.from(NOW), delta ? 8 : 1);
        builder.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(AKI));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(delta ? 8 : 7)));
        if (delta) builder.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.valueOf(7)));
        if (unknownNoncritical) builder.addExtension(new ASN1ObjectIdentifier("1.2.3.4"), false, new DEROctetString(new byte[] {7}));
        return builder.build(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC").build(primary.getPrivate()), false,
                new JcaContentSignerBuilder("ML-DSA-87").setProvider("BC").build(alternative.getPrivate()));
    }

    private static byte[] sign(String algorithm, KeyPair key, byte[] input) throws Exception {
        Signature signer = Signature.getInstance(algorithm, "BC");
        signer.initSign(key.getPrivate()); signer.update(input); return signer.sign();
    }

    private static void assertSignatureRejected(RepeatableContent input, byte[] spki, byte[] signature) {
        Exception failure = assertThrows(Exception.class, () -> StreamingCrlSignatureVerifier.verify(input, ALTERNATIVE_ID,
                spki, signature, BINDINGS, CancellationSignal.NONE));
        assertTrue(failure instanceof IOException || failure instanceof GeneralSecurityException, failure::toString);
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream input = StreamingCrlAlternativeSignatureTest.class.getResourceAsStream("/c036/der/" + name)) {
            if (input == null) throw new IOException("Missing independent DER vector " + name);
            return input.readAllBytes();
        }
    }

    private static byte[] signed(byte[] tbs, byte[] signature) throws IOException {
        return new DERSequence(new ASN1Encodable[] {ASN1Sequence.getInstance(tbs),
                new AlgorithmIdentifier(new ASN1ObjectIdentifier(NATIVE.oid())), new DERBitString(signature)}).getEncoded("DER");
    }

    private static byte[] extensions(byte[] original, UnaryOperator<List<ASN1Encodable>> change) throws IOException {
        ASN1Sequence outer = ASN1Sequence.getInstance(original);
        ASN1Sequence tbs = ASN1Sequence.getInstance(outer.getObjectAt(0));
        ASN1Sequence ext = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(tbs.getObjectAt(tbs.size() - 1)).getExplicitBaseObject());
        List<ASN1Encodable> values = new ArrayList<>();
        ext.forEach(values::add);
        List<ASN1Encodable> rewritten = copy(tbs);
        rewritten.set(tbs.size() - 1, new DERTaggedObject(0, new DERSequence(change.apply(values).toArray(ASN1Encodable[]::new))));
        return outer(new DERSequence(rewritten.toArray(ASN1Encodable[]::new)), outer);
    }

    private static void makeCritical(List<ASN1Encodable> extensions, ASN1ObjectIdentifier oid) {
        for (int i = 0; i < extensions.size(); i++) {
            Extension ext = Extension.getInstance(extensions.get(i));
            if (ext.getExtnId().equals(oid)) extensions.set(i, new Extension(oid, true, ext.getExtnValue().getOctets()));
        }
    }

    private static List<ASN1Encodable> copy(ASN1Sequence sequence) {
        List<ASN1Encodable> vector = new ArrayList<>();
        sequence.forEach(vector::add);
        return vector;
    }

    private static byte[] outer(ASN1Encodable tbs, ASN1Sequence original) throws IOException {
        return new DERSequence(new ASN1Encodable[] {tbs, original.getObjectAt(1), original.getObjectAt(2)}).getEncoded("DER");
    }

    private static byte[] read(RepeatableContent content) throws IOException {
        try (InputStream input = content.openStream()) { return input.readAllBytes(); }
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static RepeatableContent bytes(byte[] value) { return new TrackedContent(value); }

    private static CrlEntrySource entries(List<CrlEntry> entries) {
        return new CrlEntrySource() {
            @Override public Cursor openCursor() {
                return new Cursor() {
                    private int index = -1;
                    @Override public boolean next() { return ++index < entries.size(); }
                    @Override public CrlEntry current() { return entries.get(index); }
                    @Override public long ordinal() { return index; }
                    @Override public void close() { }
                };
            }
            @Override public OptionalLong count() { return OptionalLong.of(entries.size()); }
            @Override public void close() { }
        };
    }

    private static X509BindingRule privateSpkiRule() {
        return new X509BindingRule() {
            @Override public String id() { return "example.crl-private-spki"; }
            @Override public X509AlgorithmRole role() { return X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM; }
            @Override public String oid() { return "1.3.6.1.4.1.31424.1.2.998"; }
            @Override public String semanticFingerprint() { return "crl-test-private-spki-v1"; }
            @Override public SignatureEncoding signatureEncoding() { return SignatureEncoding.NOT_APPLICABLE; }
            @Override public PublicKeyEncoding publicKeyEncoding() { return PublicKeyEncoding.NESTED_SPKI_DER; }
            @Override public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
                return BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY.equals(identity) ? Optional.of(X509AlgorithmIdentifier.absent(oid())) : Optional.empty();
            }
            @Override public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
                return X509AlgorithmIdentifier.absent(oid()).equals(identifier) ? Optional.of(BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY) : Optional.empty();
            }
        };
    }

    private static class TrackedContent implements RepeatableContent {
        private final byte[] data;
        int opens;
        int closedStreams;
        boolean closed;
        TrackedContent(byte[] data) { this.data = data.clone(); }
        @Override public InputStream openStream() {
            opens++;
            return new ByteArrayInputStream(data) {
                private boolean done;
                @Override public void close() throws IOException {
                    if (!done) { done = true; closedStreams++; }
                    super.close();
                }
            };
        }
        @Override public OptionalLong length() { return OptionalLong.of(data.length); }
        @Override public String contentId() { return "fixture-crl"; }
        @Override public void close() { closed = true; }
    }

    /** Generates one bounded serial/time entry at a time; the CRL never exists as an aggregate byte array. */
    private static final class LazyCrl implements RepeatableContent {
        private final int count;
        private final byte[] prefix;
        private final byte[] suffix;
        private final byte[] entryTemplate;
        private final long alternativeLength;
        private int opens;
        private int closedStreams;
        private int largestRead;
        private boolean closed;
        LazyCrl(int count) throws IOException {
            this.count = count;
            entryTemplate = new DERSequence(new ASN1Encodable[] {new ASN1Integer(BigInteger.ONE.shiftLeft(32)), new Time(Date.from(NOW))}).getEncoded("DER");
            byte[] beforeEntries = concat(new ASN1Integer(1).getEncoded("DER"),
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier(NATIVE.oid())).getEncoded("DER"), ISSUER.getEncoded(),
                    new Time(Date.from(NOW)).getEncoded("DER"), new Time(Date.from(NOW.plusSeconds(86400))).getEncoded("DER"));
            byte[] altAlgorithm = new Extension(Extension.altSignatureAlgorithm, false,
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier(ALTERNATIVE.oid())).getEncoded("DER")).getEncoded("DER");
            byte[] retained = concat(new Extension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(AKI).getEncoded("DER")).getEncoded("DER"),
                    new Extension(Extension.cRLNumber, false, new ASN1Integer(7).getEncoded("DER")).getEncoded("DER"), altAlgorithm);
            byte[] placeholder = new byte[4627]; Arrays.fill(placeholder, (byte) 0xa5);
            byte[] finalExtensions = tlv(0xa0, tlv(0x30, concat(retained,
                    new Extension(Extension.altSignatureValue, false, new DERBitString(placeholder).getEncoded("DER")).getEncoded("DER"))));
            long entryBytes = Math.multiplyExact((long) count, entryTemplate.length);
            byte[] entriesHeader = header(0x30, entryBytes);
            long nativeBody = beforeEntries.length + entriesHeader.length + entryBytes + finalExtensions.length;
            byte[] nativeHeader = header(0x30, nativeBody);
            byte[] outerTail = concat(new AlgorithmIdentifier(new ASN1ObjectIdentifier(NATIVE.oid())).getEncoded("DER"), new DERBitString(new byte[] {1, 2}).getEncoded("DER"));
            prefix = concat(header(0x30, nativeHeader.length + nativeBody + outerTail.length), nativeHeader, beforeEntries, entriesHeader);
            suffix = concat(finalExtensions, outerTail);
            int nativeAlgorithmBytes = new AlgorithmIdentifier(new ASN1ObjectIdentifier(NATIVE.oid())).getEncoded("DER").length;
            long altBody = beforeEntries.length - nativeAlgorithmBytes + entriesHeader.length + entryBytes + tlv(0xa0, tlv(0x30, retained)).length;
            alternativeLength = header(0x30, altBody).length + altBody;
        }
        @Override public InputStream openStream() {
            opens++;
            return new InputStream() {
                private int part;
                private int entry;
                private byte[] chunk = prefix;
                private int offset;
                private boolean done;
                @Override public int read() throws IOException {
                    byte[] one = new byte[1]; return read(one, 0, 1) < 0 ? -1 : Byte.toUnsignedInt(one[0]);
                }
                @Override public int read(byte[] buffer, int start, int length) {
                    largestRead = Math.max(largestRead, length);
                    if (length == 0) return 0;
                    while (offset == chunk.length) {
                        if (part == 2) return -1;
                        if (entry < count) {
                            part = 1; chunk = entryTemplate.clone();
                            // The serial has fixed five-byte positive DER width throughout this fixture.
                            int serialOffset = 4;
                            long serial = (1L << 32) + entry++;
                            for (int i = 4; i >= 0; i--) { chunk[serialOffset + i] = (byte) serial; serial >>>= 8; }
                        } else { part = 2; chunk = suffix; }
                        offset = 0;
                    }
                    int copied = Math.min(length, chunk.length - offset);
                    System.arraycopy(chunk, offset, buffer, start, copied); offset += copied; return copied;
                }
                @Override public void close() { if (!done) { done = true; closedStreams++; } }
            };
        }
        @Override public OptionalLong length() { return OptionalLong.of(prefix.length + (long) count * entryTemplate.length + suffix.length); }
        @Override public String contentId() { return "lazy-hybrid-crl"; }
        @Override public void close() { closed = true; }
    }

    private static byte[] concat(byte[]... values) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] value : values) output.write(value);
        return output.toByteArray();
    }
    private static byte[] tlv(int tag, byte[] value) throws IOException { return concat(header(tag, value.length), value); }
    private static byte[] header(int tag, long length) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(); StreamingDerWriter.writeTagAndLength(output, tag, length); return output.toByteArray();
    }
}
