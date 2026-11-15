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
package zeroecho.pki.api.ca;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Strict bounded ZICB version-one full public evidence codec, independent of storage.
 * The full canonical domain form allows four MiB for generation coordinate context
 * plus new evidence. Compact persisted rows and combined transactions retain the
 * filesystem's separate two-MiB limit; this codec does not enlarge store budgets.
 */
public final class IssuerCryptographicBindingCodec {
    private static final int MAGIC = 0x5a494342;
    private static final int MAXIMUM_BYTES = 4 * 1024 * 1024;
    private IssuerCryptographicBindingCodec() { }

    /** @param value complete binding @return deterministic domain-separated encoding */
    public static byte[] encode(IssuerCryptographicBinding value) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(bytes)) {
                out.writeInt(MAGIC); out.writeShort(1); out.writeShort(0);
                text(out, value.issuerId().value()); text(out, value.authorityId().value());
                text(out, value.credentialId().value()); text(out, value.formatId());
                key(out, value.primary()); out.writeBoolean(value.alternative().isPresent());
                if (value.alternative().isPresent()) { key(out, value.alternative().orElseThrow()); }
                text(out, value.certificateSha256()); text(out, value.profile().profileId());
                out.writeLong(value.profile().profileVersion()); data(out, value.profile().canonicalSha256());
                text(out, value.bindingSetCommitment()); text(out, value.certificateHybridBaseline().name());
                text(out, value.evidenceSha256());
            }
            if (bytes.size() > MAXIMUM_BYTES) { throw new IllegalArgumentException("Issuer binding too large"); }
            return bytes.toByteArray();
        } catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }

    /** @param bytes exact bounded encoding @return validated complete binding @throws IllegalArgumentException for malformed or unknown encodings */
    public static IssuerCryptographicBinding decode(byte[] bytes) {
        if (bytes == null || bytes.length > MAXIMUM_BYTES) { throw invalid(); }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (in.readInt() != MAGIC || in.readUnsignedShort() != 1 || in.readUnsignedShort() != 0) { throw invalid(); }
            PkiId issuer = new PkiId(text(in)), authority = new PkiId(text(in)), credential = new PkiId(text(in));
            String format = text(in); IssuerKeyBinding primary = key(in);
            Optional<IssuerKeyBinding> alternative = flag(in) ? Optional.of(key(in)) : Optional.empty();
            String certificate = text(in), profile = text(in); long profileVersion = in.readLong();
            CertificateProfileRef reference = new CertificateProfileRef(profile, profileVersion, data(in));
            String bindings = text(in);
            var baseline = IssuerCryptographicBinding.HybridSignatureBaseline.valueOf(text(in));
            String evidence = text(in);
            if (in.available() != 0) { throw invalid(); }
            return new IssuerCryptographicBinding(1, issuer, authority, credential, format, primary, alternative,
                    certificate, reference, bindings, baseline, evidence);
        } catch (IOException | RuntimeException failure) { throw new IllegalArgumentException("Malformed issuer binding", failure); }
    }

    private static void key(DataOutputStream out, IssuerKeyBinding value) throws IOException {
        text(out, value.keyRef().value()); text(out, value.publicKeyAlgorithm().canonicalForm());
        text(out, value.signatureAlgorithm().canonicalForm()); data(out, value.signatureAlgorithmIdentifier().bytes());
        text(out, value.subjectSpkiSha256());
    }
    private static IssuerKeyBinding key(DataInputStream in) throws IOException {
        return new IssuerKeyBinding(new KeyRef(text(in)), AlgorithmIdentity.parse(text(in), List.of()),
                AlgorithmIdentity.parse(text(in), List.of()), new EncodedObject(Encoding.DER, data(in)), text(in));
    }
    private static boolean flag(DataInputStream in) throws IOException {
        int value = in.readUnsignedByte(); if (value > 1) { throw invalid(); } return value == 1;
    }
    private static void text(DataOutputStream out, String value) throws IOException { data(out, value.getBytes(StandardCharsets.UTF_8)); }
    private static String text(DataInputStream in) throws IOException {
        byte[] bytes = data(in); String text = new String(bytes, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))) { throw invalid(); }
        return text;
    }
    private static void data(DataOutputStream out, byte[] value) throws IOException {
        if (value.length == 0 || value.length > MAXIMUM_BYTES) { throw invalid(); }
        if ((long) out.size() + Integer.BYTES + value.length > MAXIMUM_BYTES) { throw invalid(); }
        out.writeInt(value.length); out.write(value);
    }
    private static byte[] data(DataInputStream in) throws IOException {
        int length = in.readInt(); if (length < 1 || length > MAXIMUM_BYTES || length > in.available()) { throw invalid(); }
        return in.readNBytes(length);
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Malformed issuer binding"); }
}
