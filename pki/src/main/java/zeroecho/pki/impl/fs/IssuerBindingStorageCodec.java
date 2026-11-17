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

import java.io.DataInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.*;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Context-bound compact ZICB v1 storage; immutable generation coordinates are stored once.
 */
final class IssuerBindingStorageCodec {
    private static final int BOOLEAN_TRUE = 1;
    private static final int MAGIC = 0x5a494342;
    private static final int MAXIMUM = SigningWalFrameCodec.MAX_PAYLOAD_BYTES;
    private IssuerBindingStorageCodec() { }

    /**
     * Encodes issuer public binding evidence with its exact generation context.
     *
     * @param binding validated immutable issuer cryptographic binding
     * @param generation exact authoritative generation whose key and profile coordinates must match
     * @return newly allocated context-bound binary binding evidence
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if binding and generation coordinates differ
     * @throws IOException if bounded field encoding fails
     */
    /* default */ static byte[] encode(IssuerCryptographicBinding binding, IssuerGeneration generation) throws IOException {
        requireCoordinates(binding, generation);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(MAGIC); out.writeShort(1); out.writeShort(1);
            text(out, generation.issuerId().value()); data(out, context(generation)); text(out, binding.commitment());
            text(out, binding.formatId()); key(out, binding.primary(), false);
            out.writeBoolean(binding.alternative().isPresent());
            if (binding.alternative().isPresent()) { key(out, binding.alternative().orElseThrow(), true); }
            text(out, binding.certificateSha256()); text(out, binding.profile().profileId());
            out.writeLong(binding.profile().profileVersion()); data(out, binding.profile().canonicalSha256());
            text(out, binding.bindingSetCommitment()); text(out, binding.certificateHybridBaseline().name());
            text(out, binding.evidenceSha256());
        }
        return bytes.toByteArray();
    }

    /**
     * Reads the issuer identity from a versioned storage envelope.
     *
     * @param bytes complete context-bound binding envelope
     * @return decoded issuer identity; this lookup alone does not validate the full binding or its generation context
     * @throws IOException if envelope framing or the leading identity field cannot be decoded
     */
    /* default */ static PkiId issuerId(byte[] bytes) throws IOException {
        try (DataInputStream in = input(bytes)) { return new PkiId(text(in)); }
    }

    /**
     * Decodes and authenticates binding coordinates against the exact authoritative generation context.
     *
     * @param bytes complete stored binding envelope
     * @param generation authoritative generation supplying owner, credential, key and profile coordinates
     * @return validated immutable binding with matching canonical commitment
     * @throws IOException if framing, context, coordinates, canonical commitment or trailing data is invalid
     */
    /* default */ static IssuerCryptographicBinding decode(byte[] bytes, IssuerGeneration generation) throws IOException {
        try (DataInputStream in = input(bytes)) {
            PkiId id = new PkiId(text(in));
            if (!id.equals(generation.issuerId()) || !MessageDigest.isEqual(data(in), context(generation))) { throw invalid(); }
            String commitment = text(in); String format = text(in);
            IssuerKeyBinding primary = key(in, generation.signingKeyRef());
            Optional<IssuerKeyBinding> alternative = flag(in) ? Optional.of(key(in, new KeyRef(text(in)))) : Optional.empty();
            String certificate = text(in); String profileId = text(in); long profileVersion = in.readLong();
            CertificateProfileRef profile = new CertificateProfileRef(profileId, profileVersion, data(in));
            String registry = text(in);
            IssuerCryptographicBinding.HybridSignatureBaseline baseline = IssuerCryptographicBinding.HybridSignatureBaseline.valueOf(text(in));
            String evidence = text(in);
            if (in.read() != -1) { throw invalid(); }
            IssuerCryptographicBinding value = new IssuerCryptographicBinding(1, id, generation.authorityId(), generation.credentialId(), format,
                    primary, alternative, certificate, profile, registry, baseline, evidence);
            requireCoordinates(value, generation);
            if (!value.commitment().equals(commitment)) { throw invalid(); }
            return value;
        } catch (IllegalArgumentException | IllegalStateException | NullPointerException failure) { throw new IOException("Invalid context-bound issuer binding", failure); }
    }

    private static DataInputStream input(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length > MAXIMUM) { throw invalid(); }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        if (in.readInt() != MAGIC || in.readUnsignedShort() != 1 || in.readUnsignedShort() != 1) { throw invalid(); }
        return in;
    }
    private static void requireCoordinates(IssuerCryptographicBinding value, IssuerGeneration generation) throws IOException {
        if (!value.issuerId().equals(generation.issuerId()) || !value.authorityId().equals(generation.authorityId())
                || !value.credentialId().equals(generation.credentialId()) || !value.primary().keyRef().equals(generation.signingKeyRef())
                || !HexFormat.of().formatHex(value.profile().canonicalSha256()).equals(generation.profilePolicyCommitment())
                || !value.bindingSetCommitment().equals(generation.x509BindingCommitment())) { throw invalid(); }
    }
    private static byte[] context(IssuerGeneration generation) throws IOException {
        MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
        // State is deliberately excluded: lifecycle transitions do not change immutable signing authority.
        for (String field : List.of("zeroecho-issuer-binding-context-v1", generation.issuerId().value(), generation.authorityId().value(),
                generation.credentialId().value(), generation.signingKeyRef().value(), generation.profilePolicyCommitment(), generation.x509BindingCommitment())) {
            byte[] bytes = field.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > MAXIMUM) { throw invalid(); }
            digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array()); digest.update(bytes);
        }
        return digest.digest();
    }
    private static void key(DataOutputStream out, IssuerKeyBinding value, boolean includeReference) throws IOException {
        if (includeReference) { text(out, value.keyRef().value()); }
        text(out, value.publicKeyAlgorithm().canonicalForm()); text(out, value.signatureAlgorithm().canonicalForm());
        data(out, value.signatureAlgorithmIdentifier().bytes()); text(out, value.subjectSpkiSha256());
    }
    private static IssuerKeyBinding key(DataInputStream in, KeyRef reference) throws IOException {
        return new IssuerKeyBinding(reference, AlgorithmIdentity.parse(text(in), List.of()), AlgorithmIdentity.parse(text(in), List.of()),
                new EncodedObject(Encoding.DER, data(in)), text(in));
    }
    private static boolean flag(DataInputStream in) throws IOException {
        int value = in.readUnsignedByte(); if (value > BOOLEAN_TRUE) { throw invalid(); } return value == 1;
    }
    private static void text(DataOutputStream out, String value) throws IOException { data(out, value.getBytes(StandardCharsets.UTF_8)); }
    private static String text(DataInputStream in) throws IOException {
        byte[] bytes = data(in); String value = new String(bytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(bytes, value.getBytes(StandardCharsets.UTF_8))) { throw invalid(); } return value;
    }
    private static void data(DataOutputStream out, byte[] value) throws IOException {
        if (value.length < 1 || (long)out.size() + 4 + value.length > MAXIMUM) { throw invalid(); }
        out.writeInt(value.length); out.write(value);
    }
    private static byte[] data(DataInputStream in) throws IOException {
        int length = in.readInt(); if (length < 1 || length > MAXIMUM || length > in.available()) { throw invalid(); }
        return in.readNBytes(length);
    }
    private static IOException invalid() { return new IOException("Issuer binding immutable storage context differs"); }
}
