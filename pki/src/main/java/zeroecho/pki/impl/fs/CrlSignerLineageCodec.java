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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.MetadataKey;

/**
 * Strict ZCLN/v1 private rows, capped at16KiB independently of unchanged FsCodec11/store18.
 */
final class CrlSignerLineageCodec {
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.crl-signer-lineage}; persisted identities depend on this value.
     */
    /* default */ static final String NAMESPACE = "io.zeroecho.pki.crl-signer-lineage";
    /**
     * Inclusive maximum encoded metadata record length in bytes.
     */
    /* default */ static final int MAXIMUM_BYTES = 16 * 1024;
    private static final int BOOLEAN_TRUE = 1;
    private static final int MAGIC = 0x5a434c4e;
    private CrlSignerLineageCodec() { }
    /**
     * Derives the exact issuer-generation metadata key for hybrid CRL lineage.
     *
     * @param issuer exact issuer generation identity
     * @return canonical lineage metadata key
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey key(PkiId issuer) { return new MetadataKey(NAMESPACE, issuer.value()); }
    /**
     * Encodes hybrid signer-lineage membership without private material or mutable-head inference.
     *
     * @param value validated immutable hybrid lineage evidence
     * @return newly allocated bounded binary lineage record
     * @throws NullPointerException if the value is null
     * @throws IOException if bounded text encoding fails or the record exceeds its row bound
     */
    /* default */ static byte[] encode(CrlSignerLineage value) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(MAGIC); output.writeShort(value.version()); output.writeShort(0);
            text(output, value.issuerId().value());
            output.writeBoolean(value.predecessorSelectedIssuerId().isPresent());
            if (value.predecessorSelectedIssuerId().isPresent()) { text(output, value.predecessorSelectedIssuerId().orElseThrow().value()); }
            text(output, value.lineageId().value()); text(output, value.signerTupleCommitment()); text(output, value.issuerBindingCommitment());
        }
        if (bytes.size() > MAXIMUM_BYTES) { throw new IOException("Hybrid CRL lineage exceeds row bound"); }
        return bytes.toByteArray();
    }
    /**
     * Decodes exact hybrid signer-lineage evidence and checks its persisted issuer identity.
     *
     * @param key exact persisted lineage metadata key
     * @param bytes complete bounded binary lineage record
     * @return validated immutable lineage evidence
     * @throws NullPointerException if a required input is null
     * @throws IllegalStateException if framing, version, identity, canonical fields or trailing data is invalid
     */
    /* default */ static CrlSignerLineage decode(MetadataKey key, byte[] bytes) {
        try {
            return decodeValue(key, bytes);
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalStateException("Hybrid CRL signer-lineage evidence invalid", failure);
        }
    }
    private static void text(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        if (encoded.length == 0 || encoded.length > 64 || !value.equals(new String(encoded, StandardCharsets.US_ASCII))) { throw new IOException("Invalid lineage scalar"); }
        output.writeInt(encoded.length); output.write(encoded);
    }
    private static String text(DataInputStream input) throws IOException {
        int length = input.readInt(); if (length < 1 || length > 64 || length > input.available()) { throw new IOException("Invalid lineage scalar length"); }
        byte[] encoded = input.readNBytes(length); String value = new String(encoded, StandardCharsets.US_ASCII);
        if (!Arrays.equals(encoded, value.getBytes(StandardCharsets.US_ASCII))) { throw new IOException("Invalid lineage scalar encoding"); }
        return value;
    }

    private static CrlSignerLineage decodeValue(MetadataKey key, byte[] bytes) throws IOException {
            if (bytes.length > MAXIMUM_BYTES) { throw new IOException("Hybrid CRL lineage exceeds row bound"); }
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
                if (input.readInt() != MAGIC || input.readUnsignedShort() != 1 || input.readUnsignedShort() != 0) { throw new IOException("Unknown hybrid CRL lineage encoding"); }
                PkiId issuer = new PkiId(text(input)); int present = input.readUnsignedByte();
                if (present > BOOLEAN_TRUE) { throw new IOException("Noncanonical hybrid CRL lineage optional"); }
                Optional<PkiId> predecessor = present == 0 ? Optional.<PkiId>empty() : Optional.of(new PkiId(text(input)));
                CrlSignerLineage value = new CrlSignerLineage(1, issuer, predecessor, new PkiId(text(input)), text(input), text(input));
                if (!key.equals(key(issuer)) || input.read() != -1) { throw new IOException("Hybrid CRL lineage identity differs"); }
                return value;
            }

    }

}
