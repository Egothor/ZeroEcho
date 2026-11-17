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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.util.Arrays;
import java.util.HexFormat;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.api.ca.RootTrustAnchorActivation;
import zeroecho.pki.api.ca.RootTrustAnchorTransition;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataKey;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import zeroecho.pki.api.PkiId;

/**
 * Strict v1 CA lifecycle companion metadata, independent of unchanged FsCodec11 payloads.
 * Current heads use the existing hashed CA identity. Head-history rows use EXACTLY
 * the corresponding CA_HISTORY key (timestamp and transaction token) in a separate
 * namespace; this preserves actual historical epochs rather than deriving them.
 */
final class CaLifecycleMetadataCodec {
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.ca-head-snapshot}; persisted identities depend on this value.
     */
    /* default */ static final String HEAD = "io.zeroecho.pki.ca-head-snapshot";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.ca-head-snapshot-history}; persisted identities depend on this value.
     */
    /* default */ static final String HEAD_HISTORY = "io.zeroecho.pki.ca-head-snapshot-history";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.root-anchor-transition}; persisted identities depend on this value.
     */
    /* default */ static final String TRANSITION = "io.zeroecho.pki.root-anchor-transition";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.root-anchor-activation}; persisted identities depend on this value.
     */
    /* default */ static final String ACTIVATION = "io.zeroecho.pki.root-anchor-activation";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.root-anchor-candidate}; persisted identities depend on this value.
     */
    /* default */ static final String CANDIDATE_INDEX = "io.zeroecho.pki.root-anchor-candidate";
    private static final int BOOLEAN_TRUE = 1;
    private static final int MAGIC = 0x5a434c43;
    private CaLifecycleMetadataCodec() { }
    /**
     * Derives the current CA lifecycle head metadata identity.
     *
     * @param ca exact source identity used to derive the canonical namespace key
     * @return canonical current CA lifecycle head key
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey headKey(PkiId ca) { return new MetadataKey(HEAD, AuthorityMetadataCodec.caKey(ca).key()); }
    /**
     * Derives the CA lifecycle head history metadata identity.
     *
     * @param caHistory exact source identity used to derive the canonical namespace key
     * @return canonical CA lifecycle head history key
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey historyKey(MetadataKey caHistory) { return new MetadataKey(HEAD_HISTORY, caHistory.key()); }
    /**
     * Derives the root trust-anchor transition metadata identity.
     *
     * @param id exact source identity used to derive the canonical namespace key
     * @return canonical root trust-anchor transition key
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey transitionKey(PkiId id) { return new MetadataKey(TRANSITION, Scalars.digest(id.value())); }
    /**
     * Derives the root trust-anchor activation metadata identity.
     *
     * @param id exact source identity used to derive the canonical namespace key
     * @return canonical root trust-anchor activation key
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey activationKey(PkiId id) { return new MetadataKey(ACTIVATION, Scalars.digest(id.value())); }
    /**
     * Derives the candidate issuer lookup for a root transition metadata identity.
     *
     * @param id exact source identity used to derive the canonical namespace key
     * @return canonical candidate issuer lookup for a root transition key
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey candidateKey(PkiId id) { return new MetadataKey(CANDIDATE_INDEX, Scalars.digest(id.value())); }

    /**
     * Reads and validates the exact current CA lifecycle head from a stable metadata snapshot.
     *
     * @param snapshot borrowed stable metadata snapshot
     * @param ca exact logical identity being requested
     * @return matching validated value, or an empty optional if absent
     * @throws NullPointerException if a required input is null
     * @throws IOException if stored content cannot be read or its framing and identity are invalid
     */
    /* default */ static Optional<CaHeadSnapshot> head(MetadataSnapshot snapshot, PkiId ca) throws IOException {
        return read(snapshot, headKey(ca), bytes -> {
            CaHeadSnapshot value = decodeHead(bytes); if (!value.caId().equals(ca)) { throw Scalars.invalid(); } return value;
        });
    }
    /**
     * Reads and validates the exact root trust-anchor transition from a stable metadata snapshot.
     *
     * @param snapshot borrowed stable metadata snapshot
     * @param id exact logical identity being requested
     * @return matching validated value, or an empty optional if absent
     * @throws NullPointerException if a required input is null
     * @throws IOException if stored content cannot be read or its framing and identity are invalid
     */
    /* default */ static Optional<RootTrustAnchorTransition> transition(MetadataSnapshot snapshot, PkiId id) throws IOException {
        return read(snapshot, transitionKey(id), bytes -> {
            RootTrustAnchorTransition value = decodeTransition(bytes); if (!value.transitionId().equals(id)) { throw Scalars.invalid(); } return value;
        });
    }
    /**
     * Reads and validates the exact root trust-anchor activation from a stable metadata snapshot.
     *
     * @param snapshot borrowed stable metadata snapshot
     * @param id exact logical identity being requested
     * @return matching validated value, or an empty optional if absent
     * @throws NullPointerException if a required input is null
     * @throws IOException if stored content cannot be read or its framing and identity are invalid
     */
    /* default */ static Optional<RootTrustAnchorActivation> activation(MetadataSnapshot snapshot, PkiId id) throws IOException {
        return read(snapshot, activationKey(id), bytes -> {
            RootTrustAnchorActivation value = decodeActivation(bytes); if (!value.transitionId().equals(id)) { throw Scalars.invalid(); } return value;
        });
    }
    /**
     * Decodes a CA lifecycle head row and checks its exact metadata identity.
     *
     * @param key persisted metadata row identity
     * @param bytes complete encoded lifecycle metadata value
     * @return validated immutable CA lifecycle head
     * @throws NullPointerException if the key is null
     * @throws IllegalStateException if encoded framing, semantic fields or key identity are invalid
     */
    /* default */ static CaHeadSnapshot headRow(MetadataKey key, byte[] bytes) {
        try { return headRowValue(key, bytes); }
        catch (IOException failure) { throw new IllegalStateException("CA head metadata invalid", failure); }
    }
    /**
     * Decodes a root transition or candidate-index entry row and checks its exact metadata identity.
     *
     * @param key persisted metadata row identity
     * @param bytes complete encoded lifecycle metadata value
     * @return validated immutable root transition or candidate-index entry
     * @throws NullPointerException if the key is null
     * @throws IllegalStateException if encoded framing, semantic fields or key identity are invalid
     */
    /* default */ static RootTrustAnchorTransition transitionRow(MetadataKey key, byte[] bytes) {
        try { return transitionRowValue(key, bytes); }
        catch (IOException failure) { throw new IllegalStateException("Root transition metadata invalid", failure); }
    }
    /**
     * Decodes a root activation row and checks its exact metadata identity.
     *
     * @param key persisted metadata row identity
     * @param bytes complete encoded lifecycle metadata value
     * @return validated immutable root activation
     * @throws NullPointerException if the key is null
     * @throws IllegalStateException if encoded framing, semantic fields or key identity are invalid
     */
    /* default */ static RootTrustAnchorActivation activationRow(MetadataKey key, byte[] bytes) {
        try { return activationRowValue(key, bytes); }
        catch (IOException failure) { throw new IllegalStateException("Root activation metadata invalid", failure); }
    }
    /** Decodes one bounded lifecycle metadata payload. */
    @FunctionalInterface private interface Decoder<T> {
        /** @return decoded value
         * @param bytes bounded payload
         * @throws IOException if framing or fields are invalid
         */
        T decode(byte[] bytes) throws IOException;
    }
    private static <T> Optional<T> read(MetadataSnapshot snapshot, MetadataKey key, Decoder<T> decoder) throws IOException {
        try (MetadataSnapshot.Record row = snapshot.get(key).orElse(null)) {
            return row == null ? Optional.empty() : Optional.of(decoder.decode(CredentialMetadataAuthority.read(row, SigningWalFrameCodec.MAX_PAYLOAD_BYTES)));
        }
    }
    /**
     * Encodes an immutable CA lifecycle head snapshot with its explicit record kind.
     *
     * @param value validated exact CA lifecycle head snapshot
     * @return newly allocated versioned binary lifecycle record
     * @throws NullPointerException if the value is null
     * @throws IOException if bounded canonical field encoding fails
     */
    /* default */ static byte[] encode(CaHeadSnapshot value) throws IOException {
        return encode(1, out -> writeHead(out, value));
    }
    /**
     * Encodes an immutable root trust-anchor transition with its explicit record kind.
     *
     * @param value validated exact root trust-anchor transition
     * @return newly allocated versioned binary lifecycle record
     * @throws NullPointerException if the value is null
     * @throws IOException if bounded canonical field encoding fails
     */
    /* default */ static byte[] encode(RootTrustAnchorTransition value) throws IOException {
        return encode(2, out -> {
            out.writeInt(value.version()); Scalars.text(out, value.transitionId().value()); Scalars.text(out, value.caId().value()); writeHead(out, value.expectedHead());
            Scalars.text(out, value.oldCredentialId().value()); Scalars.text(out, value.oldCertificateSha256()); Scalars.text(out, value.oldBindingCommitment());
            Scalars.text(out, value.candidateIssuerId().value()); Scalars.text(out, value.candidatePathId().value()); Scalars.text(out, value.candidateCredentialId().value());
            Scalars.text(out, value.candidateCertificateSha256()); Scalars.text(out, value.candidateBindingCommitment());
            Scalars.text(out, value.originatingSigningOperationId().value()); Scalars.text(out, value.commandCommitment());
        });
    }
    /**
     * Encodes an immutable root trust-anchor activation with its explicit record kind.
     *
     * @param value validated exact root trust-anchor activation
     * @return newly allocated versioned binary lifecycle record
     * @throws NullPointerException if the value is null
     * @throws IOException if bounded canonical field encoding fails
     */
    /* default */ static byte[] encode(RootTrustAnchorActivation value) throws IOException {
        return encode(3, out -> {
            out.writeInt(value.version()); Scalars.text(out, value.transitionId().value()); Scalars.text(out, value.transitionCommitment()); writeHead(out, value.expectedHead());
            Scalars.text(out, value.candidateIssuerId().value()); Scalars.text(out, value.candidatePathId().value()); out.writeLong(value.newEpoch());
            Scalars.text(out, value.activationRequestId().value()); Scalars.text(out, value.actorId()); Scalars.text(out, value.approvalPolicyCommitment()); Scalars.text(out, value.approvedTargetCommitment());
            out.writeLong(value.acceptedAt().getEpochSecond()); out.writeInt(value.acceptedAt().getNano()); out.writeBoolean(value.distributionAcknowledged());
        });
    }
    /**
     * Decodes one exact versioned CA lifecycle head record.
     *
     * @param bytes complete bounded binary lifecycle value
     * @return validated immutable CA lifecycle head
     * @throws IOException if version, kind, framing, model coordinates or trailing data is invalid
     */
    /* default */ static CaHeadSnapshot decodeHead(byte[] bytes) throws IOException {
        try (DataInputStream in = Scalars.input(bytes, 1)) { CaHeadSnapshot value = readHead(in); Scalars.end(in); return value; }
        catch (IllegalArgumentException | IllegalStateException | NullPointerException | DateTimeException failure) { throw new IOException("CA head metadata invalid", failure); }
    }
    /**
     * Decodes one exact versioned root trust-anchor transition record.
     *
     * @param bytes complete bounded binary lifecycle value
     * @return validated immutable root trust-anchor transition
     * @throws IOException if version, kind, framing, model coordinates or trailing data is invalid
     */
    /* default */ static RootTrustAnchorTransition decodeTransition(byte[] bytes) throws IOException {
        try (DataInputStream in = Scalars.input(bytes, 2)) {
            RootTrustAnchorTransition value = new RootTrustAnchorTransition(in.readInt(), Scalars.id(in), Scalars.id(in), readHead(in), Scalars.id(in), Scalars.text(in), Scalars.text(in), Scalars.id(in), Scalars.id(in), Scalars.id(in), Scalars.text(in), Scalars.text(in), Scalars.id(in), Scalars.text(in));
            Scalars.end(in); return value;
        } catch (IllegalArgumentException | IllegalStateException | NullPointerException | DateTimeException failure) { throw new IOException("Root transition metadata invalid", failure); }
    }
    /**
     * Decodes one exact versioned root trust-anchor activation record.
     *
     * @param bytes complete bounded binary lifecycle value
     * @return validated immutable root trust-anchor activation
     * @throws IOException if version, kind, framing, model coordinates or trailing data is invalid
     */
    /* default */ static RootTrustAnchorActivation decodeActivation(byte[] bytes) throws IOException {
        try (DataInputStream in = Scalars.input(bytes, 3)) {
            RootTrustAnchorActivation value = new RootTrustAnchorActivation(in.readInt(), Scalars.id(in), Scalars.text(in), readHead(in), Scalars.id(in), Scalars.id(in), in.readLong(), Scalars.id(in), Scalars.text(in), Scalars.text(in), Scalars.text(in),
                    Scalars.instant(in), Scalars.flag(in)); Scalars.end(in); return value;
        } catch (IllegalArgumentException | IllegalStateException | NullPointerException | DateTimeException failure) { throw new IOException("Root activation metadata invalid", failure); }
    }
    private static void writeHead(DataOutputStream out, CaHeadSnapshot value) throws IOException {
        out.writeInt(value.version()); Scalars.text(out, value.caId().value()); out.writeLong(value.epoch()); Scalars.text(out, value.issuerId().value()); Scalars.text(out, value.pathId().value()); Scalars.text(out, value.bindingCommitment());
    }
    private static CaHeadSnapshot readHead(DataInputStream in) throws IOException { return new CaHeadSnapshot(in.readInt(), Scalars.id(in), in.readLong(), Scalars.id(in), Scalars.id(in), Scalars.text(in)); }
    /** Writes one canonical lifecycle metadata payload. */
    @FunctionalInterface private interface Encoder {
        /** @param out borrowed output stream
         * @throws IOException if encoding fails
         */
        void write(DataOutputStream out) throws IOException;
    }
    private static byte[] encode(int type, Encoder encoder) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) { out.writeInt(MAGIC); out.writeShort(1); out.writeByte(type); out.writeByte(0); encoder.write(out); }
        if (bytes.size() > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) { throw Scalars.invalid(); } return bytes.toByteArray();
    }










    /** Isolates the canonical lifecycle scalar wire encoding. */
    private static final class Scalars {
        private static void text(DataOutputStream out, String value) throws IOException {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length < 1 || bytes.length > 1_048_576 || (long)out.size() + 4 + bytes.length > SigningWalFrameCodec.MAX_PAYLOAD_BYTES
                    || !value.equals(new String(bytes, StandardCharsets.UTF_8))) { throw invalid(); }
            out.writeInt(bytes.length); out.write(bytes);
        }

        private static String text(DataInputStream in) throws IOException {
            int length = in.readInt(); if (length < 1 || length > 1_048_576 || length > in.available()) { throw invalid(); }
            byte[] bytes = in.readNBytes(length); String value = new String(bytes, StandardCharsets.UTF_8);
            if (!Arrays.equals(bytes, value.getBytes(StandardCharsets.UTF_8))) { throw invalid(); } return value;
        }

        private static PkiId id(DataInputStream in) throws IOException { return new PkiId(text(in)); }

        private static boolean flag(DataInputStream in) throws IOException { int value = in.readUnsignedByte(); if (value > BOOLEAN_TRUE) { throw invalid(); } return value == 1; }

        private static Instant instant(DataInputStream in) throws IOException {
            long seconds = in.readLong(); int nanos = in.readInt();
            if (nanos < 0 || nanos > 999_999_999) { throw invalid(); }
            return Instant.ofEpochSecond(seconds, nanos);
        }

        private static String digest(String value) {
            try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
            catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
        }

        private static DataInputStream input(byte[] bytes, int type) throws IOException {
            if (bytes == null || bytes.length > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) { throw invalid(); }
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
            if (in.readInt() != MAGIC || in.readUnsignedShort() != 1 || in.readUnsignedByte() != type || in.readUnsignedByte() != 0) { throw invalid(); } return in;
        }

        private static void end(DataInputStream in) throws IOException { if (in.read() != -1) { throw invalid(); } }

        private static IOException invalid() { return new IOException("CA lifecycle metadata is malformed or incomplete"); }
    }


    private static CaHeadSnapshot headRowValue(MetadataKey key, byte[] bytes) throws IOException {
        CaHeadSnapshot value = decodeHead(bytes);
        if (!key.equals(headKey(value.caId()))) { throw Scalars.invalid(); }
        return value;
    }


    private static RootTrustAnchorTransition transitionRowValue(MetadataKey key, byte[] bytes) throws IOException {
        RootTrustAnchorTransition value = decodeTransition(bytes);
        if (!key.equals(transitionKey(value.transitionId())) && !key.equals(candidateKey(value.candidateIssuerId()))) { throw Scalars.invalid(); }
        return value;
    }


    private static RootTrustAnchorActivation activationRowValue(MetadataKey key, byte[] bytes) throws IOException {
        RootTrustAnchorActivation value = decodeActivation(bytes);
        if (!key.equals(activationKey(value.transitionId()))) { throw Scalars.invalid(); }
        return value;
    }

}
