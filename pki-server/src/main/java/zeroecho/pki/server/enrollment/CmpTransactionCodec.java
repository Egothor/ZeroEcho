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
package zeroecho.pki.server.enrollment;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlStore;

/** Strict v1 manifest and fixed-slot codec; all mutations belong to the coordinator. */
final class CmpTransactionCodec {
    private static final int MAX_SLOT_INDEX_TEXT_LENGTH = 20;
    /* default */ static final int SLOT_BYTES = 262_144;
    /* default */ static final int MAXIMUM_SLOTS = 254;
    private static final int VERSION = 1;
    private CmpTransactionCodec() { }

    /* default */ static String id(RealmId realm, String label, String transaction) {
        return "cmp:" + EnrollmentTransactionCodec.sha256(bytes(out -> {
            out.writeUTF("zeroecho.cmp-transaction.v1"); out.writeUTF(realm.value()); out.writeUTF(label); out.writeUTF(transaction);
        }));
    }
    /* default */ static int slots(CmpTransaction value) { return (value.frozen().maximumResponseBytes() - 1) / SLOT_BYTES + 1; }
    /* default */ static String slotId(String id, int index) { return id + ":" + index; }

    /* default */ static long reservation(CmpTransaction value) {
        // Fixed mutable fields (link, digests, nonces, deadline) fit within 4096 bytes.
        CmpTransaction blank = new CmpTransaction(value.id(), 1, value.frozen(), Optional.empty(), Optional.empty());
        long metadata = Math.addExact(encode(blank).length, 4096);
        if (metadata > EnrollmentTransactionCodec.MAXIMUM_BYTES) {
            throw invalid();
        }
        // 512 bytes covers slot identity/length framing and the control-record envelope.
        return Math.addExact(metadata, Math.addExact(value.frozen().maximumResponseBytes(), Math.multiplyExact(512L, slots(value))));
    }

    /* default */ static ServerControlStore.ProtocolRecord record(CmpTransaction value) {
        byte[] payload = encode(value);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.CMP_TRANSACTION, value.id(), hash(payload), payload);
    }

    /* default */ static byte[] encode(CmpTransaction value) {
        return bytes(out -> {
            out.writeInt(VERSION); out.writeUTF(value.id()); out.writeLong(value.revision());
            CmpTransaction.Frozen f = value.frozen();
            out.writeUTF(f.realmId().value()); EnrollmentTransactionCodec.source(out, f.source());
            EnrollmentTransactionCodec.requester(out, f.requester());
            out.writeUTF(f.authorityId().value()); out.writeUTF(f.profile().profileId()); out.writeLong(f.profile().profileVersion()); out.write(f.profile().canonicalSha256());
            out.writeUTF(f.issuerId().value()); out.writeUTF(f.pathId().value()); out.writeUTF(f.pathCommitment());
            out.writeUTF(f.transactionSha256()); out.writeUTF(f.originalWireSha256()); out.writeInt(f.originalType()); out.writeUTF(f.requestId().toString());
            optional(out, f.requestSha256()); out.writeBoolean(f.implicitConfirmation()); instant(out, f.createdAt()); instant(out, f.expiresAt());
            out.writeInt(f.maximumResponseBytes()); optional(out, value.enrollmentId()); out.writeBoolean(value.response().isPresent());
            if (value.response().isPresent()) {
                CmpTransaction.Response r = value.response().orElseThrow();
                out.writeUTF(r.requestSha256()); out.writeUTF(r.responseSha256()); out.writeInt(r.length());
                out.writeUTF(r.senderNonce()); out.writeUTF(r.recipientNonce()); out.writeBoolean(r.confirmationDeadline().isPresent());
                if (r.confirmationDeadline().isPresent()) {
                    instant(out, r.confirmationDeadline().orElseThrow());
                }
                out.writeUTF(r.confirmation().name()); out.writeBoolean(r.terminal());
            }
        });
    }

    /* default */ static CmpTransaction decode(ServerControlStore.ProtocolRecord record) {
        byte[] payload = record.payload();
        if (!ServerControlStore.CMP_TRANSACTION.equals(record.namespace()) || !hash(payload).equals(record.commitment())) {
            throw invalid();
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (in.readInt() != VERSION) {
                throw invalid();
            }
            String id = in.readUTF(); long revision = in.readLong();
            CmpTransaction.Frozen frozen = new CmpTransaction.Frozen(new RealmId(in.readUTF()), EnrollmentTransactionCodec.source(in),
                    EnrollmentTransactionCodec.requester(in), new PkiId(in.readUTF()), new CertificateProfileRef(in.readUTF(), in.readLong(), in.readNBytes(32)),
                    new PkiId(in.readUTF()), new PkiId(in.readUTF()),
                    in.readUTF(), in.readUTF(), in.readUTF(), in.readInt(), requestId(in), optional(in), in.readBoolean(),
                    instant(in), instant(in), in.readInt());
            Optional<String> enrollment = optional(in);
            Optional<CmpTransaction.Response> response = in.readBoolean() ? Optional.of(new CmpTransaction.Response(
                    in.readUTF(), in.readUTF(), in.readInt(), in.readUTF(), in.readUTF(),
                    in.readBoolean() ? Optional.of(instant(in)) : Optional.empty(), CmpTransaction.Confirmation.valueOf(in.readUTF()), in.readBoolean())) : Optional.empty();
            CmpTransaction result = new CmpTransaction(id, revision, frozen, enrollment, response);
            if (in.read() != -1 || !id.equals(record.recordId()) || !Arrays.equals(payload, encode(result))) {
                throw invalid();
            }
            reservation(result);
            return result;
        } catch (IOException | IllegalArgumentException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    /* default */ static List<ServerControlStore.ProtocolMutation> create(CmpTransaction value) {
        List<ServerControlStore.ProtocolMutation> mutations = new ArrayList<>(slots(value) + 1);
        mutations.add(new ServerControlStore.ProtocolMutation(record(value), Optional.empty()));
        for (int index = 0; index < slots(value); index++) {
            mutations.add(
                new ServerControlStore.ProtocolMutation(slot(value.id(), index, new byte[0]), Optional.empty()));
        }
        return List.copyOf(mutations);
    }

    /* default */ static List<ServerControlStore.ProtocolMutation> response(ServerControlStore control, CmpTransaction prior,
            CmpTransaction next, byte[] response) {
        if (response.length != next.response().orElseThrow().length() || !hash(response).equals(next.response().orElseThrow().responseSha256())) {
            throw invalid();
        }
        List<ServerControlStore.ProtocolMutation> mutations = new ArrayList<>(slots(prior) + 1);
        mutations.add(new ServerControlStore.ProtocolMutation(record(next), Optional.of(prior.commitment())));
        for (int index = 0; index < slots(prior); index++) {
            ServerControlStore.ProtocolRecord old = control.protocolRecord(ServerControlStore.CMP_RESPONSE, slotId(prior.id(), index)).orElseThrow(CmpTransactionCodec::invalid);
            slotData(old, prior.id(), index);
            int start = Math.min(response.length, index * SLOT_BYTES);
            int end = Math.min(response.length, start + SLOT_BYTES);
            mutations.add(new ServerControlStore.ProtocolMutation(slot(prior.id(), index, Arrays.copyOfRange(response, start, end)), Optional.of(old.commitment())));
        }
        return List.copyOf(mutations);
    }

    /* default */ static byte[] response(ServerControlStore control, CmpTransaction value) {
        int length = value.response().map(CmpTransaction.Response::length).orElse(0);
        byte[] result = new byte[length];
        int offset = 0;
        for (int index = 0; index < slots(value); index++) {
            ServerControlStore.ProtocolRecord record = control.protocolRecord(ServerControlStore.CMP_RESPONSE, slotId(value.id(), index)).orElseThrow(CmpTransactionCodec::invalid);
            byte[] data = slotData(record, value.id(), index);
            int expected = Math.min(SLOT_BYTES, length - offset);
            if (data.length != expected) {
                throw invalid();
            }
            System.arraycopy(data, 0, result, offset, data.length); offset += data.length;
        }
        if (offset != length || value.response().filter(r -> !r.responseSha256().equals(hash(result))).isPresent()) {
            throw invalid();
        }
        return result;
    }

    /* default */ static void requireOwnedSlot(ServerControlStore control, ServerControlStore.ProtocolRecord record) {
        int separator = record.recordId().lastIndexOf(':');
        if (separator <= 0) {
            throw invalid();
        }
        String id = record.recordId().substring(0, separator);
        int index;
        try { index = Integer.parseInt(record.recordId().substring(separator + 1)); }
        catch (NumberFormatException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        CmpTransaction manifest = control.protocolRecord(ServerControlStore.CMP_TRANSACTION, id).map(CmpTransactionCodec::decode).orElseThrow(CmpTransactionCodec::invalid);
        if (index < 0 || index >= slots(manifest)) {
            throw invalid();
        }
        slotData(record, id, index);
    }

    private static ServerControlStore.ProtocolRecord slot(String id, int index, byte[] data) {
        byte[] payload = bytes(out -> {
            out.writeInt(VERSION); out.writeUTF(id); out.writeInt(index); out.writeInt(data.length); out.write(data);
        });
        return new ServerControlStore.ProtocolRecord(ServerControlStore.CMP_RESPONSE, slotId(id, index), hash(payload), payload);
    }
    private static byte[] slotData(ServerControlStore.ProtocolRecord record, String id, int index) {
        byte[] payload = record.payload();
        if (!ServerControlStore.CMP_RESPONSE.equals(record.namespace()) || !record.recordId().equals(slotId(id, index))
                || !hash(payload).equals(record.commitment())) {
            throw invalid();
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (in.readInt() != VERSION || !in.readUTF().equals(id) || in.readInt() != index) {
                throw invalid();
            }
            int size = in.readInt();
            if (size < 0 || size > SLOT_BYTES || size != in.available()) {
                throw invalid();
            }
            return in.readNBytes(size);
        } catch (IOException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    private static String hash(byte[] payload) { return EnrollmentTransactionCodec.sha256(payload); }
    private static BigInteger requestId(DataInputStream in) throws IOException {
        String value = in.readUTF();
        if (value.length() > MAX_SLOT_INDEX_TEXT_LENGTH) {
            throw invalid();
        }
        return new BigInteger(value);
    }
    private static void optional(DataOutputStream out, Optional<String> value) throws IOException {
        out.writeBoolean(value.isPresent()); if (value.isPresent()) {
            out.writeUTF(value.orElseThrow());
        }
    }
    private static Optional<String> optional(DataInputStream in) throws IOException { return in.readBoolean() ? Optional.of(in.readUTF()) : Optional.empty(); }
    private static void instant(DataOutputStream out, Instant value) throws IOException { out.writeLong(value.getEpochSecond()); out.writeInt(value.getNano()); }
    private static Instant instant(DataInputStream in) throws IOException { return Instant.ofEpochSecond(in.readLong(), in.readInt()); }
    private static byte[] bytes(Encoder encoder) {
        try (ByteArrayOutputStream bytes = new BoundedBytes(); DataOutputStream out = new DataOutputStream(bytes)) {
            encoder.write(out); out.flush();
            if (bytes.size() > EnrollmentTransactionCodec.MAXIMUM_BYTES) {
                throw invalid();
            }
            return bytes.toByteArray();
        } catch (IOException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    private static IllegalStateException invalid() { return new IllegalStateException("CMP retained state is invalid"); }
    /** Rejects encoded transaction growth before the persistent record limit is exceeded. */
    private static final class BoundedBytes extends ByteArrayOutputStream {
        // Preserves ByteArrayOutputStream synchronization while enforcing the encoded-size bound.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void write(int value) {
            if (count == EnrollmentTransactionCodec.MAXIMUM_BYTES) {
                throw invalid();
            }
            super.write(value);
        }
        // Preserves ByteArrayOutputStream synchronization while enforcing the encoded-size bound.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void write(byte[] values, int offset, int length) {
            if (length > EnrollmentTransactionCodec.MAXIMUM_BYTES - count) {
                throw invalid();
            }
            super.write(values, offset, length);
        }
    }
    /** Encodes one canonical record into an owned output buffer. */
    @FunctionalInterface private interface Encoder {
        /**
         * Writes the canonical binary representation.
         * @param out borrowed output
         * @throws IOException if encoding fails
         */
        void write(DataOutputStream out) throws IOException;
    }
}
