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

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Strict store- and cutoff-bound opaque pending-review cursor codec. */
@SuppressWarnings({ "PMD.ExceptionAsFlowControl", "PMD.PreserveStackTrace" })
final class CredentialConfirmationReviewCursorCodec {
    private static final int MAGIC = 0x5a454352; // ZECR
    private static final int VERSION = 2;
    private static final int STORE_ID_BYTES = 16;
    private static final int SCOPE_BINDING_BYTES = 32;
    private static final int CHECKSUM_BYTES = 32;
    private static final long MAXIMUM_EPOCH_SECOND = 253_402_300_799L;
    private static final byte[] DOMAIN =
            "zeroecho:credential-confirmation-review-cursor:v2".getBytes(StandardCharsets.US_ASCII);
    private static final HexFormat HEX = HexFormat.of();

    private CredentialConfirmationReviewCursorCodec() { }

    /* default */ static CredentialConfirmationReviewCursor encode(MetadataStoreId storeId,
            byte[] scopeBinding, Instant cutoff, Instant reviewAt, PkiId credentialId) {
        byte[] identity = credentialId.value().getBytes(StandardCharsets.UTF_8);
        ByteBuffer body = ByteBuffer.allocate(Integer.BYTES * 5 + Long.BYTES * 2
                + STORE_ID_BYTES + SCOPE_BINDING_BYTES + identity.length);
        body.putInt(MAGIC).putInt(VERSION).put(HEX.parseHex(storeId.value()))
                .put(requireScopeBinding(scopeBinding));
        putInstant(body, cutoff);
        putInstant(body, reviewAt);
        body.putInt(identity.length).put(identity);
        byte[] framed = body.array();
        ByteBuffer complete = ByteBuffer.allocate(framed.length + CHECKSUM_BYTES);
        complete.put(framed).put(checksum(framed));
        return new CredentialConfirmationReviewCursor(Base64.getUrlEncoder().withoutPadding()
                .encodeToString(complete.array()));
    }

    /* default */ static State decode(CredentialConfirmationReviewCursor cursor) {
        try {
            byte[] encoded = Base64.getUrlDecoder().decode(cursor.value());
            int fixed = Integer.BYTES * 5 + Long.BYTES * 2 + STORE_ID_BYTES
                    + SCOPE_BINDING_BYTES + CHECKSUM_BYTES;
            if (encoded.length <= fixed || encoded.length > fixed
                    + CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES) {
                throw malformed();
            }
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(encoded).equals(cursor.value())) {
                throw malformed();
            }
            int bodyLength = encoded.length - CHECKSUM_BYTES;
            if (!MessageDigest.isEqual(Arrays.copyOfRange(encoded, bodyLength, encoded.length),
                    checksum(Arrays.copyOf(encoded, bodyLength)))) {
                throw malformed();
            }
            ByteBuffer input = ByteBuffer.wrap(encoded, 0, bodyLength);
            if (input.getInt() != MAGIC || input.getInt() != VERSION) {
                throw malformed();
            }
            byte[] store = new byte[STORE_ID_BYTES];
            input.get(store);
            MetadataStoreId storeId = new MetadataStoreId(HEX.formatHex(store));
            byte[] scopeBinding = new byte[SCOPE_BINDING_BYTES];
            input.get(scopeBinding);
            Instant cutoff = readInstant(input);
            Instant reviewAt = readInstant(input);
            int identityLength = input.getInt();
            if (identityLength <= 0
                    || identityLength > CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES
                    || input.remaining() != identityLength) {
                throw malformed();
            }
            byte[] identity = new byte[identityLength];
            input.get(identity);
            String decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(identity)).toString();
            PkiId credentialId = new PkiId(decoded);
            // Reuse the public model's exact strict UTF-8 bound.
            new CredentialConfirmationInitialization(credentialId,
                    zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy.PUBLIC,
                    "0".repeat(64), false, reviewAt,
                    new zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef(
                            "cursor.v1", "0".repeat(64)));
            return new State(storeId, scopeBinding, cutoff, reviewAt, credentialId);
        } catch (IllegalArgumentException | java.nio.BufferUnderflowException
                | CharacterCodingException failure) {
            throw malformed();
        }
    }

    private static void putInstant(ByteBuffer output, Instant value) {
        output.putLong(value.getEpochSecond()).putInt(value.getNano());
    }

    private static Instant readInstant(ByteBuffer input) {
        long seconds = input.getLong();
        int nanos = input.getInt();
        if (seconds < 0L || seconds > MAXIMUM_EPOCH_SECOND
                || nanos < 0 || nanos > 999_999_999) {
            throw malformed();
        }
        return Instant.ofEpochSecond(seconds, nanos);
    }

    private static byte[] checksum(byte[] body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(DOMAIN.length).array());
            digest.update(DOMAIN);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(body.length).array());
            return digest.digest(body);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static byte[] requireScopeBinding(byte[] value) {
        if (value == null || value.length != SCOPE_BINDING_BYTES) {
            throw new IllegalArgumentException("Confirmation review cursor scope binding is invalid");
        }
        return value;
    }

    private static IllegalArgumentException malformed() {
        return new IllegalArgumentException("Confirmation review cursor is malformed");
    }

    /** Decoded non-authoritative traversal state. */
    /* default */ record State(MetadataStoreId storeId, byte[] scopeBinding, Instant cutoff,
            Instant reviewAt, PkiId credentialId) {
        State {
            scopeBinding = scopeBinding.clone();
        }

        @Override
        public byte[] scopeBinding() {
            return scopeBinding.clone();
        }
    }
}
