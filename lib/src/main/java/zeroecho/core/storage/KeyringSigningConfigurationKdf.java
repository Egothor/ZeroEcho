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
package zeroecho.core.storage;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Fixed-purpose signing-configuration tag derivation. */
final class KeyringSigningConfigurationKdf {
    private static final int MASTER_KEY_BYTES = 32;
    private static final int STORE_ID_BYTES = 16;
    private static final int OUTPUT_BYTES = 32;
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String DOMAIN_LABEL = "zeroecho:keyring:signing-configuration-tag:v1";
    private static final String TRANSCRIPT_LABEL = "zeroecho:signing-configuration-transcript:v1";

    private KeyringSigningConfigurationKdf() {
    }

    /** Borrowed encrypted-entry identity required by the signing transcript. */
    /* default */ interface EntryView {
        /** Returns the canonical persisted entry position. */
        int position();

        /** Appends this entry's canonical identity, metadata, and ciphertext digest. */
        void writeSigningConfigurationIdentity(DataOutputStream output) throws IOException;
    }

    /** Encodes, derives, and applies the store-specific signing-configuration tag. */
    /* default */ static byte[] tag(byte[] masterKey, byte[] storeId, String workflowId,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            Collection<? extends EntryView> entries) throws GeneralSecurityException {
        requireString(workflowId, "workflowId");
        Objects.requireNonNull(operationHorizon, "operationHorizon must not be null");
        if (operationHorizon.isZero() || operationHorizon.isNegative()) {
            throw new IllegalArgumentException("operationHorizon must be positive");
        }
        requireString(keyRefPrefix, "keyRefPrefix");
        Objects.requireNonNull(entries, "entries must not be null");
        byte[] transcript = encodeTranscript(workflowId, operationHorizon, keyRefPrefix,
                requireComponentSuffix, entries);
        try {
            return apply(masterKey, storeId, transcript);
        } finally {
            wipe(transcript);
        }
    }

    private static byte[] apply(byte[] masterKey, byte[] storeId, byte[] transcript)
            throws GeneralSecurityException {
        if (masterKey == null || masterKey.length != MASTER_KEY_BYTES || storeId == null
                || storeId.length != STORE_ID_BYTES || transcript == null) {
            throw new IllegalArgumentException("Invalid signing-configuration derivation input");
        }
        byte[] salt = storeId.clone();
        byte[] info = DOMAIN_LABEL.getBytes(StandardCharsets.US_ASCII);
        byte[] prk = null;
        byte[] expandInput = null;
        byte[] derivedKey = null;
        try {
            prk = hmac(salt, masterKey);
            expandInput = Arrays.copyOf(info, info.length + 1);
            expandInput[expandInput.length - 1] = 1;
            derivedKey = hmac(prk, expandInput);
            byte[] tag = hmac(derivedKey, transcript);
            if (tag.length != OUTPUT_BYTES) {
                Arrays.fill(tag, (byte) 0);
                throw new GeneralSecurityException("KEYRING_DERIVATION_FAILED");
            }
            return tag;
        } finally {
            wipe(salt);
            wipe(info);
            wipe(prk);
            wipe(expandInput);
            wipe(derivedKey);
        }
    }

    private static byte[] encodeTranscript(String workflowId, Duration operationHorizon, String keyRefPrefix,
            boolean requireComponentSuffix, Collection<? extends EntryView> entries) {
        List<EntryView> ordered = new ArrayList<>(entries);
        ordered.sort(Comparator.comparingInt(EntryView::position));
        try (WipingByteArrayOutputStream bytes = new WipingByteArrayOutputStream();
                DataOutputStream output = new DataOutputStream(bytes)) {
            writeString(output, TRANSCRIPT_LABEL);
            writeString(output, workflowId);
            writeLong(output, operationHorizon.getSeconds());
            writeInt(output, operationHorizon.getNano());
            writeString(output, keyRefPrefix);
            writeBoolean(output, requireComponentSuffix);
            writeInt(output, ordered.size());
            for (EntryView entry : ordered) {
                entry.writeSigningConfigurationIdentity(output);
            }
            output.flush();
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("KEYRING_SIGNING_CONFIGURATION_TAG_FAILED"); // NOPMD
        }
    }

    /* default */ static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            writeBytes(output, encoded);
        } finally {
            wipe(encoded);
        }
    }

    private static void writeLong(DataOutputStream output, long value) throws IOException {
        byte[] encoded = ByteBuffer.allocate(Long.BYTES).putLong(value).array();
        try {
            writeBytes(output, encoded);
        } finally {
            wipe(encoded);
        }
    }

    /* default */ static void writeInt(DataOutputStream output, int value) throws IOException {
        byte[] encoded = ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
        try {
            writeBytes(output, encoded);
        } finally {
            wipe(encoded);
        }
    }

    private static void writeBoolean(DataOutputStream output, boolean value) throws IOException {
        byte[] encoded = { value ? (byte) 1 : (byte) 0 };
        try {
            writeBytes(output, encoded);
        } finally {
            wipe(encoded);
        }
    }

    /* default */ static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static void requireString(String value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            if (value.isBlank() || encoded.length > KeyringStore.MAX_METADATA_BYTES) {
                throw new IllegalArgumentException(name + " is invalid");
            }
        } finally {
            wipe(encoded);
        }
    }

    private static byte[] hmac(byte[] key, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(key, HMAC_SHA256));
        return mac.doFinal(input);
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    /** Byte-array output whose internal transcript storage is cleared on close. */
    private static final class WipingByteArrayOutputStream extends ByteArrayOutputStream {
        @Override
        public void close() {
            Arrays.fill(buf, (byte) 0);
            reset();
        }
    }
}
