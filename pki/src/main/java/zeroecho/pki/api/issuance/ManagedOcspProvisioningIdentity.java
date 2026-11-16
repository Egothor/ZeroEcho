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

package zeroecho.pki.api.issuance;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;

/**
 * Derives canonical managed-responder provisioning coordinates from public evidence.
 *
 * <p>Identities use domain-separated, length-framed SHA-256 commitments. Callers
 * supply actual managed public keys and an authoritative revision; this utility
 * neither resolves a key nor reserves a slot, creates a request, proves possession
 * or grants authorization. Server realm scoping is distinct from the store-local
 * core identity and must come from trusted configuration.
 */
public final class ManagedOcspProvisioningIdentity {
    private ManagedOcspProvisioningIdentity() {
    }
    /**
     * Derives the stable core slot from actual managed public keys, independent of caller IDs and realm names.
     *
     * <p>The caller must resolve and validate the public keys before invoking this
     * function. The function checks DER labeling and a one-MiB byte bound but does
     * not parse the SPKI or establish its managed custody. Primary and alternative
     * SPKI digests occupy distinct ordered fields in the core-slot commitment.
     *
     * @param authorityId exact logical authority in the owning store
     * @param issuerId selected immutable issuer-generation identity
     * @param primarySpki actual managed primary SubjectPublicKeyInfo DER
     * @param alternativeSpki actual managed alternative SubjectPublicKeyInfo DER
     * @return raw lowercase SHA256 slot ID
     * @throws NullPointerException if an authority, issuer or SPKI argument is null
     * @throws IllegalArgumentException if an identifier is invalid or unbounded, or a public-key
     *         encoding is not DER-labeled or exceeds one MiB
     * @throws IllegalStateException if the required SHA-256 implementation is unavailable
     */
    public static String coreSlotId(PkiId authorityId, PkiId issuerId, EncodedObject primarySpki, EncodedObject alternativeSpki) {
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(issuerId, "issuerId");
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(authorityId.value());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(issuerId.value());
        return framed(text("zeroecho:ocsp-responder-core-slot:v1"), text(authorityId.value()), text(issuerId.value()),
                spkiHash(primarySpki), spkiHash(alternativeSpki));
    }
    /**
     * Maps a core slot into one trusted server realm; callers must supply the realm from server configuration.
     *
     * <p>The realm has 1 through 256 ASCII identifier characters, beginning with a
     * letter or digit. Scoping an identity does not authenticate that realm or authorize
     * provisioning; no record is read or written by this derivation.
     *
     * @param trustedRealmId configured realm identifier, never an applicant-selected salt
     * @param coreSlotId canonical core slot as 64 lowercase hexadecimal characters
     * @return distinct raw lowercase SHA256 server slot ID
     * @throws IllegalArgumentException if the realm or core-slot representation is null or malformed
     * @throws IllegalStateException if the required SHA-256 implementation is unavailable
     */
    public static String serverSlotId(String trustedRealmId, String coreSlotId) {
        if (trustedRealmId == null || !trustedRealmId.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
            throw invalid();
        }
        digest(coreSlotId);
        return framed(text("zeroecho:ocsp-responder-server-slot:v1"), text(trustedRealmId), text(coreSlotId));
    }
    /**
     * Returns the canonical core issuance identity for an authoritative slot revision.
     *
     * <p>The caller supplies the already-selected authoritative revision. This
     * function does not increment it or choose a new retry identity.
     *
     * @param coreSlotId stable core slot as 64 lowercase hexadecimal characters
     * @param revision positive authoritative revision
     * @return bounded canonical issuance ID
     * @throws IllegalArgumentException if the slot is null or malformed, or the revision is not positive
     */
    public static String coreIssuanceId(String coreSlotId, long revision) {
        return canonical(coreSlotId, revision);
    }
    /**
     * Returns the canonical administrative request identity, distinct from core issuance identity.
     *
     * <p>Use the server-scoped slot derived from trusted realm configuration, not
     * the core slot. Request identity is deterministic for that slot/revision and
     * does not imply that a request has been admitted or approved.
     *
     * @param serverSlotId trusted-realm slot as 64 lowercase hexadecimal characters
     * @param revision positive authoritative revision
     * @return bounded canonical administrative request ID
     * @throws IllegalArgumentException if the slot is null or malformed, or the revision is not positive
     */
    public static String serverRequestId(String serverSlotId, long revision) {
        return canonical(serverSlotId, revision);
    }
    private static String canonical(String slot, long revision) {
        digest(slot);
        if (revision < 1) {
            throw invalid();
        }
        return "ocsp-prov:" + slot + ":r" + revision;
    }
    private static byte[] spkiHash(EncodedObject value) {
        Objects.requireNonNull(value, "spki");
        if (value.encoding() != Encoding.DER || value.byteLength() > 1_048_576) {
            throw invalid();
        }
        return sha256(value.bytes());
    }
    private static byte[] text(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
    private static String framed(byte[]... fields) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream output = new DataOutputStream(bytes)) {
            for (byte[] field : fields) {
                output.writeInt(field.length);
                output.write(field);
            }
            output.flush();
            return HexFormat.of().formatHex(sha256(bytes.toByteArray()));
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
    private static void digest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw invalid();
        }
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("OCSP provisioning identity invalid");
    }
}
