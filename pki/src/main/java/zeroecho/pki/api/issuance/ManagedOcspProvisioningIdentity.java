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

/** Pure store-scoped provisioning identity framing; no identity grants authority or establishes key possession. */
public final class ManagedOcspProvisioningIdentity {
    private ManagedOcspProvisioningIdentity() { }
    /**
     * Derives the stable core slot from actual managed public keys, independent of caller IDs and realm names.
     * @param authorityId owned-store authority @param issuerId immutable generation
     * @param primarySpki actual primary DER SPKI @param alternativeSpki actual alternative DER SPKI
     * @return raw lowercase SHA256 slot ID
     */
    public static String coreSlotId(PkiId authorityId, PkiId issuerId, EncodedObject primarySpki, EncodedObject alternativeSpki) {
        Objects.requireNonNull(authorityId, "authorityId"); Objects.requireNonNull(issuerId, "issuerId");
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(authorityId.value());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(issuerId.value());
        return framed(text("zeroecho:ocsp-responder-core-slot:v1"), text(authorityId.value()), text(issuerId.value()), spkiHash(primarySpki), spkiHash(alternativeSpki));
    }
    /**
     * Maps a core slot into one trusted server realm; callers must supply the realm from server configuration.
     * @param trustedRealmId configured realm, never an untrusted salt @param coreSlotId core identity
     * @return distinct raw lowercase SHA256 server slot ID
     */
    public static String serverSlotId(String trustedRealmId, String coreSlotId) {
        if (trustedRealmId == null || !trustedRealmId.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) throw invalid();
        digest(coreSlotId);
        return framed(text("zeroecho:ocsp-responder-server-slot:v1"), text(trustedRealmId), text(coreSlotId));
    }
    /**
     * Returns the canonical core issuance identity for an authoritative slot revision.
     * @param coreSlotId stable core slot @param revision positive authoritative revision
     * @return bounded canonical issuance ID
     */
    public static String coreIssuanceId(String coreSlotId, long revision) { return canonical(coreSlotId, revision); }
    /**
     * Returns the canonical administrative request identity, distinct from core issuance identity.
     * @param serverSlotId trusted-realm slot @param revision positive authoritative revision
     * @return bounded canonical administrative request ID
     */
    public static String serverRequestId(String serverSlotId, long revision) { return canonical(serverSlotId, revision); }
    private static String canonical(String slot, long revision) {
        digest(slot); if (revision < 1) throw invalid(); return "ocsp-prov:" + slot + ":r" + revision;
    }
    private static byte[] spkiHash(EncodedObject value) {
        Objects.requireNonNull(value, "spki");
        if (value.encoding() != Encoding.DER || value.byteLength() > 1_048_576) throw invalid();
        return sha256(value.bytes());
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String framed(byte[]... fields) {
        try (var bytes = new ByteArrayOutputStream(); var output = new DataOutputStream(bytes)) {
            for (byte[] field : fields) { output.writeInt(field.length); output.write(field); }
            output.flush(); return HexFormat.of().formatHex(sha256(bytes.toByteArray()));
        } catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }
    private static byte[] sha256(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static void digest(String value) { if (value == null || !value.matches("[0-9a-f]{64}")) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("OCSP provisioning identity invalid"); }
}
