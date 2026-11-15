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

package zeroecho.pki.impl.core.continuation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.core.PreparedFullCrlTbs;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Strict version-one qualified CRL descriptor; no private keys or whole CRLs are encoded. */
public final class CrlHybridSigningCommand {
    /** Owner-selected interoperable CRL transcript, distinct from certificate Cor3. */
    public static final String PROFILE = "ZEROECHO_CRL_ALT_BC186_V1";
    /** Exact issuer generation retained after signing-record purge. */
    public static final zeroecho.pki.api.attr.AttributeId ISSUER_GENERATION = new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.issuer-generation");
    /** Exact immutable two-role binding digest. */
    public static final zeroecho.pki.api.attr.AttributeId ISSUER_BINDING = new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.issuer-binding-sha256");
    /** Actual CRL role-presentation tuple commitment. */
    public static final zeroecho.pki.api.attr.AttributeId ROLE_TUPLE = new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.role-tuple-sha256");
    /** Immutable compatible-generation lineage. */
    public static final zeroecho.pki.api.attr.AttributeId SIGNER_LINEAGE = new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.signer-lineage");
    /** Explicit qualified alternative CRL profile. */
    public static final zeroecho.pki.api.attr.AttributeId SIGNATURE_PROFILE = new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.signature-profile");
    /** Full CRL dependency retained for delta snapshot export after workflow purge. */
    public static final zeroecho.pki.api.attr.AttributeId BASE_STATUS_ID = new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.base-status-id");
    private static final String OPERATION = "CRL_HYBRID_V1";
    private CrlHybridSigningCommand() { }

    /**
     * Identifies only the explicit extended full/delta command variants.
     * @param command decoded outer command
     * @return whether the exact supported operation has its one descriptor suffix
     */
    public static boolean isHybrid(DomainCommandEncoding.Decoded command) {
        return FullCrlSigningCommand.OPERATION.equals(command.operation()) && command.fields().size() == 32
                || FullCrlSigningCommand.DELTA_OPERATION.equals(command.operation()) && command.fields().size() == 37;
    }

    /**
     * Derives a distinct native child in the exact parent namespace and creation time.
     * @param parentId canonical accepted parent identity
     * @return deterministic private native-child identity
     */
    public static PkiId nativeChildId(PkiId parentId) {
        var parent = SigningSubmissionId.parse(parentId);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                    ("zeroecho-crl-native-child-v1\0" + parentId.value()).getBytes(StandardCharsets.UTF_8));
            PkiId child = new PkiId("zsign:v1:" + parent.namespace() + ":" + parent.createdAt().toEpochMilli()
                    + ":" + HexFormat.of().formatHex(digest, 0, 16));
            SigningSubmissionId.parse(child);
            if (child.equals(parentId)) throw new IllegalArgumentException("CRL parent/child identity collision");
            return child;
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    /**
     * Freezes the nine scalar descriptor fields without copying public keys.
     * @param prepared exact alternative transcript preparation
     * @param parentId selected public signing identity
     * @return extended correlated STATUS command
     */
    public static DomainContinuationTemplate template(PreparedFullCrlTbs prepared, PkiId parentId) {
        var hybrid = prepared.hybrid().orElseThrow();
        var descriptor = new Descriptor(hybrid.binding().commitment(), hybrid.tupleCommitment(), nativeChildId(parentId),
                hybrid.primaryPlanCommitment(), hybrid.alternativePlanCommitment(),
                hybrid.alternativeMaximumSignatureBytes(), hybrid.primaryMaximumSignatureBytes());
        return FullCrlSigningCommand.template(prepared, descriptor.encode());
    }

    /**
     * Restores and validates the sole descriptor suffix and empty-key sentinel.
     * @param command explicit extended command
     * @return bounded validated descriptor
     */
    public static Descriptor descriptor(DomainCommandEncoding.Decoded command) {
        if (!isHybrid(command) || !command.field(5).isEmpty()) throw new IllegalArgumentException("Invalid hybrid CRL variant");
        String value = command.field(command.fields().size() - 1);
        if (value.length() > 16_384) throw new IllegalArgumentException("Hybrid CRL descriptor is too large");
        byte[] bytes = Base64.getUrlDecoder().decode(value);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value))
            throw new IllegalArgumentException("Noncanonical hybrid CRL descriptor");
        var decoded = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes));
        decoded.requireFields(9);
        if (!OPERATION.equals(decoded.operation()) || !"1".equals(decoded.field(0)) || !PROFILE.equals(decoded.field(1)))
            throw new IllegalArgumentException("Unsupported hybrid CRL profile");
        return new Descriptor(decoded.field(2), decoded.field(3), new PkiId(decoded.field(4)), decoded.field(5), decoded.field(6),
                bound(decoded.field(7)), bound(decoded.field(8)));
    }

    private static int bound(String value) {
        int parsed = Integer.parseInt(value);
        if (parsed < 1 || parsed > 1_048_576 || !Integer.toString(parsed).equals(value))
            throw new IllegalArgumentException("Invalid hybrid CRL signature bound");
        return parsed;
    }

    /** Immutable bounded role and child commitments.
     * @param issuerBindingCommitment complete retained generation binding
     * @param roleTupleCommitment compatible CRL signer tuple
     * @param nativeChildId predetermined private child
     * @param primaryPlanCommitment frozen native execution plan
     * @param alternativePlanCommitment frozen alternative execution plan
     * @param alternativeMaximumSignatureBytes maximum external alternative result
     * @param primaryMaximumSignatureBytes maximum external native result
     */
    public record Descriptor(String issuerBindingCommitment, String roleTupleCommitment, PkiId nativeChildId,
            String primaryPlanCommitment, String alternativePlanCommitment,
            int alternativeMaximumSignatureBytes, int primaryMaximumSignatureBytes) {
        /** Validates canonical fixed-size commitments, child grammar and byte bounds. */
        public Descriptor {
            for (String value : new String[] {issuerBindingCommitment, roleTupleCommitment, primaryPlanCommitment, alternativePlanCommitment})
                if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid CRL commitment");
            SigningSubmissionId.parse(nativeChildId);
            bound(Integer.toString(alternativeMaximumSignatureBytes)); bound(Integer.toString(primaryMaximumSignatureBytes));
        }
        /** @return canonical unpadded base64url version-one descriptor */
        public String encode() {
            var command = DomainCommandEncoding.template(DomainContinuationStore.Kind.STATUS, OPERATION,
                    "1", PROFILE, issuerBindingCommitment, roleTupleCommitment, nativeChildId.value(),
                    primaryPlanCommitment, alternativePlanCommitment,
                    Integer.toString(alternativeMaximumSignatureBytes), Integer.toString(primaryMaximumSignatureBytes));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(command.command().bytes());
        }
    }
}
