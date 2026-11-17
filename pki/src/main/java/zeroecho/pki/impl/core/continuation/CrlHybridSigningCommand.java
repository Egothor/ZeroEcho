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

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.core.PreparedFullCrlTbs;
import zeroecho.pki.spi.store.DomainContinuationStore;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Encodes the version-one role descriptor for the qualified hybrid CRL signing workflow.
 *
 * <p>The descriptor binds issuer and role-plan commitments, a predetermined internal
 * child signing identity and signature-size bounds. It contains neither private keys
 * nor whole CRLs. Structural decoding does not verify CRL signatures or authorize
 * a signer; continuation validation and configured execution retain those duties.
 */
public final class CrlHybridSigningCommand {
    private static final int MAX_ALGORITHM_BYTES = 16_384;

    /**
     * Identifier of the qualified CRL alternative-signature transcript, distinct from
     * the certificate Cor3 transcript.
     */
    public static final String PROFILE = "ZEROECHO_CRL_ALT_BC186_V1";

    /**
     * Attribute retaining the exact issuer-generation identity after signing records are purged.
     */
    public static final zeroecho.pki.api.attr.AttributeId ISSUER_GENERATION =
            new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.issuer-generation");

    /** Attribute retaining the SHA-256 commitment of the immutable two-role issuer binding. */
    public static final zeroecho.pki.api.attr.AttributeId ISSUER_BINDING =
            new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.issuer-binding-sha256");

    /** Attribute retaining the commitment of the actual CRL role-presentation tuple. */
    public static final zeroecho.pki.api.attr.AttributeId ROLE_TUPLE =
            new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.role-tuple-sha256");

    /** Attribute retaining the immutable lineage shared by compatible signer generations. */
    public static final zeroecho.pki.api.attr.AttributeId SIGNER_LINEAGE =
            new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.signer-lineage");

    /** Attribute identifying the explicitly qualified alternative CRL signature profile. */
    public static final zeroecho.pki.api.attr.AttributeId SIGNATURE_PROFILE =
            new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.signature-profile");

    /**
     * Attribute retaining the full-CRL dependency needed to export a delta snapshot after its
     * signing workflow is purged.
     */
    public static final zeroecho.pki.api.attr.AttributeId BASE_STATUS_ID =
            new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.crl.base-status-id");

    private static final String OPERATION = "CRL_HYBRID_V1";
    private CrlHybridSigningCommand() {
    }

    /**
     * Identifies only the explicit extended full/delta command variants.
     *
     * <p>This predicate checks the operation discriminator and field count only.
     * Call {@link #descriptor(DomainCommandEncoding.Decoded)} to validate the suffix
     * and hybrid empty-key sentinel; successful identification is not command admission.
     *
     * @param command decoded outer command
     * @return whether the exact supported operation has its one descriptor suffix
     * @throws NullPointerException if the command is null
     */
    public static boolean isHybrid(DomainCommandEncoding.Decoded command) {
        return FullCrlSigningCommand.OPERATION.equals(command.operation()) && command.fields().size() == 32
                || FullCrlSigningCommand.DELTA_OPERATION.equals(command.operation()) && command.fields().size() == 37;
    }

    /**
     * Derives a distinct native child in the exact parent namespace and creation time.
     *
     * <p>The child's 128-bit suffix is deterministically derived from a domain-separated
     * SHA-256 digest of the parent identity. No random source, provider or store is
     * consulted, so recovery obtains the same child identity without admitting a new job.
     * A collision with the parent fails rather than reusing the parent signing identity.
     *
     * @param parentId canonical accepted parent identity
     * @return deterministic internal native-child identity, distinct from the parent
     * @throws NullPointerException if the parent identity is null
     * @throws IllegalArgumentException if the parent identity is malformed or collides with its child
     * @throws IllegalStateException if the required SHA-256 implementation is unavailable
     */
    public static PkiId nativeChildId(PkiId parentId) {
        SigningSubmissionId parent = SigningSubmissionId.parse(parentId);
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-256")
                            .digest(
                                    ("zeroecho-crl-native-child-v1\0" + parentId.value())
                                            .getBytes(StandardCharsets.UTF_8));
            PkiId child =
                    new PkiId(
                            "zsign:v1:"
                                    + parent.namespace()
                                    + ":"
                                    + parent.createdAt().toEpochMilli()
                                    + ":"
                                    + HexFormat.of().formatHex(digest, 0, 16));
            SigningSubmissionId.parse(child);
            if (child.equals(parentId)) {
                throw new IllegalArgumentException("CRL parent/child identity collision");
            }
            return child;
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /**
     * Freezes the nine scalar descriptor fields without copying public keys.
     *
     * <p>The preparation must contain hybrid role evidence. The returned template
     * records that evidence and the deterministic child identity but does not submit
     * the command, resolve a private key or consume a signing result.
     *
     * @param prepared exact alternative transcript preparation
     * @param parentId selected public signing identity
     * @return extended correlated STATUS command
     * @throws NullPointerException if the preparation or parent identity is null
     * @throws java.util.NoSuchElementException if the preparation has no hybrid evidence
     * @throws IllegalArgumentException if the identity, descriptor or enclosing command is invalid
     */
    public static DomainContinuationTemplate template(PreparedFullCrlTbs prepared, PkiId parentId) {
        PreparedFullCrlTbs.Hybrid hybrid = prepared.hybrid().orElseThrow();
        Descriptor descriptor = new Descriptor(hybrid.binding().commitment(), hybrid.tupleCommitment(), nativeChildId(parentId),
                hybrid.primaryPlanCommitment(), hybrid.alternativePlanCommitment(),
                hybrid.alternativeMaximumSignatureBytes(), hybrid.primaryMaximumSignatureBytes());
        return FullCrlSigningCommand.template(prepared, descriptor.encode());
    }

    /**
     * Restores and validates the sole descriptor suffix and empty-key sentinel.
     *
     * <p>The suffix must be canonical unpadded Base64url, no more than 16,384
     * characters, with exactly nine fields and the supported version and profile.
     * Decoding validates commitment and child-identity structure; it does not compare
     * those commitments with a live issuer or execution plan.
     *
     * @param command explicit extended command
     * @return bounded validated descriptor
     * @throws NullPointerException if the command is null
     * @throws IllegalArgumentException if the command variant, sentinel, framing,
     *         encoding, profile, commitment, identity or signature bound is invalid
     */
    public static Descriptor descriptor(DomainCommandEncoding.Decoded command) {
        if (!isHybrid(command) || !command.field(5).isEmpty()) {
            throw new IllegalArgumentException("Invalid hybrid CRL variant");
        }
        String value = command.field(command.fields().size() - 1);
        if (value.length() > MAX_ALGORITHM_BYTES) {
            throw new IllegalArgumentException("Hybrid CRL descriptor is too large");
        }
        byte[] bytes = Base64.getUrlDecoder().decode(value);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) {
            throw new IllegalArgumentException("Noncanonical hybrid CRL descriptor");
        }
        DomainCommandEncoding.Decoded decoded = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes));
        decoded.requireFields(9);
        if (!OPERATION.equals(decoded.operation()) || !"1".equals(decoded.field(0)) || !PROFILE.equals(decoded.field(1))) {
            throw new IllegalArgumentException("Unsupported hybrid CRL profile");
        }
        return new Descriptor(decoded.field(2), decoded.field(3), new PkiId(decoded.field(4)), decoded.field(5), decoded.field(6),
                bound(decoded.field(7)), bound(decoded.field(8)));
    }

    private static int bound(String value) {
        int parsed = Integer.parseInt(value);
        if (parsed < 1 || parsed > 1_048_576 || !Integer.toString(parsed).equals(value)) {
            throw new IllegalArgumentException("Invalid hybrid CRL signature bound");
        }
        return parsed;
    }

    /**
     * Retains bounded issuer, role-plan and internal-child coordinates for hybrid CRL signing.
     *
     * <p>Every digest is a canonical SHA-256 coordinate. The child identity must parse as a
     * signing-submission identity; this record alone does not prove that it is the deterministic
     * child of a particular parent or that a current plan matches.
     *
     * @param issuerBindingCommitment complete issuer-binding digest as 64 lowercase hexadecimal
     *     characters
     * @param roleTupleCommitment compatible signer-tuple digest as 64 lowercase hexadecimal
     *     characters
     * @param nativeChildId predetermined internal child signing identity; must not be null
     * @param primaryPlanCommitment frozen primary-plan digest as 64 lowercase hexadecimal
     *     characters
     * @param alternativePlanCommitment frozen alternative-plan digest as 64 lowercase hexadecimal
     *     characters
     * @param alternativeMaximumSignatureBytes maximum alternative result, between 1 and 1,048,576
     *     bytes
     * @param primaryMaximumSignatureBytes maximum primary result, between 1 and 1,048,576 bytes
     */
    // Component accessors are part of the existing public contract.
    @SuppressWarnings("PMD.LongVariable")
    public record Descriptor(
            String issuerBindingCommitment,
            String roleTupleCommitment,
            PkiId nativeChildId,
            String primaryPlanCommitment,
            String alternativePlanCommitment,
            int alternativeMaximumSignatureBytes,
            int primaryMaximumSignatureBytes) {
        /**
         * Validates digest representations, child-identity grammar and signature-size bounds.
         *
         * @throws NullPointerException if the child identity is null
         * @throws IllegalArgumentException if a digest is null or malformed, the child
         *         identity is malformed, or a signature bound is outside its permitted range
         * @param issuerBindingCommitment complete issuer-binding digest as 64 lowercase hexadecimal characters
         * @param roleTupleCommitment compatible signer-tuple digest as 64 lowercase hexadecimal characters
         * @param nativeChildId predetermined internal child signing identity; must not be null
         * @param primaryPlanCommitment frozen primary-plan digest as 64 lowercase hexadecimal characters
         * @param alternativePlanCommitment frozen alternative-plan digest as 64 lowercase hexadecimal characters
         * @param alternativeMaximumSignatureBytes maximum alternative result, between 1 and 1,048,576 bytes
         * @param primaryMaximumSignatureBytes maximum primary result, between 1 and 1,048,576 bytes
         */
        public Descriptor {
            for (String value : new String[] {issuerBindingCommitment, roleTupleCommitment, primaryPlanCommitment, alternativePlanCommitment}) {
                if (value == null || !value.matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("Invalid CRL commitment");
                }
            }
            SigningSubmissionId.parse(nativeChildId);
            bound(Integer.toString(alternativeMaximumSignatureBytes));
            bound(Integer.toString(primaryMaximumSignatureBytes));
        }
        /**
         * Encodes the exact retained coordinates as a version-one hybrid CRL descriptor.
         *
         * <p>The output is canonical unpadded Base64url and contains public scalar
         * metadata only. The enclosing full or delta command supplies the remaining
         * frozen CRL context.
         *
         * @return the complete nine-field descriptor encoding
         */
        public String encode() {
            DomainContinuationTemplate command =
                    DomainCommandEncoding.template(
                            DomainContinuationStore.Kind.STATUS,
                            OPERATION,
                            "1",
                            PROFILE,
                            issuerBindingCommitment,
                            roleTupleCommitment,
                            nativeChildId.value(),
                            primaryPlanCommitment,
                            alternativePlanCommitment,
                            Integer.toString(alternativeMaximumSignatureBytes),
                            Integer.toString(primaryMaximumSignatureBytes));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(command.command().bytes());
        }
    }
}
