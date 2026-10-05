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

package zeroecho.pki.impl.core.continuation;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.DigestOutputStream;
import java.security.NoSuchAlgorithmException;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.impl.framework.x509.StreamingDerWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Arrays;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.core.PreparedFullCrlTbs;
import zeroecho.pki.impl.core.DeltaCrlBase;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.Pkix;

/** Internal durable full-CRL schema shared by preparation, publication and recovery. */
public final class FullCrlSigningCommand { // NOPMD - CyclomaticComplexity totals independent cohesive operations; method-level checks remain enabled.
    /** Full-CRL-only schema discriminator. */
    public static final String OPERATION = "GENERATE_FULL_CRL";
    /** Delta-CRL schema discriminator with an immutable five-field base suffix. */
    public static final String DELTA_OPERATION = "GENERATE_DELTA_CRL";

    /**
     * Tests whether the exact operation uses this streaming CRL schema.
     * @param operation semantic operation discriminator
     * @return true for supported full or delta CRL operations
     */
    public static boolean supports(String operation) {
        return OPERATION.equals(operation) || DELTA_OPERATION.equals(operation);
    }

    private FullCrlSigningCommand() { }

    /**
     * Freezes bounded provenance for an already staged, validated TBS. No content is copied.
     * @param prepared exact completed domain preparation
     * @return correlated durable command
     */
    public static DomainContinuationTemplate template(PreparedFullCrlTbs prepared) {
        String number = prepared.crlNumber().toString();
        boolean delta = prepared.base().isPresent();
        String correlation = (delta ? "delta-crl:" : "full-crl:") + DomainContinuationPublisher.sha256(
                (prepared.scopeDigest() + ":" + number).getBytes(StandardCharsets.US_ASCII));
        String[] fields = {
                prepared.authorityId().value(), delta ? "DELTA_CRL" : "CRL", "x509", prepared.thisUpdate().toString(),
                prepared.nextUpdate().toString(), prepared.signingKeyRef().value(),
                prepared.issuerGenerationId().value(), prepared.issuerCredentialId().value(),
                prepared.signatureAlgorithm(), HexFormat.of().formatHex(Pkix.encodeAlgorithmIdentifier(
                        BcX509AlgorithmAdapter.toLib(prepared.signatureIdentifier()))), number,
                prepared.scopeDigest(), prepared.profile().profileId(), Long.toString(prepared.profile().profileVersion()),
                HexFormat.of().formatHex(prepared.profile().canonicalSha256()), prepared.profilePolicyCommitment(),
                prepared.x509BindingCommitment(), prepared.signatureBinding().bindingId(),
                prepared.signatureBinding().semanticCommitment(), prepared.snapshotId(),
                Long.toString(prepared.snapshotRevision()), Long.toString(prepared.snapshotBoundary()),
                prepared.snapshotCommitment(), prepared.rawEntryCount().isPresent()
                        ? Long.toString(prepared.rawEntryCount().getAsLong()) : "",
                Long.toString(prepared.emittedEntryCount()), Long.toString(prepared.issuerContent().length()),
                prepared.issuerContent().sha256(), Long.toString(prepared.tbsContent().length()),
                prepared.tbsContent().sha256(), prepared.evaluationTime().toString(), prepared.snapshotSourceStoreId().value()};
        if (delta) {
            DeltaCrlBase base = prepared.base().orElseThrow();
            fields = Arrays.copyOf(fields, 36);
            fields[31] = base.statusObjectId().value();
            fields[32] = base.crlNumber().toString();
            fields[33] = Long.toString(base.provenance().revision());
            fields[34] = Long.toString(base.provenance().boundary());
            fields[35] = base.provenance().commitment();
            if (!base.provenance().sourceStoreId().equals(prepared.snapshotSourceStoreId())) {
                throw new IllegalArgumentException("Delta CRL base source differs from its snapshot");
            }
        }
        return DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.STATUS, correlation,
                delta ? DELTA_OPERATION : OPERATION, fields);
    }

    /**
     * Validates the canonical scalar schema without opening any content.
     * @param command frozen full or delta CRL command
     */
    public static void validate(DomainCommandEncoding.Decoded command) {
        boolean delta = DELTA_OPERATION.equals(command.operation());
        command.requireFields(delta ? 36 : 31);
        FullCrlSnapshotProvenance.from(command);
        if (!supports(command.operation()) || !(delta ? "DELTA_CRL" : "CRL").equals(command.field(1))
                || !"x509".equals(command.field(2))) {
            throw new IllegalStateException("Full CRL command discriminator is invalid");
        }
        validateIdentityAndValidity(command);
        validateAlgorithm(command);
        BigInteger number = new BigInteger(command.field(10));
        if (number.signum() < 0 || number.bitLength() > 159 || !number.toString().equals(command.field(10))) {
            throw new IllegalStateException("Full CRL number is invalid");
        }
        validateCommitmentsAndCounts(command);
        if (delta) { validateDeltaBase(command, number); }
    }

    // Each identity is separately validated; reusing an instance would omit validation of another field.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static void validateIdentityAndValidity(DomainCommandEncoding.Decoded command) {
        for (int index : new int[] {0, 6, 7}) { new PkiId(command.field(index)); }
        new KeyRef(command.field(5));
        for (int index : new int[] {3, 4, 29}) {
            if (!Instant.parse(command.field(index)).toString().equals(command.field(index))) {
                throw new IllegalStateException("Full CRL instant is noncanonical");
            }
        }
        if (!Instant.parse(command.field(4)).isAfter(Instant.parse(command.field(3)))) {
            throw new IllegalStateException("Full CRL validity is empty");
        }
        for (int index : new int[] {8, 12, 17, 18, 19}) {
            if (command.field(index).isBlank()) { throw new IllegalStateException("Full CRL identity is empty"); }
        }
    }

    private static void validateAlgorithm(DomainCommandEncoding.Decoded command) {
        byte[] algorithm = HexFormat.of().parseHex(command.field(9));
        if (algorithm.length == 0 || algorithm.length > 16_384
                || algorithm[0] != 0x30 || !HexFormat.of().formatHex(algorithm).equals(command.field(9))) {
            throw new IllegalStateException("Full CRL algorithm encoding is invalid");
        }
        try { new StreamingDerReader().validate(algorithm, 16_384); }
        catch (IOException invalid) { throw new IllegalStateException("Full CRL algorithm is invalid", invalid); }
    }

    private static void validateCommitmentsAndCounts(DomainCommandEncoding.Decoded command) {
        for (int index : new int[] {11, 14, 15, 16, 22, 26, 28}) {
            if (!command.field(index).matches("[0-9a-f]{64}")) {
                throw new IllegalStateException("Full CRL commitment is noncanonical");
            }
        }
        for (int index : new int[] {13, 20, 21, 24, 25, 27}) { nonnegative(command.field(index)); }
        if (!command.field(23).isEmpty() && nonnegative(command.field(23)) < nonnegative(command.field(24))) {
            throw new IllegalStateException("Full CRL emitted count exceeds raw count");
        }
        new CertificateProfileRef(command.field(12), Long.parseLong(command.field(13)),
                HexFormat.of().parseHex(command.field(14)));
        if (Long.parseLong(command.field(25)) == 0 || Long.parseLong(command.field(27)) == 0) {
            throw new IllegalStateException("Full CRL content is empty");
        }
    }

    private static void validateDeltaBase(DomainCommandEncoding.Decoded command, BigInteger number) {
        BigInteger baseNumber = new BigInteger(command.field(32));
        long revision = nonnegative(command.field(33));
        long boundary = nonnegative(command.field(34));
        if (!command.field(31).matches("crl:[0-9a-f]{64}")
                || baseNumber.signum() < 0 || baseNumber.bitLength() > 159
                || !baseNumber.toString().equals(command.field(32)) || number.compareTo(baseNumber) <= 0
                || !command.field(35).matches("[0-9a-f]{64}")
                || revision > Long.parseLong(command.field(20)) || boundary > Long.parseLong(command.field(21))
                || revision == Long.parseLong(command.field(20))
                        && (boundary != Long.parseLong(command.field(21)) || !command.field(35).equals(command.field(22)))) {
            throw new IllegalStateException("Delta CRL base is inconsistent with its frozen snapshot");
        }
    }

    /**
     * Checks live TBS metadata against the frozen command, without restoring retired content.
     * @param command validated frozen command
     * @param content live operation-owned TBS reference
     */
    public static void requireTbs(DomainCommandEncoding.Decoded command, DurableContentReference content) {
        if (content.encoding() != Encoding.DER || content.lifecycle() != DurableContentReference.Lifecycle.OPERATION
                || content.length() != Long.parseLong(command.field(27)) || !content.sha256().equals(command.field(28))) {
            throw new IllegalStateException("Full CRL signing content differs from its frozen command");
        }
    }

    /**
     * Enforces the configured pure-EdDSA message bound before entering a provider.
     * @param algorithm canonical signature algorithm identity
     * @param length candidate message length in bytes
     * @param maximum positive finite pure-EdDSA message bound in bytes
     */
    public static void requireAdmission(String algorithm, long length, long maximum) {
        if (maximum <= 0 || maximum > Integer.MAX_VALUE - 8L) {
            throw new IllegalArgumentException("Pure EdDSA maximum is outside its finite bound");
        }
        if ((BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm().equals(algorithm)
                || BootstrapAlgorithmIdentities.ED448_SIGNATURE.canonicalForm().equals(algorithm)) && length > maximum) {
            throw new IllegalArgumentException("Full CRL exceeds the configured pure EdDSA TBS limit");
        }
    }

    /**
     * Decodes the sole permitted full-CRL completion result.
     * @param result encoded bounded canonical status identity
     * @return parsed status-object identifier
     */
    public static PkiId resultId(EncodedObject result) {
        byte[] bytes = result.bytes();
        String id = new String(bytes, StandardCharsets.US_ASCII);
        if (result.encoding() != Encoding.BINARY || bytes.length != 68 || !id.matches("crl:[0-9a-f]{64}")) {
            throw new IllegalStateException("Full CRL result is not a canonical status identity");
        }
        return new PkiId(id);
    }

    /**
     * Resolves a completed result against authoritative publication metadata without reopening retired TBS.
     * @param store authoritative store containing the published status object
     * @param domain completed CRL continuation with a retained result
     */
    public static void requireCompleted(PkiStore store, DomainContinuationStore.Record domain) {
        PkiId id = resultId(domain.result().orElseThrow());
        StatusObject status = store.getStatusObject(id)
                .orElseThrow(() -> new IllegalStateException("Completed full CRL publication is missing"));
        requireCompleted(status, domain);
    }

    /**
     * Checks a completed result against publication metadata whose content and owner
     * have already been validated by the caller. This check does not open CRL or TBS content.
     *
     * @param status authoritative, independently validated publication metadata
     * @param domain completed full-CRL continuation
     * @throws IllegalStateException if the result identity is malformed or differs
     * @throws RuntimeException if the publication metadata differs from the frozen command
     */
    public static void requireCompleted(StatusObject status, DomainContinuationStore.Record domain) {
        PkiId id = resultId(domain.result().orElseThrow());
        if (!id.equals(status.statusObjectId())) { throw new IllegalStateException("Completed full CRL identity differs"); }
        FullCrlContinuationPublisher.requirePublished(status, domain, status.content());
    }

    /**
     * Checks canonical publication metadata against its retained command, including before acknowledgement.
     * @param status authoritative status metadata
     * @param domain retained publishing or completed continuation
     */
    public static void requirePublicationMetadata(StatusObject status, DomainContinuationStore.Record domain) {
        FullCrlContinuationPublisher.requirePublished(status, domain, status.content());
    }

    /**
     * Checks a proposed publication against the exact accepted TBS and signature in bounded memory.
     * @param store content authority
     * @param status proposed canonical CRL
     * @param domain publishing continuation
     * @param signature authoritative provider result
     * @throws IOException if content cannot be read
     */
    public static void requireSigningEffect(PkiStore store, StatusObject status,
            DomainContinuationStore.Record domain, EncodedObject signature) throws IOException {
        FullCrlContinuationPublisher.requirePublished(status, domain, status.content());
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(domain.command());
        validate(command);
        DurableContentReference tbs = domain.signingContent().orElseThrow();
        requireTbs(command, tbs);
        byte[] signed = signature.bytes();
        try {
            if (signature.encoding() != Encoding.BINARY || signed.length == 0 || signed.length > 1_048_576) {
                throw new IllegalStateException("Invalid CRL signing result");
            }
            byte[] algorithm = HexFormat.of().parseHex(command.field(9));
            long signatureLength = Math.addExact(1L, signed.length);
            long bodyLength = Math.addExact(Math.addExact(tbs.length(), algorithm.length),
                    StreamingDerWriter.encodedLength(signatureLength));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (OutputStream output = new DigestOutputStream(OutputStream.nullOutputStream(), digest);
                    RepeatableContent content = store.stagedContent().openContent(tbs);
                    InputStream input = content.openStream()) {
                StreamingDerWriter.writeTagAndLength(output, 0x30, bodyLength);
                if (StreamingDerWriter.copy(input, output, CancellationSignal.NONE) != tbs.length()) {
                    throw new IllegalStateException("CRL TBS length differs");
                }
                output.write(algorithm);
                StreamingDerWriter.writeTagAndLength(output, 0x03, signatureLength);
                output.write(0); output.write(signed);
            }
            if (status.content().length() != StreamingDerWriter.encodedLength(bodyLength)
                    || !status.content().sha256().equals(HexFormat.of().formatHex(digest.digest()))) {
                throw new IllegalStateException("CRL differs from its accepted signing result");
            }
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        } finally { Arrays.fill(signed, (byte) 0); }
    }

    private static long nonnegative(String value) {
        long parsed = Long.parseLong(value);
        if (parsed < 0 || !Long.toString(parsed).equals(value)) {
            throw new IllegalStateException("Full CRL count or length is noncanonical");
        }
        return parsed;
    }
}
