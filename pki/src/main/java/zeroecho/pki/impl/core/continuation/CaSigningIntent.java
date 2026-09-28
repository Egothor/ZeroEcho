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

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Pure, domain-separated commitment to an intermediate CA signing intent.
 * Fields 18 (proof reference) and 19 (proof command) are deliberately excluded,
 * so the intent can be frozen before its internal proof exists. All other fields
 * of the current 23-field schema, including attributes, subject SPKI digest and
 * final TBS length/hash, and the exact signature identity are committed in order.
 * No proof lookup, content read, staging, authorization or persistence occurs.
 * This helper does not change the live command or challenge serialization.
 */
public final class CaSigningIntent {
    private static final String DOMAIN = "zeroecho.ca-signing-intent:v1";
    private static final String PREFIX = "ca-intent:v1:";
    private static final int FIELD_COUNT = 21;

    private CaSigningIntent() { }

    /**
     * Validates and commits the nonproof portion of a prospective command.
     * Proof fields may be empty; their values are neither interpreted nor hashed.
     * This is not complete-command validation or signing authorization. Algorithm
     * policy, provider authority and exact TBS/SPKI bytes are checked by the later
     * preparation/admission boundary. Length framing uses big-endian 32-bit byte
     * lengths and strict UTF-8; aggregate framed input is bounded to 1 MiB.
     *
     * @param command exact supported intermediate discriminator and 23 fields
     * @param signatureAlgorithm exact selected signature identity
     * @return canonical versioned SHA-256 commitment
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if nonproof structure, canonical values or bounds are invalid
     * @implNote Work is O(B + A² + A log A) and auxiliary memory is O(B + A),
     * where B is bounded nonproof metadata and A is the attribute count. Hashing
     * streams one field at a time; attribute decoding retains its existing costs.
     */
    public static String commitment(DomainCommandEncoding.Decoded command, AlgorithmIdentity signatureAlgorithm) {
        Objects.requireNonNull(command, "command").requireFields(23);
        Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        if (!IntermediateSigningCommand.supports(command.operation())
                || signatureAlgorithm.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw invalid();
        }
        return commitmentOfCanonicalAlgorithm(command, signatureAlgorithm.canonicalForm());
    }

    /**
     * Recomputes accepted intent from exact stored algorithm text without resolving
     * installed codecs. This is equality validation, never signing authorization;
     * the selected authority must establish canonical signature semantics.
     * @param command exact supported intermediate command
     * @param algorithm exact bounded nonblank canonical algorithm text
     * @return the same commitment as the typed entry for identical text
     */
    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    public static String commitmentOfCanonicalAlgorithm(DomainCommandEncoding.Decoded command, String algorithm) {
        Objects.requireNonNull(command, "command").requireFields(23);
        if (!IntermediateSigningCommand.supports(command.operation()) || Objects.requireNonNull(algorithm, "algorithm").isBlank()) {
            throw invalid();
        }
        long size = 4L + DOMAIN.length() + 4L + command.operation().length() + 4L
                + ManagedKeyProofCommand.utf8Length(algorithm, 8192) + 4L;
        for (int index = 0; index < command.fields().size(); index++) {
            if (isProofField(index)) { continue; }
            size += 4L + ManagedKeyProofCommand.utf8Length(command.field(index), ManagedKeyProofCommand.MAX_COMMAND_BYTES);
            if (size > ManagedKeyProofCommand.MAX_COMMAND_BYTES) { throw invalid(); }
        }
        try {
            validateFields(command);
        } catch (java.time.DateTimeException malformed) {
            throw invalid();
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (DataOutputStream output = new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(), digest))) {
                field(output, DOMAIN);
                field(output, command.operation());
                field(output, algorithm);
                output.writeInt(FIELD_COUNT);
                for (int index = 0; index < command.fields().size(); index++) {
                    if (!isProofField(index)) { field(output, command.field(index)); }
                }
            }
            return PREFIX + HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory CA intent commitment failed", impossible);
        }
    }

    // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
    @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
    private static void validateFields(DomainCommandEncoding.Decoded command) {
        new FormatId(command.field(0));
        ManagedKeyProofCommand.utf8Length(command.field(1), 4096);
        ManagedKeyProofCommand.utf8Length(command.field(2), 4096);
        ManagedKeyProofCommand.utf8Length(command.field(7), 256);
        for (int index = 1; index <= 4; index++) { new PkiId(command.field(index)); }
        ManagedKeyProofCommand.hex(command.field(5), 32, 32);
        new KeyRef(command.field(6));
        long version = Long.parseLong(command.field(8));
        if (!Long.toString(version).equals(command.field(8))) { throw invalid(); }
        new CertificateProfileRef(command.field(7), version, ManagedKeyProofCommand.hex(command.field(9), 32, 32));
        new SubjectRef(command.field(10));
        for (int index = 11; index <= 12; index++) {
            if (!Instant.parse(command.field(index)).toString().equals(command.field(index))) { throw invalid(); }
        }
        if (!new BigInteger(command.field(13)).toString().equals(command.field(13))) { throw invalid(); }
        new KeyRef(command.field(14));
        if (IntermediateSigningCommand.CREATE.equals(command.operation()) && command.field(6).equals(command.field(14))) {
            throw invalid();
        }
        ManagedKeyProofCommand.hex(command.field(16), 32, 32);
        ManagedKeyProofCommand.hex(command.field(17), 32, 32);
        DomainAttributeEncoding.decode(command.field(20));
        ManagedKeyProofCommand.positiveLength(command.field(21), 1_048_576);
        ManagedKeyProofCommand.hex(command.field(22), 32, 32);
    }

    private static boolean isProofField(int index) { return index == 18 || index == 19; }
    private static void field(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("CA signing intent is invalid");
    }
}
