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

import java.io.IOException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.signing.ManagedKeyProofPurpose;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.ManagedKeyProofScope;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningScope;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pkix.Pkix;

/**
 * Frozen managed-key proof authorization prefix. Fields 0 through 5 are purpose,
 * authority ID, subject-authority ID, profile ID, responder-credential ID and key
 * reference, respectively. Empty strings encode inapplicable optional coordinates.
 * Fields 6 through 13 freeze namespace, configuration SHA-256, canonical signature
 * identity, exact AlgorithmIdentifier DER hex, SPKI length and SHA-256, and challenge
 * length and SHA-256. Complete-schema validation does not itself accept an
 * operation, verify a proof or perform caller authorization.
 * Structural validation is linear in bounded command text; prefix validation uses
 * constant auxiliary memory and complete validation uses bounded algorithm-DER
 * workspace. Installed algorithm semantics require a separate authority check.
 */
public final class ManagedKeyProofCommand {
    private static final int MAX_INT_DIGITS = 10;
    private static final int UTF8_TWO_BYTE_START = 0x80;
    private static final int UTF8_THREE_BYTE_START = 0x800;
    /** Single discriminator for both managed key proof purposes. */
    public static final String OPERATION = "PROVE_MANAGED_KEY";
    /** Inclusive aggregate encoded command bound, in bytes. */
    public static final int MAX_COMMAND_BYTES = 1_048_576;
    /** Inclusive canonical SubjectPublicKeyInfo bound, in bytes. */
    public static final int MAX_SPKI_BYTES = 1_048_576;
    /** Inclusive complete challenge bound, in bytes. */
    public static final int MAX_CHALLENGE_BYTES = MAX_COMMAND_BYTES + MAX_SPKI_BYTES + 8192;
    /** Inclusive AlgorithmIdentifier DER bound, in bytes. */
    public static final int MAX_ALGORITHM_DER_BYTES = 16_384;

    private ManagedKeyProofCommand() { }

    /**
     * Returns the six frozen prefix fields without encoding or staging content.
     * @param request bounded immutable proof coordinates
     * @return immutable ordered prefix; this is not a complete admissible command
     * @throws NullPointerException if the request is null
     */
    public static List<String> prefix(ManagedKeyProofRequest request) {
        return switch (Objects.requireNonNull(request, "request")) {
            case ManagedKeyProofRequest.CaSubject ca -> List.of(ManagedKeyProofPurpose.CA_SUBJECT_KEY.name(),
                    ca.issuerAuthorityId().value(), ca.subjectAuthorityId().map(PkiId::value).orElse(""),
                    ca.profileId(), "", ca.keyRef().value());
            case ManagedKeyProofRequest.OcspResponder responder -> List.of(ManagedKeyProofPurpose.OCSP_RESPONDER_KEY.name(),
                    responder.authorityId().value(), "", "", responder.responderCredentialId().value(),
                    responder.keyRef().value());
        };
    }

    /**
     * Validates only fields 0 through 5 and the proof discriminator.
     * Any suffix remains subject to complete-command validation; a valid
     * prefix alone must never be treated as proof preparation or acceptance.
     * @param command decoded internal command containing at least six fields
     * @return immutable bounded request reconstructed from the exact prefix
     * @throws NullPointerException if the command is null
     * @throws IllegalArgumentException if the discriminator, bounds or closed combination is invalid
     */
    public static ManagedKeyProofRequest decodePrefix(DomainCommandEncoding.Decoded command) {
        Objects.requireNonNull(command, "command");
        if (!OPERATION.equals(command.operation())) {
            throw invalid();
        }
        String purpose = command.field(0);
        if (ManagedKeyProofPurpose.CA_SUBJECT_KEY.name().equals(purpose)) {
            if (!command.field(4).isEmpty()) { throw invalid(); }
            return new ManagedKeyProofRequest.CaSubject(new PkiId(command.field(1)),
                    command.field(2).isEmpty() ? Optional.empty() : Optional.of(new PkiId(command.field(2))),
                    command.field(3), new KeyRef(command.field(5)));
        }
        if (ManagedKeyProofPurpose.OCSP_RESPONDER_KEY.name().equals(purpose)) {
            if (!command.field(2).isEmpty() || !command.field(3).isEmpty()) { throw invalid(); }
            return new ManagedKeyProofRequest.OcspResponder(new PkiId(command.field(1)),
                    new PkiId(command.field(4)), new KeyRef(command.field(5)));
        }
        throw invalid();
    }

    /**
     * Maps a validated prefix to disclosure scope using the retained envelope actor
     * and exact signing key. Performs no lookup and grants no operation authority.
     * @param command decoded internal proof prefix
     * @param access trusted or retained envelope access context
     * @param key exact envelope key, which must match prefix field 5
     * @return immutable proof scope
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if the prefix is invalid or the envelope key differs
     */
    public static SemanticSigningScope scope(DomainCommandEncoding.Decoded command, AccessContext access, KeyRef key) {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(key, "key");
        ManagedKeyProofRequest request = decodePrefix(command);
        if (!key.equals(request.keyRef())) { throw invalid(); }
        return switch (request) {
            case ManagedKeyProofRequest.CaSubject ca -> new SemanticSigningScope(SemanticSigningKind.KEY_PROOF,
                    OPERATION, access, key, Optional.of(ca.issuerAuthorityId()), ca.subjectAuthorityId(),
                    Optional.of(ca.profileId()), Optional.of(new ManagedKeyProofScope(
                            ManagedKeyProofPurpose.CA_SUBJECT_KEY, Optional.empty())));
            case ManagedKeyProofRequest.OcspResponder responder -> new SemanticSigningScope(SemanticSigningKind.KEY_PROOF,
                    OPERATION, access, key, Optional.of(responder.authorityId()), Optional.empty(), Optional.empty(),
                    Optional.of(new ManagedKeyProofScope(ManagedKeyProofPurpose.OCSP_RESPONDER_KEY,
                            Optional.of(responder.responderCredentialId()))));
        };
    }

    /**
     * Returns the exact request authority for separate trusted scheduling metadata.
     * This coordinate grants no authorization and performs no lookup.
     * @param request bounded request
     * @return logical CA authority, never the responder or subject authority
     */
    public static PkiId authorityId(ManagedKeyProofRequest request) {
        return switch (Objects.requireNonNull(request, "request")) {
            case ManagedKeyProofRequest.CaSubject ca -> ca.issuerAuthorityId();
            case ManagedKeyProofRequest.OcspResponder responder -> responder.authorityId();
        };
    }

    /**
     * Validates the complete 14-field internal preparation schema and aggregate
     * encoded size before command allocation. Admission additionally requires exact
     * envelope and live challenge bindings.
     * Algorithm identity text is bounded and nonblank here; its installed canonical
     * semantics are checked separately by {@link #validateAlgorithm}.
     * @param command exact decoded command
     * @throws IllegalArgumentException if schema, canonical values or bounds differ
     */
    public static void validateComplete(DomainCommandEncoding.Decoded command) {
        command.requireFields(14);
        validateMetadata(command);
        positiveLength(command.field(10), MAX_SPKI_BYTES);
        hex(command.field(11), 32, 32);
        positiveLength(command.field(12), MAX_CHALLENGE_BYTES);
        hex(command.field(13), 32, 32);
        long size = 5L + 4L + OPERATION.length() + 4L;
        for (String field : command.fields()) {
            size += 4L + utf8Length(field, MAX_COMMAND_BYTES);
            if (size > MAX_COMMAND_BYTES) { throw invalid(); }
        }
    }

    /* default */ static void validateMetadata(DomainCommandEncoding.Decoded command) {
        decodePrefix(command);
        String namespace = command.field(6);
        if (!namespace.matches("[a-z0-9._-]{1,128}")) { throw invalid(); }
        hex(command.field(7), 32, 32);
        String canonical = command.field(8);
        utf8Length(canonical, 8192);
        if (canonical.isBlank()) { throw invalid(); }
        byte[] algorithm = hex(command.field(9), 1, MAX_ALGORITHM_DER_BYTES);
        try {
            new StreamingDerReader().validate(algorithm, MAX_ALGORITHM_DER_BYTES);
            zeroecho.pkix.AlgorithmIdentifier identifier = Pkix.parseAlgorithmIdentifier(algorithm);
            if (!java.util.Arrays.equals(algorithm, Pkix.encodeAlgorithmIdentifier(identifier))) {
                throw invalid();
            }
        } catch (IOException malformed) {
            throw new IllegalArgumentException("Managed key proof algorithm encoding is invalid", malformed);
        }
    }

    /**
     * Resolves signature semantics separately from configuration-independent durable
     * structure validation. Extension identities use the supplied installed codecs;
     * aliases and DER bound to another identity are rejected. Preparation additionally
     * requires exact DER agreement between the selected SIGN and VERIFY plans.
     * @param command structurally validated metadata or complete command
     * @param authority selected immutable identity and binding authority
     * @return exact canonical signature identity
     */
    public static AlgorithmIdentity validateAlgorithm(DomainCommandEncoding.Decoded command,
            X509AuthoritySnapshot authority) {
        validateMetadata(command);
        String canonical = command.field(8);
        AlgorithmIdentity identity = Objects.requireNonNull(authority, "authority").resolveIdentity(canonical);
        if (!identity.canonicalForm().equals(canonical) || identity.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw invalid();
        }
        X509SecurityFloor.requirePermitted(identity);
        byte[] algorithm = hex(command.field(9), 1, MAX_ALGORITHM_DER_BYTES);
        if (!identity.equals(new BcX509AlgorithmAdapter(authority.bindings()).decode(
                Pkix.parseAlgorithmIdentifier(algorithm), X509AlgorithmRole.SIGNATURE_ALGORITHM))) {
            throw invalid();
        }
        return identity;
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static int positiveLength(String value, int maximum) {
        if (value.length() > MAX_INT_DIGITS) { throw invalid(); }
        try {
            int length = Integer.parseInt(value);
            if (length <= 0 || length > maximum || !Integer.toString(length).equals(value)) { throw invalid(); }
            return length;
        } catch (NumberFormatException malformed) {
            throw invalid();
        }
    }

    /* default */ static byte[] hex(String value, int minimum, int maximum) {
        if (value.length() < 2L * minimum || value.length() > 2L * maximum || (value.length() & 1) != 0) {
            throw invalid();
        }
        int index = 0;
        while (index < value.length()) {
            char character = value.charAt(index);
            if (!(character >= '0' && character <= '9' || character >= 'a' && character <= 'f')) { throw invalid(); }
            index++;
        }
        return HexFormat.of().parseHex(value);
    }

    /* default */ static int utf8Length(String value, int maximum) {
        Objects.requireNonNull(value, "value");
        if (value.length() > maximum) { throw invalid(); }
        int bytes = 0;
        int index = 0;
        while (index < value.length()) {
            char character = value.charAt(index);
            if (character < UTF8_TWO_BYTE_START) { bytes++; }
            else if (character < UTF8_THREE_BYTE_START) { bytes += 2; }
            else if (Character.isHighSurrogate(character)) {
                if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index))) { throw invalid(); }
                bytes += 4;
            } else {
                if (Character.isLowSurrogate(character)) { throw invalid(); }
                bytes += 3;
            }
            if (bytes > maximum) { throw invalid(); }
            index++;
        }
        return bytes;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Managed key proof command prefix is invalid");
    }
}
