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

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.spi.store.DomainContinuationStore;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Retains the exact outgoing CA signer evidence captured before certificate signing.
 *
 * <p>The descriptor carries managed key references, public-key commitments and
 * algorithm identities, not private key material. It does not create a generation or
 * credential identity before publication, resolve a key, or authorize its use.
 * The complete encoding includes the primary reference; the subject-bound encoding
 * obtains that reference from its independently committed enclosing command.
 *
 * @param primary exact outgoing primary signer binding; must not be {@code null}
 * @param alternative exact outgoing alternative binding, or an empty optional;
 *        the optional must not be {@code null}
 * @param authorityCommitment captured installed X.509 binding-registry commitment
 *        as 64 lowercase hexadecimal characters
 */
public record CaOutgoingBinding(IssuerKeyBinding primary, Optional<IssuerKeyBinding> alternative,
        String authorityCommitment) {
    private static final int MAXIMUM_ENCODED_TEXT = 1_398_104;

    /**
     * Requires the signer evidence and canonical registry commitment.
     *
     * <p>This structural check does not establish that managed key bytes still match
     * the retained evidence or that the registry authorizes a particular operation.
     *
     * @throws NullPointerException if the primary binding or alternative optional is null
     * @throws IllegalArgumentException if the registry commitment is null or malformed
     * @param primary exact outgoing primary signer binding; must not be {@code null}
     * @param alternative exact outgoing alternative binding, or an empty optional; the optional must not be {@code null}
     * @param authorityCommitment captured installed X.509 binding-registry commitment as 64 lowercase hexadecimal characters
     */
    public CaOutgoingBinding {
        Objects.requireNonNull(primary);
        Objects.requireNonNull(alternative);
        if (authorityCommitment == null || !authorityCommitment.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid CA authority commitment");
        }
    }
    /**
     * Encodes the complete outgoing evidence, including the primary key reference.
     *
     * <p>The version-one domain command uses canonical unpadded Base64url. It contains
     * only public metadata and does not acquire or serialize managed private keys.
     *
     * @return the complete {@code CA_OUTGOING_BINDING_V1} descriptor
     * @throws IllegalArgumentException if the encoded domain command exceeds its bounds
     */
    public String encode() {
        List<String> fields = new ArrayList<>();
        append(fields, primary);
        fields.add(alternative.isPresent() ? "1" : "0");
        alternative.ifPresent(value -> append(fields, value));
        fields.add(authorityCommitment);
        EncodedObject command = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                "CA_OUTGOING_BINDING_V1", fields.toArray(String[]::new)).command();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(command.bytes());
    }
    /**
     * Encodes exact outgoing evidence without duplicating the enclosing command's primary key reference.
     *
     * <p>The caller must retain the primary reference as a separately committed
     * enclosing-command field. This descriptor alone cannot identify that reference.
     *
     * @return context-bound v1 descriptor; decode requires the independently committed subject reference
     * @throws IllegalArgumentException if the encoded domain command exceeds its bounds
     */
    public String encodeForSubject() {
        List<String> fields = new ArrayList<>();
        append(fields, primary);
        fields.removeFirst();
        fields.add(alternative.isPresent() ? "1" : "0");
        alternative.ifPresent(value -> append(fields, value));
        fields.add(authorityCommitment);
        byte[] encoded = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                "CA_OUTGOING_SUBJECT_V1", fields.toArray(String[]::new)).command().bytes();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
    }
    /**
     * Reconstructs evidence using the enclosing command's already committed primary reference.
     *
     * <p>Only canonical unpadded Base64url and the subject-bound version-one schema
     * are accepted. The supplied reference is incorporated into the result; this
     * operation does not independently authenticate the enclosing command.
     *
     * @param text canonical context-bound descriptor, at most 1,398,104 characters
     * @param primaryReference exact subject key reference from the enclosing command;
     *        must not be {@code null}
     * @return complete immutable outgoing evidence using the supplied primary reference
     * @throws NullPointerException if the primary reference is null
     * @throws IllegalArgumentException if text is null, oversized, malformed,
     *         noncanonical or uses an unsupported schema or role representation
     */
    public static CaOutgoingBinding decodeForSubject(String text, KeyRef primaryReference) {
        if (text == null || text.length() > MAXIMUM_ENCODED_TEXT) {
            throw new IllegalArgumentException("Invalid CA binding size");
        }
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text)) {
            throw new IllegalArgumentException("Noncanonical CA binding");
        }
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes));
        if (!"CA_OUTGOING_SUBJECT_V1".equals(command.operation())) {
            throw new IllegalArgumentException("Unknown CA binding schema");
        }
        boolean alternative = switch (command.field(4)) {
            case "0" -> false;
            case "1" -> true;
            default -> throw new IllegalArgumentException("Unknown alternative discriminator");
        };
        command.requireFields(alternative ? 11 : 6);
        List<String> fields = new ArrayList<>();
        fields.add(primaryReference.value());
        fields.addAll(command.fields());
        DomainCommandEncoding.Decoded expanded =
                new DomainCommandEncoding.Decoded("CA_OUTGOING_BINDING_V1", fields);
        return new CaOutgoingBinding(key(expanded, 0), alternative ? Optional.of(key(expanded, 6)) : Optional.empty(),
                expanded.field(alternative ? 11 : 6));
    }

    /**
     * Decodes complete bounded frozen evidence without consulting mutable defaults.
     *
     * <p>No provider, mutable default or private key is consulted. Successful decoding
     * establishes the descriptor's structure, not current key eligibility or signing authority.
     *
     * @param text canonical unpadded Base64url encoding, at most 1,398,104 characters
     * @return exact frozen outgoing key evidence
     * @throws IllegalArgumentException for malformed, oversized or noncanonical input
     */
    public static CaOutgoingBinding decode(String text) {
        if (text == null || text.length() > MAXIMUM_ENCODED_TEXT) {
            throw new IllegalArgumentException("Invalid CA binding size");
        }
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text)) {
            throw new IllegalArgumentException("Noncanonical CA binding");
        }
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes));
        if (!"CA_OUTGOING_BINDING_V1".equals(command.operation())) {
            throw new IllegalArgumentException("Unknown CA binding schema");
        }
        boolean alternative = switch (command.field(5)) {
            case "0" -> false;
            case "1" -> true;
            default -> throw new IllegalArgumentException("Unknown alternative discriminator");
        };
        command.requireFields(alternative ? 12 : 7);
        return new CaOutgoingBinding(key(command, 0), alternative ? Optional.of(key(command, 6)) : Optional.empty(),
                command.field(alternative ? 11 : 6));
    }
    private static void append(List<String> fields, IssuerKeyBinding key) {
        fields.add(key.keyRef().value());
        fields.add(key.publicKeyAlgorithm().canonicalForm());
        fields.add(key.signatureAlgorithm().canonicalForm());
        fields.add(HexFormat.of().formatHex(key.signatureAlgorithmIdentifier().bytes()));
        fields.add(key.subjectSpkiSha256());
    }
    private static IssuerKeyBinding key(DomainCommandEncoding.Decoded command, int offset) {
        return new IssuerKeyBinding(new KeyRef(command.field(offset)), AlgorithmIdentity.parse(command.field(offset + 1), List.of()),
                AlgorithmIdentity.parse(command.field(offset + 2), List.of()),
                new EncodedObject(Encoding.DER, HexFormat.of().parseHex(command.field(offset + 3))), command.field(offset + 4));
    }
}
