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

import java.util.*;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.spi.store.DomainContinuationStore;

/**
 * Exact versioned outgoing CA key evidence retained before certificate signing.
 * No CA generation or credential identity is invented before publication.
 * @param primary exact outgoing primary key binding
 * @param alternative optional exact outgoing alternative key binding
 * @param authorityCommitment captured exact installed X.509 registry commitment
 */
public record CaOutgoingBinding(IssuerKeyBinding primary, Optional<IssuerKeyBinding> alternative,
        String authorityCommitment) {
    private static final int MAXIMUM_ENCODED_TEXT = 1_398_104;

    /** Rejects missing evidence; all values are immutable public metadata. */
    public CaOutgoingBinding {
        Objects.requireNonNull(primary); Objects.requireNonNull(alternative);
        if (authorityCommitment == null || !authorityCommitment.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid CA authority commitment");
        }
    }
    /** @return strict Base64url v1 domain encoding, with no private key bytes */
    public String encode() {
        var fields = new ArrayList<String>(); append(fields, primary);
        fields.add(alternative.isPresent() ? "1" : "0"); alternative.ifPresent(value -> append(fields, value));
        fields.add(authorityCommitment);
        var command = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                "CA_OUTGOING_BINDING_V1", fields.toArray(String[]::new)).command();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(command.bytes());
    }
    /**
     * Encodes exact outgoing evidence without duplicating the enclosing command's primary key reference.
     * @return context-bound v1 descriptor; decode requires the independently committed subject reference
     */
    public String encodeForSubject() {
        var fields = new ArrayList<String>(); append(fields, primary); fields.removeFirst();
        fields.add(alternative.isPresent() ? "1" : "0"); alternative.ifPresent(value -> append(fields, value));
        fields.add(authorityCommitment);
        byte[] encoded = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                "CA_OUTGOING_SUBJECT_V1", fields.toArray(String[]::new)).command().bytes();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
    }
    /**
     * Reconstructs evidence using the enclosing command's already committed primary reference.
     * @param text bounded canonical context-bound descriptor
     * @param primaryReference exact subject key reference from the enclosing command
     * @return complete outgoing evidence; changing the context changes its primary binding
     * @throws IllegalArgumentException for a malformed descriptor or wrong schema
     */
    public static CaOutgoingBinding decodeForSubject(String text, KeyRef primaryReference) {
        if (text == null || text.length() > MAXIMUM_ENCODED_TEXT) throw new IllegalArgumentException("Invalid CA binding size");
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text)) throw new IllegalArgumentException("Noncanonical CA binding");
        var command = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes));
        if (!command.operation().equals("CA_OUTGOING_SUBJECT_V1")) throw new IllegalArgumentException("Unknown CA binding schema");
        boolean alternative = switch (command.field(4)) {
            case "0" -> false; case "1" -> true; default -> throw new IllegalArgumentException("Unknown alternative discriminator");
        };
        command.requireFields(alternative ? 11 : 6);
        var fields = new ArrayList<String>(); fields.add(primaryReference.value()); fields.addAll(command.fields());
        var expanded = new DomainCommandEncoding.Decoded("CA_OUTGOING_BINDING_V1", fields);
        return new CaOutgoingBinding(key(expanded, 0), alternative ? Optional.of(key(expanded, 6)) : Optional.empty(),
                expanded.field(alternative ? 11 : 6));
    }

    /**
     * Decodes complete bounded frozen evidence without consulting mutable defaults.
     * @param text canonical Base64url encoding
     * @return exact frozen outgoing key evidence
     * @throws IllegalArgumentException for malformed, oversized or noncanonical input
     */
    public static CaOutgoingBinding decode(String text) {
        if (text == null || text.length() > MAXIMUM_ENCODED_TEXT) throw new IllegalArgumentException("Invalid CA binding size");
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text)) throw new IllegalArgumentException("Noncanonical CA binding");
        var command = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes));
        if (!command.operation().equals("CA_OUTGOING_BINDING_V1")) throw new IllegalArgumentException("Unknown CA binding schema");
        boolean alternative = switch (command.field(5)) {
            case "0" -> false; case "1" -> true; default -> throw new IllegalArgumentException("Unknown alternative discriminator");
        };
        command.requireFields(alternative ? 12 : 7);
        return new CaOutgoingBinding(key(command, 0), alternative ? Optional.of(key(command, 6)) : Optional.empty(),
                command.field(alternative ? 11 : 6));
    }
    private static void append(List<String> fields, IssuerKeyBinding key) {
        fields.add(key.keyRef().value()); fields.add(key.publicKeyAlgorithm().canonicalForm());
        fields.add(key.signatureAlgorithm().canonicalForm());
        fields.add(HexFormat.of().formatHex(key.signatureAlgorithmIdentifier().bytes())); fields.add(key.subjectSpkiSha256());
    }
    private static IssuerKeyBinding key(DomainCommandEncoding.Decoded command, int offset) {
        return new IssuerKeyBinding(new KeyRef(command.field(offset)), AlgorithmIdentity.parse(command.field(offset + 1), List.of()),
                AlgorithmIdentity.parse(command.field(offset + 2), List.of()),
                new EncodedObject(Encoding.DER, HexFormat.of().parseHex(command.field(offset + 3))), command.field(offset + 4));
    }
}
