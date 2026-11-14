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
package zeroecho.pki.spi.framework;

import zeroecho.pki.api.FormatId;
import java.util.Objects;
import java.util.Optional;

/**
 * Pluggable credential framework implementation.
 *
 * <p>
 * A framework implementation provides request parsing, proof-of-possession
 * verification and status object generation for a particular {@link FormatId}.
 * Credential minting is intentionally not exposed by this framework facade;
 * core issuance services own that privileged implementation boundary.
 * </p>
 */
public interface CredentialFramework {

    /**
     * Returns the format id supported by this framework.
     *
     * @return format id
     */
    FormatId formatId();

    /**
     * Returns the format's safe user-facing name.
     * @return nonblank format name, without provider secrets
     */
    default String displayName() { return formatId().value(); }

    /**
     * Returns format-owned subject input guidance. A generic framework imposes
     * no distinguished-name grammar; a format can advertise its own bounded hint.
     * @return immutable non-secret subject input metadata
     */
    default SubjectInput subjectInput() { return SubjectInput.generic(); }

    /**
     * Safe format-owned subject guidance, independent of a particular UI toolkit.
     * The optional pattern is an anchored Java/ECMAScript-compatible input hint,
     * not a replacement for authoritative format and certificate-profile checks.
     * @param label field label, at most 128 characters
     * @param help usage explanation, at most 2048 characters
     * @param placeholder format-specific example, at most 512 characters
     * @param pattern optional coarse syntax hint, at most 1024 characters
     */
    record SubjectInput(String label, String help, String placeholder, Optional<String> pattern) {
        /** Validates finite metadata and retains no provider instance. */
        public SubjectInput {
            Objects.requireNonNull(label, "label");
            Objects.requireNonNull(help, "help");
            Objects.requireNonNull(placeholder, "placeholder");
            Objects.requireNonNull(pattern, "pattern");
            if (label.isBlank() || label.length() > 128 || help.length() > 2048 || placeholder.length() > 512
                    || pattern.filter(value -> value.isBlank() || value.length() > 1024).isPresent()) {
                throw new IllegalArgumentException("Subject input metadata is empty or exceeds its bound");
            }
        }

        /**
         * Returns neutral guidance for opaque subjects with no DN restriction.
         * @return generic subject metadata with no syntax pattern
         */
        public static SubjectInput generic() {
            return new SubjectInput("Subject reference", "Value interpreted by the selected credential format.", "", Optional.empty());
        }
    }

    /**
     * Advertises safe certificate-content representations owned by this format.
     * Generic formats support exact original bytes without assuming a text grammar.
     * @param storedEncoding authoritative native content encoding
     * @return immutable supported representations, including original bytes
     */
    default java.util.List<CredentialRepresentation> credentialRepresentations(zeroecho.pki.api.Encoding storedEncoding) {
        return java.util.List.of(CredentialRepresentation.original(storedEncoding));
    }

    /**
     * Validates and exports bounded public credential content without key or signing access.
     * The caller authorizes retrieval and enforces input/output byte budgets separately.
     * @param stored immutable original encoded public content
     * @param representation exact advertised representation identity
     * @param cancellation cooperative cancellation
     * @return exact original or format-owned converted public content
     * @throws java.io.IOException if validation, conversion or cancellation fails
     * @throws UnsupportedOperationException if the representation is unsupported
     */
    default zeroecho.pki.api.EncodedObject exportCredential(zeroecho.pki.api.EncodedObject stored,
            String representation, zeroecho.core.io.CancellationSignal cancellation) throws java.io.IOException {
        Objects.requireNonNull(stored, "stored");
        Objects.requireNonNull(representation, "representation");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        if (!"original".equals(representation)) throw new UnsupportedOperationException("Unsupported credential representation");
        return stored;
    }

    /**
     * Finite non-secret display and transport metadata for one content representation.
     * @param id stable lower-case representation identity
     * @param label user-facing representation label
     * @param mediaType safe MIME type without parameters
     * @param fileExtension safe filename extension without a dot
     * @param encoding exact representation encoding
     */
    record CredentialRepresentation(String id, String label, String mediaType, String fileExtension,
            zeroecho.pki.api.Encoding encoding) {
        /** Validates all metadata before it can reach UI or HTTP headers. */
        public CredentialRepresentation {
            Objects.requireNonNull(id, "id"); Objects.requireNonNull(label, "label");
            Objects.requireNonNull(mediaType, "mediaType"); Objects.requireNonNull(fileExtension, "fileExtension");
            Objects.requireNonNull(encoding, "encoding");
            if (!id.matches("[a-z][a-z0-9-]{0,31}") || label.isBlank() || label.length() > 128
                    || !mediaType.matches("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+") || mediaType.length() > 128
                    || !fileExtension.matches("[a-z0-9]{1,16}")) throw new IllegalArgumentException("Invalid credential representation metadata");
        }
        /**
         * Returns neutral transport metadata for native public bytes.
         * @param encoding exact stored encoding
         * @return original-byte representation without format assumptions
         */
        public static CredentialRepresentation original(zeroecho.pki.api.Encoding encoding) {
            return new CredentialRepresentation("original", "Original", "application/octet-stream", "bin", encoding);
        }
    }

    /**
     * Returns the request parser for this framework.
     *
     * @return request parser
     */
    CertificationRequestParser requestParser();

    /**
     * Returns the proof-of-possession verifier for this framework.
     *
     * @return PoP verifier
     */
    ProofOfPossessionVerifier proofOfPossessionVerifier();

    /**
     * Returns format-owned status representations without opening content.
     * @param type exact stored status kind
     * @param storedEncoding native stored encoding
     * @return immutable metadata; generic formats expose original bytes only
     */
    default java.util.List<CredentialRepresentation> statusRepresentations(zeroecho.pki.api.status.StatusObjectType type,
            zeroecho.pki.api.Encoding storedEncoding) {
        java.util.Objects.requireNonNull(type,"type");return java.util.List.of(CredentialRepresentation.original(storedEncoding));
    }

    /**
     * Exposes a repeatable format representation without materializing the full status object.
     * Ownership of the source transfers to the returned content on success; on failure the caller retains it.
     * @param type exact stored status kind
     * @param storedEncoding native encoding
     * @param content immutable source with exact finite length
     * @param representation one advertised identifier
     * @param cancellation cooperative streaming cancellation
     * @return content owning the source, with an exact output length
     * @throws java.io.IOException if format validation or cancellation fails
     * @throws UnsupportedOperationException if the representation is unsupported
     */
    default zeroecho.core.io.RepeatableContent exportStatusContent(zeroecho.pki.api.status.StatusObjectType type,
            zeroecho.pki.api.Encoding storedEncoding,zeroecho.core.io.RepeatableContent content,String representation,
            zeroecho.core.io.CancellationSignal cancellation)throws java.io.IOException {
        java.util.Objects.requireNonNull(cancellation,"cancellation").throwIfCancelled();
        if(!"original".equals(representation))throw new UnsupportedOperationException("Status representation unavailable");return content;
    }

    /**
     * Returns the status object generator for this framework.
     *
     * @return status object generator
     */
    StatusObjectGenerator statusObjectGenerator();

    /**
     * Returns the framework attribute mapper.
     *
     * @return mapper
     */
    FrameworkAttributeMapper attributeMapper();
}
