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

package zeroecho.pki.application;

import java.util.Objects;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.status.StatusObjectType;

/**
 * Immutable closed signing-command inputs shared by server and local execution.
 *
 * <p>These inputs carry no authorization decision. The caller supplies its access
 * context and, when applicable, issuance evidence to {@link PkiSigningCommands}.
 * Preparation and durable acceptance remain separate operations.</p>
 */
public sealed interface PkiSigningOperation permits PkiSigningOperation.CreateAuthority, PkiSigningOperation.CreateIntermediate, PkiSigningOperation.IssueIntermediateCertificate, PkiSigningOperation.RolloverCaCertificate, PkiSigningOperation.RotateCaKey, PkiSigningOperation.IssueCredential, PkiSigningOperation.RenewCredential, PkiSigningOperation.ReplaceCredential, PkiSigningOperation.ReissueCredential, PkiSigningOperation.GenerateStatus {
    /** {@return the stable historical transport and approval identity} */
    String name();

    /**
     * Creates one root certificate authority using an existing managed key reference.
     *
     * @param formatId encoding format for the created or imported object
     * @param subjectRef subject name for the new authority
     * @param profileId nonblank stable certificate-profile identifier
     * @param keyRef managed key reference used by the authority
     */
    record CreateAuthority(FormatId formatId, SubjectRef subjectRef, String profileId, KeyRef keyRef)
            implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.create";

        /** Validates the closed authority-creation input. */
        public CreateAuthority {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(subjectRef, "subjectRef");
            Objects.requireNonNull(keyRef, "keyRef");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Creates one intermediate certificate authority and its initial CA credential.
     *
     * @param formatId encoding format for the created or imported object
     * @param issuerCaId issuing certificate-authority identifier
     * @param subjectRef subject name for the new authority
     * @param profileId nonblank stable certificate-profile identifier
     * @param keyRef optional existing managed key; a managed key must be present
     */
    record CreateIntermediate(FormatId formatId, PkiId issuerCaId, SubjectRef subjectRef, String profileId,
            java.util.Optional<KeyRef> keyRef) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.intermediate.create";

        /** Validates the closed intermediate-creation input. */
        public CreateIntermediate {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(subjectRef, "subjectRef");
            keyRef = Objects.requireNonNull(keyRef, "keyRef");
            if (keyRef.isEmpty()) { throw new IllegalArgumentException("A managed subject key is required"); }
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Issues a new CA credential for an existing intermediate authority (cross-sign or renewal).
     *
     * @param formatId encoding format for the created or imported object
     * @param issuerCaId issuing certificate-authority identifier
     * @param subjectCaId subject intermediate-authority identifier
     * @param profileId nonblank stable certificate-profile identifier
     * @param requestedValidity optional requested validity constrained by the profile and issuer
     */
    record IssueIntermediateCertificate(FormatId formatId, PkiId issuerCaId, PkiId subjectCaId, String profileId,
            java.util.Optional<Validity> requestedValidity) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.intermediate.issue";

        /** Validates the closed intermediate-issuance input. */
        public IssueIntermediateCertificate {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(subjectCaId, "subjectCaId");
            requestedValidity = Objects.requireNonNull(requestedValidity, "requestedValidity");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Rolls over one CA credential, keeping the same key and advancing the current issuance generation.
     *
     * @param caId exact certificate-authority identifier
     * @param issuerCaId optional issuing authority; empty selects the configured issuer
     */
    record RolloverCaCertificate(PkiId caId, java.util.Optional<PkiId> issuerCaId) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.rollover";

        /** Validates the rollover input. */
        public RolloverCaCertificate {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Rotates one CA key and issues a new corresponding generation, advancing the current issuance pointers.
     *
     * @param caId exact certificate-authority identifier
     * @param newKeyRef optional managed replacement key; a managed key must be present
     * @param issuerCaId optional issuing authority; empty selects the configured issuer
     */
    record RotateCaKey(PkiId caId, java.util.Optional<KeyRef> newKeyRef, java.util.Optional<PkiId> issuerCaId)
            implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.rotate";

        /** Validates the rotation input. */
        public RotateCaKey {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(newKeyRef, "newKeyRef");
            if (newKeyRef.isEmpty()) { throw new IllegalArgumentException("A managed replacement key is required"); }
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Issues one end-entity credential from an already imported request.
     *
     * @param issuerCaId issuing certificate-authority identifier
     * @param requestId exact imported certification-request identifier
     * @param profileId nonblank stable certificate-profile identifier
     */
    record IssueCredential(PkiId issuerCaId, PkiId requestId, String profileId) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.issue";

        /** Validates the issuance input. */
        public IssueCredential {
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(requestId, "requestId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Renews one end-entity credential, keeping its subject and key under a fresh validity.
     *
     * @param credentialId exact committed credential identifier
     */
    record RenewCredential(PkiId credentialId) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.renew";

        /** Validates the renewal input. */
        public RenewCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Replaces one end-entity credential from a new imported request and supersedes the predecessor.
     *
     * @param existingCredentialId exact credential that the replacement supersedes
     * @param requestId exact imported certification-request identifier
     * @param profileId nonblank stable certificate-profile identifier
     */
    record ReplaceCredential(PkiId existingCredentialId, PkiId requestId, String profileId) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.replace";

        /** Validates the replacement input. */
        public ReplaceCredential {
            Objects.requireNonNull(existingCredentialId, "existingCredentialId");
            Objects.requireNonNull(requestId, "requestId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reissues one end-entity credential from its stored issuance record and supersedes the predecessor.
     *
     * @param credentialId exact committed credential identifier
     */
    record ReissueCredential(PkiId credentialId) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.reissue";

        /** Validates the reissue input. */
        public ReissueCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Generates one signed status object from a stable revocation view.
     *
     * @param issuerCaId issuing certificate-authority identifier
     * @param type kind of status object to generate
     * @param formatId encoding format for the created or imported object
     */
    record GenerateStatus(PkiId issuerCaId, StatusObjectType type, FormatId formatId) implements PkiSigningOperation {
        /** Stable operation name. */
        public static final String NAME = "status.generate";

        /** Validates the generation input. */
        public GenerateStatus {
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(formatId, "formatId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    private static String profileIdRequiredMessage() { return "profileId must not be blank"; }
    private static String authorityIdParameter() { return "caId"; }
    private static String issuerAuthorityIdParameter() { return "issuerCaId"; }
}
