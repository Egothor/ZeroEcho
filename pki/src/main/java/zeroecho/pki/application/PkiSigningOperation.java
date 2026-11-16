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
public sealed interface PkiSigningOperation permits PkiSigningOperation.CreateAuthority, PkiSigningOperation.CreateIntermediate, PkiSigningOperation.IssueIntermediateCertificate, PkiSigningOperation.RolloverCaCertificate, PkiSigningOperation.RotateCaKey, PkiSigningOperation.IssueCredential, PkiSigningOperation.RenewCredential, PkiSigningOperation.ReplaceCredential, PkiSigningOperation.ReissueCredential, PkiSigningOperation.GenerateStatus, PkiSigningOperation.IssueOcspResponderCertificate {
    /**
     * Returns the stable historical transport and approval identity.
     *
     * @return the stable historical transport and approval identity
     */
    String name();

    /**
     * Requests controlled issuance for an existing managed dedicated responder key pair.
     * This selector grants no authority; server dispatch requires a retained canonical provisioning claim.
     *
     * @param request exact managed subject, profile, generation, path and validity selection
     */
    record IssueOcspResponderCertificate(zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request)
            implements PkiSigningOperation {
        /**
         * Stable provisioning operation identity.
         */
        public static final String NAME = "ocsp.responder.issue-certificate";
        /**
         * Requires the managed request without resolving keys, claiming a provisioning slot or issuing a
         * certificate.
         *
         * @param request exact managed subject, profile, generation, path and validity selection
         * @throws NullPointerException if a required object is null
         */
        public IssueOcspResponderCertificate {
            Objects.requireNonNull(request, "request");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Creates one root certificate authority using an existing managed key reference.
     *
     * @param formatId encoding format for the created or imported object
     * @param subjectRef subject name for the new authority
     * @param profileId nonblank stable certificate-profile identifier
     * @param keyRef managed key reference used by the authority
     * @param signatureAlgorithmId exact outgoing primary signature identity; empty selects the configured
     *     creation default
     */
    record CreateAuthority(FormatId formatId, SubjectRef subjectRef, String profileId, KeyRef keyRef,
            java.util.Optional<String> signatureAlgorithmId)
            implements PkiSigningOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "ca.create";

        /**
         * Checks the subject, managed key and outgoing selection without resolving a provider or signing.
         *
         * @param formatId encoding format for the created or imported object
         * @param subjectRef subject name for the new authority
         * @param profileId nonblank stable certificate-profile identifier
         * @param keyRef managed key reference used by the authority
         * @param signatureAlgorithmId exact outgoing primary signature identity; empty selects the configured
         *     creation default
         * @throws NullPointerException if a required object is null (except profile or signature-selection
         *     inputs)
         * @throws IllegalArgumentException if the profile identifier is null or blank, the signature selection
         *     container is null or contains blank text
         */
        public CreateAuthority {
            if (signatureAlgorithmId == null || signatureAlgorithmId.filter(String::isBlank).isPresent()) {
                throw new IllegalArgumentException("Invalid outgoing signature selection");
            }
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(subjectRef, "subjectRef");
            Objects.requireNonNull(keyRef, "keyRef");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        /**
         * Creates the operation with an empty outgoing algorithm selector for normalization.
         *
         * @param formatId format
         * @param subjectRef CA subject
         * @param profileId active profile
         * @param keyRef existing managed primary key
         * @throws NullPointerException if a required object is null
         * @throws IllegalArgumentException if the profile is null or blank
         */
        public CreateAuthority(FormatId formatId, SubjectRef subjectRef, String profileId, KeyRef keyRef) {
            this(formatId, subjectRef, profileId, keyRef, java.util.Optional.empty());
        }

        /**
         * {@inheritDoc}
         */
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
     * @param signatureAlgorithmId exact outgoing primary signature identity; empty selects the configured
     *     creation default
     * @param keyRef optional existing managed key; a managed key must be present
     */
    record CreateIntermediate(FormatId formatId, PkiId issuerCaId, SubjectRef subjectRef, String profileId,
            java.util.Optional<KeyRef> keyRef, java.util.Optional<String> signatureAlgorithmId) implements PkiSigningOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "ca.intermediate.create";

        /**
         * Requires an existing managed subject key and checks creation coordinates without resolving the
         * parent.
         *
         * @param formatId encoding format for the created or imported object
         * @param issuerCaId issuing certificate-authority identifier
         * @param subjectRef subject name for the new authority
         * @param profileId nonblank stable certificate-profile identifier
         * @param signatureAlgorithmId exact outgoing primary signature identity; empty selects the configured
         *     creation default
         * @param keyRef optional existing managed key; a managed key must be present
         * @throws NullPointerException if a required object is null (except profile or signature-selection
         *     inputs)
         * @throws IllegalArgumentException if the profile identifier is null or blank, the signature selection
         *     container is null or contains blank text, or the managed subject key is absent
         */
        public CreateIntermediate {
            if (signatureAlgorithmId == null || signatureAlgorithmId.filter(String::isBlank).isPresent()) {
                throw new IllegalArgumentException("Invalid outgoing signature selection");
            }
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(subjectRef, "subjectRef");
            keyRef = Objects.requireNonNull(keyRef, "keyRef");
            if (keyRef.isEmpty()) {
                throw new IllegalArgumentException("A managed subject key is required");
            }
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        /**
         * Creates the operation with an empty outgoing algorithm selector for normalization.
         *
         * @param formatId format
         * @param issuerCaId parent CA
         * @param subjectRef CA subject
         * @param profileId active profile
         * @param keyRef existing managed primary key
         * @throws NullPointerException if a required object is null
         * @throws IllegalArgumentException if the profile is null or blank, or the intermediate key is absent
         */
        public CreateIntermediate(FormatId formatId, PkiId issuerCaId, SubjectRef subjectRef, String profileId,
                java.util.Optional<KeyRef> keyRef) {
            this(formatId, issuerCaId, subjectRef, profileId, keyRef, java.util.Optional.empty());
        }

        /**
         * {@inheritDoc}
         */
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
     * @param expectedHead original subject head, empty only before normalization
     */
    record IssueIntermediateCertificate(FormatId formatId, PkiId issuerCaId, PkiId subjectCaId, String profileId,
            java.util.Optional<Validity> requestedValidity, java.util.Optional<zeroecho.pki.api.ca.CaHeadSnapshot> expectedHead) implements PkiSigningOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "ca.intermediate.issue";

        /**
         * Checks issuer and subject coordinates without resolving the subject head or admitting issuance.
         *
         * @param formatId encoding format for the created or imported object
         * @param issuerCaId issuing certificate-authority identifier
         * @param subjectCaId subject intermediate-authority identifier
         * @param profileId nonblank stable certificate-profile identifier
         * @param requestedValidity optional requested validity constrained by the profile and issuer
         * @param expectedHead original subject head, empty only before normalization
         * @throws NullPointerException if a required object is null (excluding the separately checked profile
         *     identifier)
         * @throws IllegalArgumentException if the profile identifier is null or blank
         */
        public IssueIntermediateCertificate {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(subjectCaId, "subjectCaId");
            requestedValidity = Objects.requireNonNull(requestedValidity, "requestedValidity");
            Objects.requireNonNull(expectedHead, "expectedHead");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        /**
         * Preserves existing intermediate issuance before head normalization.
         *
         * @param formatId format
         * @param issuerCaId parent
         * @param subjectCaId subject
         * @param profileId profile
         * @param requestedValidity requested bounds
         * @throws NullPointerException if a required identifier or optional container is null
         * @throws IllegalArgumentException if the profile identifier is null or blank
         */
        public IssueIntermediateCertificate(FormatId formatId, PkiId issuerCaId, PkiId subjectCaId, String profileId,
                java.util.Optional<Validity> requestedValidity) {
            this(formatId, issuerCaId, subjectCaId, profileId, requestedValidity, java.util.Optional.empty());
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Rolls over one CA credential, keeping the same key and advancing the current issuance generation.
     *
     * @param caId exact certificate-authority identifier
     * @param issuerCaId optional independently selected parent authority
     * @param expectedHead original subject head, empty only before normalization
     */
    record RolloverCaCertificate(PkiId caId, java.util.Optional<PkiId> issuerCaId,
            java.util.Optional<zeroecho.pki.api.ca.CaHeadSnapshot> expectedHead) implements PkiSigningOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "ca.rollover";

        /**
         * Checks authority and optional parent/head containers without preparing same-key rollover.
         *
         * @param caId exact certificate-authority identifier
         * @param issuerCaId optional independently selected parent authority
         * @param expectedHead original subject head, empty only before normalization
         * @throws NullPointerException if a required object is null
         */
        public RolloverCaCertificate {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(expectedHead, "expectedHead");
        }

        /**
         * Preserves same-key rollover before expected-head normalization.
         *
         * @param caId subject authority
         * @param issuerCaId optional parent authority
         * @throws NullPointerException if a required identifier or optional container is null
         */
        public RolloverCaCertificate(PkiId caId, java.util.Optional<PkiId> issuerCaId) {
            this(caId, issuerCaId, java.util.Optional.empty());
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Changes selected outgoing CA roles and prepares a corresponding generation.
     *
     * <p>A role change may replace a managed key or select a compatible signature
     * algorithm while retaining that role's key. Ordinary accepted rotation advances
     * the selected generation. A fresh root-anchor candidate is completed separately
     * from its later distribution acknowledgment and durable activation.</p>
     *
     * @param caId exact certificate-authority identifier
     * @param selection explicit outgoing role/member changes, resolved before approval
     * @param issuerCaId optional independently selected parent authority
     * @param expectedHead original selected head, absent only before normalization
     */
    record RotateCaKey(PkiId caId, zeroecho.pki.api.ca.CaRotationSelection selection,
            java.util.Optional<PkiId> issuerCaId, java.util.Optional<zeroecho.pki.api.ca.CaHeadSnapshot> expectedHead)
            implements PkiSigningOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "ca.rotate";

        /**
         * Retains the explicit role selection and optional head fence without resolving keys or activating a
         * candidate.
         *
         * @param caId exact certificate-authority identifier
         * @param selection explicit outgoing role/member changes, resolved before approval
         * @param issuerCaId optional independently selected parent authority
         * @param expectedHead original selected head, absent only before normalization
         * @throws NullPointerException if a required object is null
         */
        public RotateCaKey {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(selection, "selection");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(expectedHead, "expectedHead");
        }

        /**
         * Constructs the existing primary-key-only operation.
         *
         * @param caId exact authority
         * @param newKeyRef required managed primary key
         * @param issuerCaId optional parent authority
         * @throws NullPointerException if a required identifier or optional container is null
         * @throws IllegalArgumentException if the replacement primary key is absent
         */
        public RotateCaKey(PkiId caId, java.util.Optional<KeyRef> newKeyRef, java.util.Optional<PkiId> issuerCaId) {
            this(caId, zeroecho.pki.api.ca.CaRotationSelection.primaryKey(newKeyRef.orElseThrow(
                    () -> new IllegalArgumentException("A managed replacement key is required"))),
                    issuerCaId, java.util.Optional.empty());
        }

        /**
         * Returns only the explicitly selected replacement primary key.
         *
         * <p>Empty also covers an algorithm-only primary change; it does not mean
         * that no rotation was requested or resolve the effective retained key.</p>
         *
         * @return explicit primary key override, empty when no primary key override exists
         */
        public java.util.Optional<KeyRef> newKeyRef() {
            return selection.primary().flatMap(zeroecho.pki.api.ca.CaRotationSelection.RoleChange::keyRef);
        }

        /**
         * {@inheritDoc}
         */
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
        /**
         * Stable operation name.
         */
        public static final String NAME = "credential.issue";

        /**
         * Checks the required credential coordinates without resolving stored records, authorizing the caller
         * or signing.
         *
         * @param issuerCaId issuing certificate-authority identifier
         * @param requestId exact imported certification-request identifier
         * @param profileId nonblank stable certificate-profile identifier
         * @throws NullPointerException if a required object is null (excluding the separately checked profile
         *     identifier)
         * @throws IllegalArgumentException if the profile identifier is null or blank
         */
        public IssueCredential {
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(requestId, "requestId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        /**
         * {@inheritDoc}
         */
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
        /**
         * Stable operation name.
         */
        public static final String NAME = "credential.renew";

        /**
         * Checks the required credential coordinates without resolving stored records, authorizing the caller
         * or signing.
         *
         * @param credentialId exact committed credential identifier
         * @throws NullPointerException if a required object is null
         */
        public RenewCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        /**
         * {@inheritDoc}
         */
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
        /**
         * Stable operation name.
         */
        public static final String NAME = "credential.replace";

        /**
         * Checks the required credential coordinates without resolving stored records, authorizing the caller
         * or signing.
         *
         * @param existingCredentialId exact credential that the replacement supersedes
         * @param requestId exact imported certification-request identifier
         * @param profileId nonblank stable certificate-profile identifier
         * @throws NullPointerException if a required object is null (excluding the separately checked profile
         *     identifier)
         * @throws IllegalArgumentException if the profile identifier is null or blank
         */
        public ReplaceCredential {
            Objects.requireNonNull(existingCredentialId, "existingCredentialId");
            Objects.requireNonNull(requestId, "requestId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        /**
         * {@inheritDoc}
         */
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
        /**
         * Stable operation name.
         */
        public static final String NAME = "credential.reissue";

        /**
         * Checks the required credential coordinates without resolving stored records, authorizing the caller
         * or signing.
         *
         * @param credentialId exact committed credential identifier
         * @throws NullPointerException if a required object is null
         */
        public ReissueCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        /**
         * {@inheritDoc}
         */
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
        /**
         * Stable operation name.
         */
        public static final String NAME = "status.generate";

        /**
         * Checks the required status coordinates without reading revocations or verifying format support.
         *
         * @param issuerCaId issuing certificate-authority identifier
         * @param type kind of status object to generate
         * @param formatId encoding format for the created or imported object
         * @throws NullPointerException if a required object is null
         */
        public GenerateStatus {
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(formatId, "formatId");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    private static String profileIdRequiredMessage() {
        return "profileId must not be blank";
    }
    private static String authorityIdParameter() {
        return "caId";
    }
    private static String issuerAuthorityIdParameter() {
        return "issuerCaId";
    }
}
