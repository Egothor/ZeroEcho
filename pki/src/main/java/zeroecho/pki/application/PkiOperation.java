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

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationReason;

/**
 * Closed set of typed synchronous PKI operations available to transports.
 *
 * <p>Names are stable external semantic identities. Implementations dispatch by
 * explicit type and never by reflection or Java class name.</p>
 */
public sealed interface PkiOperation permits PkiOperation.ValidateConfiguration, PkiOperation.ValidateProfile,
        PkiOperation.InspectCredential, PkiOperation.RevokeCredential, PkiOperation.ReadRevocationHistory,
        PkiOperation.InspectPublication {

    /** @return stable semantic operation name */
    String name();

    /** Validates the already-open session configuration. */
    record ValidateConfiguration() implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "configuration.validate";

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Validates one bounded certificate-profile JSON document without persisting it. */
    record ValidateProfile(byte[] document) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.validate";

        /** Defensively snapshots the document. */
        public ValidateProfile {
            document = Objects.requireNonNull(document, "document").clone();
        }

        @Override
        public byte[] document() {
            return document.clone();
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads safe metadata for one committed credential. */
    record InspectCredential(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.inspect";

        /** Validates the identifier. */
        public InspectCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Permanently revokes one committed credential. */
    record RevokeCredential(PkiId credentialId, RevocationReason reason) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.revoke";

        /** Validates permanent-revocation inputs. */
        public RevokeCredential {
            Objects.requireNonNull(credentialId, "credentialId");
            Objects.requireNonNull(reason, "reason");
            if (reason == RevocationReason.CERTIFICATE_HOLD || reason == RevocationReason.REMOVE_FROM_CRL) {
                throw new IllegalArgumentException("reason must be permanent");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads a bounded prefix from one closeable authoritative history cursor. */
    record ReadRevocationHistory(PkiId credentialId, int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "revocation.history";
        /** Maximum finite result entries for one invocation. */
        public static final int MAXIMUM_RESULT_ENTRIES = 1_000;

        /** Validates the identifier and finite result limit. */
        public ReadRevocationHistory {
            Objects.requireNonNull(credentialId, "credentialId");
            if (limit < 1 || limit > MAXIMUM_RESULT_ENTRIES) {
                throw new IllegalArgumentException("limit must be between 1 and 1000");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads safe durable state for one publication operation. */
    record InspectPublication(PkiId publicationId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "publication.inspect";

        /** Validates the identifier. */
        public InspectPublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }
}
