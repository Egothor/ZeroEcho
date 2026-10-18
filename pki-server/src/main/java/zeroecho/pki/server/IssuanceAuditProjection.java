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
package zeroecho.pki.server;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.spi.store.AuditEvidenceFeed;

/**
 * Issuance family adapter for the generic {@link AuditEvidenceProjector}: maps one append-ordered
 * issuance-evidence feed entry to a payload-free audit event, decoding the credential's co-committed
 * {@link IssuanceExecutionEvidence}. Entries whose credential carries no issuance evidence (for example an
 * imported credential) project to nothing.
 */
final class IssuanceAuditProjection {
    private static final String RECORD_ID = "issuance-v1";
    private static final String CATEGORY = "ISSUANCE";
    private static final String ACTION = "CREDENTIAL_ISSUED";
    private static final Purpose PURPOSE = new Purpose("ISSUANCE_AUDIT_PROJECTION");
    private static final byte[] EVENT_ID_DOMAIN =
            "ZEROECHO-ISSUANCE-AUDIT-EVENT-V1\0".getBytes(StandardCharsets.US_ASCII);

    private IssuanceAuditProjection() {
    }

    /* default */ static String recordId() {
        return RECORD_ID;
    }

    /* default */ static Optional<AuditEvent> toEvent(AuditEvidenceFeed.Entry entry) {
        Optional<IssuanceExecutionEvidence> evidence = IssuanceExecutionEvidence.decode(entry.evidence());
        if (evidence.isEmpty()) {
            return Optional.empty();
        }
        IssuanceExecutionEvidence exact = evidence.orElseThrow();
        Map<String, String> details = new LinkedHashMap<>();
        details.put("eventId", eventId(entry));
        details.put("realmId", exact.realmId());
        details.put("credentialId", entry.objectId().value());
        details.put("issuerCaId", exact.issuerCaId());
        details.put("profileId", exact.profileId());
        details.put("requestId", exact.requestId());
        details.put("actorType", exact.actorType().name());
        details.put("actorId", exact.actorId());
        details.put("authentication", exact.authentication().name());
        details.put("authorization", exact.authorization().name());
        details.put("outcome", exact.outcome().name());
        exact.authorizationPath().ifPresent(path -> details.put("authorizationPath", path.name()));
        exact.operationCommitment().ifPresent(commitment -> details.put("operationCommitment", commitment));
        return Optional.of(new AuditEvent(entry.recordedAt(), CATEGORY, ACTION,
                new Principal(exact.actorType().name(), exact.actorId()), PURPOSE,
                Optional.of(entry.objectId()), Optional.empty(), Map.copyOf(details)));
    }

    // Deterministic event identity so a crash-retry re-emitting the same append sequence yields the same id.
    private static String eventId(AuditEvidenceFeed.Entry entry) {
        MessageDigest digest = sha256();
        digest.update(EVENT_ID_DOMAIN);
        digest.update(Long.toString(entry.sequence()).getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
        digest.update(entry.objectId().value().getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("Required SHA-256 digest is unavailable", impossible);
        }
    }
}
