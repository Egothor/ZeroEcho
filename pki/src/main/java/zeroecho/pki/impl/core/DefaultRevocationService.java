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
package zeroecho.pki.impl.core;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.revocation.HoldCommand;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevokeCommand;
import zeroecho.pki.api.revocation.RevokedRecord;
import zeroecho.pki.api.revocation.UnholdCommand;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default implementation of {@link RevocationService}.
 *
 * <p>
 * This service provides the store-backed runtime path for credential revocation
 * state recording and lookup. It validates that the referenced credential
 * exists, creates a corresponding {@link RevokedRecord}, and persists that
 * record into the configured {@link PkiStore}.
 * </p>
 *
 * <p>
 * The implementation is intentionally minimal and does not attempt to enforce a
 * complex revocation state machine. In particular, it does not prevent repeated
 * writes for the same credential, does not reconcile prior revocation records,
 * and does not validate higher-level business transitions such as whether a
 * hold can be removed only after a prior hold. Such governance is expected to
 * be handled by higher layers or by stricter store policies.
 * </p>
 *
 * <h2>Persistence model</h2>
 * <ul>
 * <li>Each successful operation creates a new {@link RevokedRecord} timestamped
 * with the current service time.</li>
 * <li>The resulting record is written to the configured {@link PkiStore}
 * through {@link PkiStore#putRevocation(RevokedRecord)}.</li>
 * <li>Lookup and search operations read from the store and do not maintain an
 * internal cache.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This service does not modify the credential object itself; it records
 * revocation state separately.</li>
 * <li>The trustworthiness of revocation status therefore depends on consumers
 * consulting the revocation store or derivative status objects such as CRLs or
 * OCSP-equivalent artifacts.</li>
 * <li>Attributes carried in revocation commands are passed through to the
 * stored record unchanged and should therefore be governed upstream to avoid
 * leaking sensitive material.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless apart from its immutable store dependency. It is safe
 * for concurrent use provided that the configured {@link PkiStore} is safe for
 * the intended concurrency model.
 * </p>
 */
public final class DefaultRevocationService implements RevocationService {

    private final PkiStore store;

    /**
     * Creates the revocation service backed by the supplied PKI store.
     *
     * @param store PKI store used for credential existence checks, revocation
     *              persistence, and revocation lookup; must not be {@code null}
     * @throws NullPointerException if {@code store} is {@code null}
     */
    public DefaultRevocationService(PkiStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /**
     * Records a revocation entry for an existing credential using the caller-
     * supplied revocation reason.
     *
     * <p>
     * The referenced credential must already exist in the store. On success, this
     * method creates a new {@link RevokedRecord} timestamped with
     * {@link Instant#now()}, persists it, and returns the stored record.
     * </p>
     *
     * <p>
     * This method does not check whether the credential has already been revoked or
     * whether the requested reason conflicts with a previously persisted
     * revocation-state history.
     * </p>
     *
     * @param command revocation request describing the target credential, reason,
     *                and auxiliary attributes; must not be {@code null}
     * @return newly created revocation record
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the referenced credential does not exist or
     *                              if the revocation record cannot be persisted
     */
    @Override
    public RevokedRecord revoke(RevokeCommand command) {
        Objects.requireNonNull(command, "command");
        store.getCredential(command.credentialId()).orElseThrow(() -> new PkiException("Credential not found"));
        RevokedRecord rr = new RevokedRecord(command.credentialId(), Instant.now(), command.reason(),
                command.attributes());
        store.putRevocation(rr);
        return rr;
    }

    /**
     * Records a certificate-hold entry for an existing credential.
     *
     * <p>
     * This method is a specialization of revocation recording that always uses
     * {@link RevocationReason#CERTIFICATE_HOLD} as the persisted reason.
     * </p>
     *
     * <p>
     * The method does not verify whether the credential is already on hold or
     * whether a prior revocation history would make the hold semantically invalid.
     * </p>
     *
     * @param command hold request describing the target credential and auxiliary
     *                attributes; must not be {@code null}
     * @return newly created hold record
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the referenced credential does not exist or
     *                              if the hold record cannot be persisted
     */
    @Override
    public RevokedRecord hold(HoldCommand command) {
        Objects.requireNonNull(command, "command");
        store.getCredential(command.credentialId()).orElseThrow(() -> new PkiException("Credential not found"));
        RevokedRecord rr = new RevokedRecord(command.credentialId(), Instant.now(), RevocationReason.CERTIFICATE_HOLD,
                command.attributes());
        store.putRevocation(rr);
        return rr;
    }

    /**
     * Records a removal-from-CRL entry for an existing credential.
     *
     * <p>
     * This method is a specialization of revocation recording that always uses
     * {@link RevocationReason#REMOVE_FROM_CRL} as the persisted reason.
     * </p>
     *
     * <p>
     * The method does not verify whether the credential was previously placed on
     * hold or whether the resulting transition is semantically valid according to a
     * stricter revocation-state model.
     * </p>
     *
     * @param command unhold request describing the target credential and auxiliary
     *                attributes; must not be {@code null}
     * @return newly created unhold record
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the referenced credential does not exist or
     *                              if the unhold record cannot be persisted
     */
    @Override
    public RevokedRecord unhold(UnholdCommand command) {
        Objects.requireNonNull(command, "command");
        store.getCredential(command.credentialId()).orElseThrow(() -> new PkiException("Credential not found"));
        RevokedRecord rr = new RevokedRecord(command.credentialId(), Instant.now(), RevocationReason.REMOVE_FROM_CRL,
                command.attributes());
        store.putRevocation(rr);
        return rr;
    }

    /**
     * Resolves the current revocation record associated with a credential
     * identifier.
     *
     * <p>
     * The exact meaning of the returned record depends on the configured
     * {@link PkiStore} implementation. For stores that keep only one effective
     * revocation entry per credential, this method returns that effective record.
     * For stores with historical tracking, the SPI contract determines which record
     * is exposed as the direct lookup result.
     * </p>
     *
     * @param credentialId identifier of the credential whose revocation state is to
     *                     be resolved; must not be {@code null}
     * @return optional containing a revocation record when one is available for the
     *         credential, or an empty optional otherwise
     * @throws NullPointerException if {@code credentialId} is {@code null}
     */
    @Override
    public Optional<RevokedRecord> get(PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        return store.getRevocation(credentialId);
    }

    /**
     * Searches revocation records matching the supplied query constraints.
     *
     * <p>
     * Filtering is performed in memory over the revocation records returned by the
     * configured {@link PkiStore}. Only constraints present in the
     * {@link RevocationQuery} are applied.
     * </p>
     *
     * <h4>Time filtering semantics</h4>
     * <ul>
     * <li>{@code revokedAfter}: records strictly earlier than the supplied instant
     * are excluded; records exactly at the supplied instant are retained.</li>
     * <li>{@code revokedBefore}: records at or after the supplied instant are
     * excluded; only records strictly before the supplied instant are
     * retained.</li>
     * </ul>
     *
     * <p>
     * When {@code issuerCaId} is present, the service resolves each revocation's
     * credential from the store and compares its issuer CA identifier. Revocation
     * records whose referenced credential can no longer be resolved are excluded
     * from the search result for that branch of filtering.
     * </p>
     *
     * @param query revocation search criteria; must not be {@code null}
     * @return immutable list of revocation records matching the supplied criteria;
     *         never {@code null}
     * @throws NullPointerException if {@code query} is {@code null}
     */
    @Override
    public List<RevokedRecord> search(RevocationQuery query) {
        Objects.requireNonNull(query, "query");
        List<RevokedRecord> all = store.listRevocations();
        return all.stream().filter(r -> {
            if (query.reason().isPresent() && query.reason().get() != r.reason()) {
                return false;
            }
            if (query.revokedAfter().isPresent() && r.revocationTime().isBefore(query.revokedAfter().get())) {
                return false;
            }
            if (query.revokedBefore().isPresent() && !r.revocationTime().isBefore(query.revokedBefore().get())) {
                return false;
            }
            if (query.issuerCaId().isPresent()) {
                Optional<zeroecho.pki.api.credential.Credential> c = store.getCredential(r.credentialId());
                if (c.isEmpty()) {
                    return false;
                }
                PkiId issuerId = c.get().issuerRef().caId();
                return query.issuerCaId().get().equals(issuerId);
            }
            return true;
        }).toList();
    }
}
