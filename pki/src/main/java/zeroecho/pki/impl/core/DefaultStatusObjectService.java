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

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.cert.X509CertificateHolder;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.revocation.RevokedRecord;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectQuery;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default implementation of {@link StatusObjectService}.
 *
 * <p>
 * This service coordinates generation and lookup of PKI status objects against
 * the configured {@link PkiStore} and delegates format-specific object creation
 * to the active {@link CredentialFramework}. The store acts as the
 * authoritative source of issuer CA state, issuer credentials, revocation
 * records, and previously generated status objects.
 * </p>
 *
 * <p>
 * The current runtime implementation primarily supports generation workflows
 * that require issuer certificate material and issuer signing key indirection
 * to be provided through status-object attributes. For X.509 CRL generation,
 * this class additionally derives revoked certificate serial numbers from the
 * revocation and credential records currently available in the store.
 * </p>
 *
 * <h2>Persistence model</h2>
 * <ul>
 * <li>Each successfully generated {@link StatusObject} is persisted through the
 * configured {@link PkiStore}.</li>
 * <li>Lookup operations read directly from the store and do not maintain an
 * internal cache.</li>
 * <li>The service is stateless apart from its immutable collaborators.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This service does not access private key material directly.</li>
 * <li>Issuer signing capability is conveyed only through
 * {@link BcX509Attributes#ISSUER_KEYREF}.</li>
 * <li>For CRL generation, malformed credentials and unresolved revocation
 * targets are silently ignored by the current implementation rather than
 * failing the entire generation request.</li>
 * <li>The correctness of the generated status object depends on the configured
 * {@link CredentialFramework} matching the requested runtime format and
 * honoring the supplied attributes.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is safe for concurrent use provided that the injected
 * {@link PkiStore} and {@link CredentialFramework} implementations are
 * themselves safe for the intended concurrency model.
 * </p>
 */
public final class DefaultStatusObjectService implements StatusObjectService {
    private static final Logger LOG = Logger.getLogger(DefaultStatusObjectService.class.getName());

    /**
     * Attribute identifier used to pass one revoked certificate serial number to
     * the current X.509 CRL backend wiring.
     *
     * <p>
     * The current implementation adds this attribute repeatedly during CRL input
     * assembly. The effective handling of multiple values is therefore determined
     * by the semantics of {@link SimpleAttributeSet.Builder} and by the downstream
     * status object generator contract.
     * </p>
     */
    private static final AttributeId CRL_REVOKED_SERIAL = new AttributeId("urn:zeroecho:pki:x509:crl:revoked");

    private final PkiStore store;
    private final CredentialFramework framework;

    /**
     * Creates a status object service bound to the supplied persistence and
     * framework collaborators.
     *
     * @param store     PKI store used for issuer lookup, revocation enumeration,
     *                  status object persistence, and status object listing; must
     *                  not be {@code null}
     * @param framework credential framework providing the format-specific status
     *                  object generator; must not be {@code null}
     * @throws NullPointerException if {@code store} or {@code framework} is
     *                              {@code null}
     */
    public DefaultStatusObjectService(PkiStore store, CredentialFramework framework) {
        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
    }

    /**
     * Generates a new status object for the specified issuer CA and persists the
     * result.
     *
     * <p>
     * The issuer CA must already exist, must be in {@link CaState#ACTIVE} state,
     * and must expose at least one CA credential. The current implementation uses
     * the last credential in {@link CaRecord#caCredentials()} as the effective
     * issuer credential for status-object generation.
     * </p>
     *
     * <p>
     * The supplied command attributes are copied and then enriched with issuer
     * material required by the current backend wiring:
     * </p>
     * <ul>
     * <li>{@link BcX509Attributes#ISSUER_CERT_DER} is populated from the selected
     * issuer credential encoding,</li>
     * <li>{@link BcX509Attributes#ISSUER_KEYREF} is populated from the issuer CA
     * key reference.</li>
     * </ul>
     *
     * <p>
     * When {@link StatusObjectType#CRL} is requested, the service additionally
     * scans all revocation records in the store, excludes entries with
     * {@code REMOVE_FROM_CRL}, resolves the referenced credentials, filters them to
     * the requested issuer CA, extracts X.509 serial numbers, and forwards serials
     * that fit into a signed 64-bit integer as repeated {@link #CRL_REVOKED_SERIAL}
     * attributes.
     * </p>
     *
     * <p>
     * Malformed credential payloads encountered during CRL input derivation are
     * ignored by the current implementation and do not abort generation.
     * </p>
     *
     * @param command status object generation request; must not be {@code null}
     * @return generated and persisted status object
     * @throws IllegalArgumentException if {@code command} is {@code null}
     * @throws PkiException             if the issuer CA does not exist, is not
     *                                  active, has no credentials, if the framework
     *                                  generator fails, or if persistence of the
     *                                  generated status object fails
     */
    @Override
    public StatusObject generate(StatusObjectGenerateCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        CaRecord ca = store.getCa(command.issuerCaId()).orElseThrow(() -> new PkiException("Issuer CA not found"));
        if (ca.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA not ACTIVE");
        }
        if (ca.caCredentials().isEmpty()) {
            throw new PkiException("Issuer CA has no credentials");
        }
        Credential issuerCred = ca.caCredentials().get(ca.caCredentials().size() - 1);

        SimpleAttributeSet.Builder b = SimpleAttributeSet.builder();
        b.putAll(command.attributes());
        b.put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(issuerCred.encoded().bytes()));
        b.put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(ca.issuerKeyRef().value()));

        if (command.type() == StatusObjectType.CRL) {
            List<RevokedRecord> revs = store.listRevocations();
            for (RevokedRecord rr : revs) {
                if (rr.reason() == zeroecho.pki.api.revocation.RevocationReason.REMOVE_FROM_CRL) {
                    continue;
                }
                Optional<Credential> credOpt = store.getCredential(rr.credentialId());
                if (credOpt.isEmpty()) {
                    continue;
                }
                Credential cred = credOpt.get();
                if (!command.issuerCaId().equals(cred.issuerRef().caId())) {
                    continue;
                }
                try {
                    X509CertificateHolder h = new X509CertificateHolder(cred.encoded().bytes()); // NOPMD
                    BigInteger serial = h.getSerialNumber();
                    if (serial.bitLength() <= 63) { // NOPMD
                        b.put(CRL_REVOKED_SERIAL, new AttributeValue.IntegerValue(serial.longValue())); // NOPMD
                    }
                } catch (Exception ex) {
                    LOG.log(Level.FINE, "malformed credential ignored", ex);
                }
            }
        }

        StatusObjectGenerateCommand wired = new StatusObjectGenerateCommand(command.issuerCaId(), command.type(),
                command.formatId(), b.build());
        StatusObject obj = framework.statusObjectGenerator().generate(wired);
        store.putStatusObject(obj);
        return obj;
    }

    /**
     * Resolves the most recent status object of the requested type for a given
     * issuer CA.
     *
     * <p>
     * The method examines all status objects returned by
     * {@link PkiStore#listStatusObjects(PkiId)} for the supplied issuer and selects
     * the object with the greatest {@link StatusObject#thisUpdate()} value among
     * those whose {@link StatusObjectType} matches the requested type.
     * </p>
     *
     * <p>
     * If multiple objects share the same latest {@code thisUpdate} instant, the
     * stream {@code max(...)} semantics determine which matching object is
     * returned. The current implementation does not define any additional tie-break
     * rule.
     * </p>
     *
     * @param issuerCaId identifier of the issuer CA whose latest status object is
     *                   to be resolved; must not be {@code null}
     * @param type       requested status object type; must not be {@code null}
     * @return optional containing the latest matching status object, or an empty
     *         optional when no object of the requested type exists for the issuer
     * @throws IllegalArgumentException if {@code issuerCaId} or {@code type} is
     *                                  {@code null}
     */
    @Override
    public Optional<StatusObject> getLatest(PkiId issuerCaId, StatusObjectType type) {
        if (issuerCaId == null) {
            throw new IllegalArgumentException("issuerCaId must not be null");
        }
        if (type == null) {
            throw new IllegalArgumentException("type must not be null");
        }
        List<StatusObject> all = store.listStatusObjects(issuerCaId);
        return all.stream().filter(o -> o.type() == type).max(java.util.Comparator.comparing(StatusObject::thisUpdate));
    }

    /**
     * Lists status objects for one issuer CA filtered by the supplied query
     * constraints.
     *
     * <p>
     * Filtering is performed in memory over the status objects returned by
     * {@link PkiStore#listStatusObjects(PkiId)} for the queried issuer CA. Only
     * constraints present in the {@link StatusObjectQuery} are applied.
     * </p>
     *
     * <h4>Time filtering semantics</h4>
     * <ul>
     * <li>{@code createdAfter}: objects strictly earlier than the supplied instant
     * are excluded; objects exactly at the supplied instant are retained.</li>
     * <li>{@code createdBefore}: objects at or after the supplied instant are
     * excluded; only objects strictly before the supplied instant are
     * retained.</li>
     * </ul>
     *
     * @param query query describing the issuer CA and optional filtering criteria;
     *              must not be {@code null}
     * @return immutable list of matching status objects; never {@code null}
     * @throws IllegalArgumentException if {@code query} is {@code null}
     */
    @Override
    public List<StatusObject> list(StatusObjectQuery query) {
        if (query == null) {
            throw new IllegalArgumentException("query must not be null");
        }
        List<StatusObject> all = store.listStatusObjects(query.issuerCaId());
        return all.stream().filter(o -> {
            if (query.type().isPresent() && query.type().get() != o.type()) {
                return false;
            }
            if (query.createdAfter().isPresent() && o.thisUpdate().isBefore(query.createdAfter().get())) {
                return false;
            }
            return !(query.createdBefore().isPresent() && !o.thisUpdate().isBefore(query.createdBefore().get()));
        }).toList();
    }
}
