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

import java.util.List;
import java.util.Objects;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.issuance.BundleCommand;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.ReissueCommand;
import zeroecho.pki.api.issuance.RenewCommand;
import zeroecho.pki.api.issuance.ReplaceCommand;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default implementation of {@link IssuanceService}.
 *
 * <p>
 * This service coordinates end-entity credential issuance against the
 * configured {@link PkiStore} and delegates format-specific issuance work to
 * the active {@link CredentialFramework}. The store is used as the
 * authoritative source of issuer CA state and previously persisted credentials,
 * while the framework backend performs the actual credential construction for
 * the selected format.
 * </p>
 *
 * <p>
 * The implementation intentionally enforces only a limited set of issuance-side
 * invariants:
 * </p>
 * <ul>
 * <li>the issuer CA must exist,</li>
 * <li>the issuer CA must be in {@link CaState#ACTIVE} state,</li>
 * <li>the issuer CA must expose at least one credential,</li>
 * <li>a suitable issuer credential must be resolvable for the active framework
 * {@link FormatId},</li>
 * <li>issuer material required by the current X.509 runtime wiring must be
 * present in issuance overrides before the backend is invoked.</li>
 * </ul>
 *
 * <p>
 * Credential bundles returned by this service are assembled at runtime. Only
 * the newly issued leaf {@link Credential} is persisted by this implementation.
 * Certificate chain assembly, publication, and advanced bundle composition are
 * treated as higher-layer concerns.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This service does not access private key material directly.</li>
 * <li>Issuer key usage is represented only through {@link KeyRef} indirection
 * in backend overrides.</li>
 * <li>The correctness of issuance semantics depends on the configured
 * {@link CredentialFramework} matching the requested runtime format and on the
 * backend honoring the supplied issuer material.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless apart from its immutable collaborators. It is safe
 * for concurrent use provided that the configured {@link PkiStore} and
 * {@link CredentialFramework} implementations are safe for the intended
 * concurrency model.
 * </p>
 */
public final class DefaultIssuanceService implements IssuanceService {

    private final PkiStore store;
    private final CredentialFramework framework;

    /**
     * Creates the issuance service bound to the supplied persistence and framework
     * collaborators.
     *
     * @param store     PKI store used for issuer CA lookup and credential
     *                  persistence; must not be {@code null}
     * @param framework credential framework providing format-specific issuance
     *                  backends; must not be {@code null}
     * @throws NullPointerException if {@code store} or {@code framework} is
     *                              {@code null}
     */
    public DefaultIssuanceService(PkiStore store, CredentialFramework framework) {
        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
    }

    /**
     * Issues a new end-entity credential and returns the resulting runtime bundle.
     *
     * <p>
     * The issuer CA is resolved from the store and validated as active before
     * issuance proceeds. The method then selects a suitable issuer credential for
     * the active framework format, enriches the supplied issuance overrides with
     * issuer material required by the X.509 backend wiring, delegates issuance to
     * the framework backend, and persists only the issued leaf credential.
     * </p>
     *
     * <p>
     * The returned {@link CredentialBundle} may contain additional runtime material
     * such as chain elements, but this implementation persists only
     * {@link CredentialBundle#credential()}.
     * </p>
     *
     * @param command end-entity issuance command; must not be {@code null}
     * @return issued credential bundle produced by the active framework backend
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the issuer CA does not exist, is not active,
     *                              has no credentials, no compatible issuer
     *                              credential can be selected, issuer material
     *                              enrichment fails, backend issuance fails, or
     *                              persistence of the issued leaf credential fails
     */
    @Override
    public CredentialBundle issueEndEntity(IssueEndEntityCommand command) {
        Objects.requireNonNull(command, "command");
        CaRecord issuer = store.getCa(command.issuerCaId()).orElseThrow(() -> new PkiException("Issuer CA not found"));

        if (issuer.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA not ACTIVE");
        }
        if (issuer.caCredentials().isEmpty()) {
            throw new PkiException("Issuer CA has no credentials");
        }

        Credential issuerCred = selectIssuerCredential(issuer, framework.formatId());
        AttributeSet enrichedOverrides = enrichOverrides(command.overrides(), issuerCred.encoded(),
                issuer.issuerKeyRef());

        // Defensive invariant: the X.509 backend requires issuer material in overrides.
        if (enrichedOverrides.get(BcX509Attributes.ISSUER_CERT_DER).isEmpty()) {
            throw new PkiException("Issuer material wiring failed: missing issuer cert DER override");
        }
        if (enrichedOverrides.get(BcX509Attributes.ISSUER_KEYREF).isEmpty()) {
            throw new PkiException("Issuer material wiring failed: missing issuer keyref override");
        }

        IssueEndEntityCommand enriched = new IssueEndEntityCommand(command.issuerCaId(), command.request(),
                command.profileId(), command.validityOverride(), enrichedOverrides);

        CredentialBundle bundle = framework.issuerBackend().issueEndEntity(enriched);
        store.putCredential(bundle.credential());
        return bundle;
    }

    /**
     * Selects the issuer credential that should be used for issuance in the given
     * format.
     *
     * <p>
     * The selection strategy prefers a credential whose {@link FormatId} matches
     * the requested format and whose status is {@link CredentialStatus#ISSUED}. If
     * no such credential exists, the method falls back to the first non-null
     * credential whose format matches, regardless of status.
     * </p>
     *
     * <p>
     * This method does not evaluate validity windows, revocation state external to
     * {@link CredentialStatus}, or profile suitability. It performs only the
     * minimal runtime selection required by the current implementation.
     * </p>
     *
     * @param issuer   issuer CA record containing candidate credentials; must not
     *                 be {@code null}
     * @param formatId format identifier required by the active framework; must not
     *                 be {@code null}
     * @return selected issuer credential
     * @throws NullPointerException if {@code issuer} or {@code formatId} is
     *                              {@code null}
     * @throws PkiException         if the issuer CA has no credential compatible
     *                              with the requested format
     */
    private static Credential selectIssuerCredential(CaRecord issuer, FormatId formatId) {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(formatId, "formatId");

        for (Credential c : issuer.caCredentials()) {
            if (c == null) {
                continue;
            }
            if (formatId.equals(c.formatId()) && c.status() == CredentialStatus.ISSUED) {
                return c;
            }
        }
        for (Credential c : issuer.caCredentials()) {
            if (c != null && formatId.equals(c.formatId())) {
                return c;
            }
        }
        throw new PkiException("Issuer CA has no credential for formatId " + formatId.value());
    }

    /**
     * Enriches caller-supplied issuance overrides with issuer material required by
     * the current X.509 backend wiring.
     *
     * <p>
     * Existing override values take precedence. Missing values for
     * {@link BcX509Attributes#ISSUER_CERT_DER} and
     * {@link BcX509Attributes#ISSUER_KEYREF} are populated from the supplied issuer
     * credential encoding and issuer key reference.
     * </p>
     *
     * <p>
     * The returned {@link AttributeSet} is a newly built instance and does not
     * mutate the caller-supplied set.
     * </p>
     *
     * @param overrides     original issuance overrides; must not be {@code null}
     * @param issuerCertDer DER-encoded issuer credential payload to inject when the
     *                      corresponding override is absent; must not be
     *                      {@code null}
     * @param issuerKeyRef  issuer key reference to inject when the corresponding
     *                      override is absent; must not be {@code null}
     * @return enriched attribute set containing the original overrides plus any
     *         missing issuer wiring attributes
     * @throws NullPointerException if any argument is {@code null}
     */
    private static AttributeSet enrichOverrides(AttributeSet overrides, EncodedObject issuerCertDer,
            KeyRef issuerKeyRef) {
        Objects.requireNonNull(overrides, "overrides");
        Objects.requireNonNull(issuerCertDer, "issuerCertDer");
        Objects.requireNonNull(issuerKeyRef, "issuerKeyRef");

        SimpleAttributeSet.Builder b = SimpleAttributeSet.builder().putAll(overrides);

        if (overrides.get(BcX509Attributes.ISSUER_CERT_DER).isEmpty()) {
            b.put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(issuerCertDer.bytes()));
        }
        if (overrides.get(BcX509Attributes.ISSUER_KEYREF).isEmpty()) {
            b.put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(issuerKeyRef.value()));
        }
        return b.build();
    }

    /**
     * Requests credential renewal.
     *
     * <p>
     * The {@link IssuanceService} contract exposes this operation, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command renewal request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because renewal is not implemented in
     *                              this runtime build
     */
    @Override
    public CredentialBundle renew(RenewCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("Renew is not implemented in this runtime build");
    }

    /**
     * Requests credential replacement.
     *
     * <p>
     * The {@link IssuanceService} contract exposes this operation, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command replacement request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because replacement is not implemented
     *                              in this runtime build
     */
    @Override
    public CredentialBundle replace(ReplaceCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("Replace is not implemented in this runtime build");
    }

    /**
     * Requests credential reissuance.
     *
     * <p>
     * The {@link IssuanceService} contract exposes this operation, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command reissuance request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because reissuance is not implemented in
     *                              this runtime build
     */
    @Override
    public CredentialBundle reissue(ReissueCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("Reissue is not implemented in this runtime build");
    }

    /**
     * Builds a runtime credential bundle for a previously persisted leaf
     * credential.
     *
     * <p>
     * This implementation currently returns a minimal bundle containing only the
     * resolved leaf credential and an empty chain. Chain discovery, issuer path
     * construction, and publication-aware bundle assembly are intentionally left to
     * higher layers.
     * </p>
     *
     * @param command bundle construction command identifying the leaf credential;
     *                must not be {@code null}
     * @return minimal credential bundle containing the resolved leaf credential and
     *         no chain elements
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the requested credential does not exist in
     *                              the store
     */
    @Override
    public CredentialBundle buildBundle(BundleCommand command) {
        Objects.requireNonNull(command, "command");
        PkiId credId = command.credentialId();
        Credential leaf = store.getCredential(credId).orElseThrow(() -> new PkiException("Credential not found"));
        // Minimal bundle: leaf only. Chain selection and publication are higher-layer
        // concerns.
        return new CredentialBundle(leaf, List.of());
    }
}
