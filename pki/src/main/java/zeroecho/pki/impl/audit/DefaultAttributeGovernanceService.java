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
package zeroecho.pki.impl.audit;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.attr.AttributeAccessPolicy;
import zeroecho.pki.api.attr.AttributeCatalogue;
import zeroecho.pki.api.attr.AttributeDefinition;
import zeroecho.pki.api.attr.AttributeExportTarget;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSensitivity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AccessAction;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.AccessDecision;
import zeroecho.pki.api.audit.AttributeAccessController;
import zeroecho.pki.api.audit.AttributeGovernanceService;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditService;

/**
 * Default enforcement implementation of {@link AttributeGovernanceService}.
 *
 * <p>
 * This component acts as a Policy Enforcement Point (PEP). For attribute
 * operations it:
 * </p>
 * <ol>
 * <li>resolves attribute metadata from {@link AttributeCatalogue},</li>
 * <li>obtains a decision from {@link AttributeAccessController} (PDP),</li>
 * <li>enforces allow/deny deterministically,</li>
 * <li>emits audit events via {@link AuditService} (if configured by
 * policy).</li>
 * </ol>
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li><strong>No secrets in audit:</strong> audit {@link AuditEvent#details()}
 * contains only metadata. Attribute values are never included.</li>
 * <li><strong>Deterministic time:</strong> timestamps are sourced from an
 * injected {@link Clock}.</li>
 * <li><strong>Export redaction:</strong> non-public attributes are
 * deterministically redacted during export.</li>
 * </ul>
 *
 * <h2>Logging</h2>
 * <p>
 * This class logs operational failures (e.g., PDP throws) and unexpected
 * states, but never logs attribute values.
 * </p>
 */
public final class DefaultAttributeGovernanceService implements AttributeGovernanceService {

    private static final Logger LOGGER = Logger.getLogger(DefaultAttributeGovernanceService.class.getName());
    private static final String CATEGORY = "ATTRIBUTE_GOVERNANCE";

    private final AttributeAccessController accessController;
    private final AuditService auditService;
    private final Clock clock;

    /**
     * Creates a governance service.
     *
     * @param accessController decision point (PDP)
     * @param auditService     audit service for recording decisions
     * @param clock            time source
     * @throws IllegalArgumentException if any argument is null
     */
    public DefaultAttributeGovernanceService(AttributeAccessController accessController, AuditService auditService,
            Clock clock) {
        if (accessController == null) {
            throw new IllegalArgumentException("accessController must not be null");
        }
        if (auditService == null) {
            throw new IllegalArgumentException("auditService must not be null");
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock must not be null");
        }
        this.accessController = accessController;
        this.auditService = auditService;
        this.clock = clock;

        LOGGER.log(Level.INFO, "DefaultAttributeGovernanceService initialized.");
    }

    @Override
    public Optional<AttributeValue> read(AttributeCatalogue catalogue, AttributeSet set, AttributeId id,
            AccessContext context) {
        Objects.requireNonNull(catalogue, "catalogue");
        Objects.requireNonNull(set, "set");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(context, "context");

        Optional<AttributeDefinition> definition = catalogue.find(id);
        if (definition.isEmpty()) {
            LOGGER.log(Level.FINE, "Attribute not found in catalogue; denying READ.");
            auditIfConfigured(null, id, AccessAction.READ, context, AccessDecision.DENY);
            return Optional.empty();
        }

        AccessDecision decision = decideSafely(definition.get(), AccessAction.READ, context);
        auditIfConfigured(definition.get(), id, AccessAction.READ, context, decision);

        if (decision != AccessDecision.ALLOW) {
            return Optional.empty();
        }

        return set.get(id);
    }

    @Override
    public AttributeSet write(AttributeCatalogue catalogue, AttributeSet set, AttributeId id, AttributeValue value,
            AccessContext context) {
        Objects.requireNonNull(catalogue, "catalogue");
        Objects.requireNonNull(set, "set");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(context, "context");

        Optional<AttributeDefinition> definition = catalogue.find(id);
        if (definition.isEmpty()) {
            LOGGER.log(Level.FINE, "Attribute not found in catalogue; denying WRITE.");
            auditIfConfigured(null, id, AccessAction.WRITE, context, AccessDecision.DENY);
            return set;
        }

        AccessDecision decision = decideSafely(definition.get(), AccessAction.WRITE, context);
        auditIfConfigured(definition.get(), id, AccessAction.WRITE, context, decision);

        if (decision != AccessDecision.ALLOW) {
            return set;
        }

        return AttributeSetCopies.withSingleValue(set, id, value);
    }

    @Override
    public Optional<AttributeValue> export(AttributeCatalogue catalogue, AttributeSet set, AttributeId id,
            AccessContext context) {
        Objects.requireNonNull(catalogue, "catalogue");
        Objects.requireNonNull(set, "set");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(context, "context");

        Optional<AttributeDefinition> definition = catalogue.find(id);
        if (definition.isEmpty()) {
            LOGGER.log(Level.FINE, "Attribute not found in catalogue; denying EXPORT.");
            auditIfConfigured(null, id, AccessAction.EXPORT, context, AccessDecision.DENY);
            return Optional.empty();
        }

        AccessDecision decision = decideSafely(definition.get(), AccessAction.EXPORT, context);
        if (decision == AccessDecision.ALLOW) {
            AttributeAccessPolicy policy = definition.get().accessPolicy();
            if (!isExportTargetAllowed(policy, context)) {
                decision = AccessDecision.DENY;
            }
        }

        auditIfConfigured(definition.get(), id, AccessAction.EXPORT, context, decision);

        if (decision != AccessDecision.ALLOW) {
            return Optional.empty();
        }

        Optional<AttributeValue> value = set.get(id);
        if (value.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(redactForExport(definition.get().sensitivity(), value.get()));
    }

    @Override
    public AttributeSet derive(AttributeCatalogue catalogue, AttributeSet set, AttributeId id, AccessContext context) {
        Objects.requireNonNull(catalogue, "catalogue");
        Objects.requireNonNull(set, "set");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(context, "context");

        Optional<AttributeDefinition> definition = catalogue.find(id);
        if (definition.isEmpty()) {
            LOGGER.log(Level.FINE, "Attribute not found in catalogue; denying DERIVE.");
            auditIfConfigured(null, id, AccessAction.DERIVE, context, AccessDecision.DENY);
            return set;
        }

        AccessDecision decision = decideSafely(definition.get(), AccessAction.DERIVE, context);
        auditIfConfigured(definition.get(), id, AccessAction.DERIVE, context, decision);

        if (decision != AccessDecision.ALLOW) {
            return set;
        }

        Optional<AttributeValue> existing = set.get(id);
        if (existing.isPresent()) {
            return set;
        }

        // Baseline deterministic derivation (no domain logic; does not use secrets).
        AttributeValue derived = new AttributeValue.StringValue("derived:" + id.value());
        return AttributeSetCopies.withSingleValue(set, id, derived);
    }

    /**
     * Wraps PDP decision with defensive error handling.
     *
     * @param definition attribute definition
     * @param action     access action
     * @param context    access context
     * @return PDP decision or DENY on failure
     */
    private AccessDecision decideSafely(AttributeDefinition definition, AccessAction action, AccessContext context) {
        try {
            return accessController.decide(definition, action, context);
        } catch (RuntimeException ex) { // NOPMD
            // Never log attribute value; only operational message.
            LOGGER.log(Level.SEVERE, "Access controller failed; defaulting to DENY.", ex);
            return AccessDecision.DENY;
        }
    }

    /**
     * Emits an audit record if configured by policy.
     *
     * <p>
     * Only metadata is recorded. No attribute values are included.
     * </p>
     *
     * @param definitionOrNull attribute definition or null if unknown attribute
     * @param id               attribute id
     * @param action           access action
     * @param context          access context
     * @param decision         access decision
     */
    private void auditIfConfigured(AttributeDefinition definitionOrNull, AttributeId id, AccessAction action,
            AccessContext context, AccessDecision decision) {

        boolean audit = shouldAudit(definitionOrNull, decision);
        if (!audit) {
            return;
        }

        Instant now = clock.instant();

        Map<String, String> details = new HashMap<>();
        details.put("attributeId", id.value());
        details.put("decision", decision.name());
        details.put("principalType", context.principal().type());
        details.put("principalName", context.principal().name());
        details.put("purpose", context.purpose().value());
        details.put("sensitivity", definitionOrNull != null ? definitionOrNull.sensitivity().name() : "UNKNOWN");

        AuditEvent event = new AuditEvent(now, CATEGORY, action.name(), context.principal(), context.purpose(),
                context.objectId(), context.formatId(), Map.copyOf(details));

        auditService.record(event);
    }

    private static boolean shouldAudit(AttributeDefinition definitionOrNull, AccessDecision decision) {
        if (definitionOrNull == null) {
            // Unknown attribute accesses are always audited.
            return true;
        }

        AttributeAccessPolicy policy = definitionOrNull.accessPolicy();
        if (decision == AccessDecision.ALLOW) {
            return policy.auditOnAllow();
        }
        return policy.auditOnDeny();
    }

    private static boolean isExportTargetAllowed(AttributeAccessPolicy policy, AccessContext context) {
        if (policy.exportTargets().isEmpty()) {
            return false;
        }

        // Baseline mapping: Purpose.value() -> AttributeExportTarget.name()
        // (case-insensitive).
        String purpose = context.purpose().value().trim().toUpperCase(Locale.ROOT);
        for (AttributeExportTarget allowed : policy.exportTargets()) {
            if (allowed.name().equalsIgnoreCase(purpose)) {
                return true;
            }
        }
        return false;
    }

    private static AttributeValue redactForExport(AttributeSensitivity sensitivity, AttributeValue value) {
        if (sensitivity == AttributeSensitivity.PUBLIC) {
            return value;
        }

        // AttributeValue is sealed; the switch is exhaustive — no default needed.
        return switch (value) {
            case AttributeValue.StringValue  ignored -> new AttributeValue.StringValue("[REDACTED]");
            case AttributeValue.BooleanValue ignored -> new AttributeValue.BooleanValue(false);
            case AttributeValue.IntegerValue ignored -> new AttributeValue.IntegerValue(0L);
            case AttributeValue.InstantValue ignored -> new AttributeValue.InstantValue(Instant.EPOCH);
            // BytesValue requires a non-empty array; use a single zero byte as sentinel.
            case AttributeValue.BytesValue   ignored -> new AttributeValue.BytesValue(new byte[]{0});
        };
    }

    /**
     * Internal helper for producing immutable {@link AttributeSet} copies with
     * modifications.
     */
    /* default */ static final class AttributeSetCopies {

        private AttributeSetCopies() {
        }

        /**
         * Returns a new set with exactly one value stored under the given id (replacing
         * existing values).
         *
         * @param input original set
         * @param id    attribute id
         * @param value attribute value
         * @return new immutable attribute set
         */
        /* default */ static AttributeSet withSingleValue(AttributeSet input, AttributeId id, AttributeValue value) {
            Map<AttributeId, List<AttributeValue>> map = new HashMap<>();
            for (AttributeId existingId : input.ids()) {
                List<AttributeValue> values = input.getAll(existingId);
                map.put(existingId, List.copyOf(values));
            }
            map.put(id, List.of(value));
            return new MapBackedAttributeSet(Map.copyOf(map));
        }
    }

    /**
     * Immutable, map-backed {@link AttributeSet} implementation used by this
     * reference PEP.
     */
    /* default */ static final class MapBackedAttributeSet implements AttributeSet {

        private final Map<AttributeId, List<AttributeValue>> values;

        /**
         * Creates a new attribute set backed by an immutable map.
         *
         * @param values attribute storage map
         */
        /* default */ MapBackedAttributeSet(Map<AttributeId, List<AttributeValue>> values) {
            this.values = Objects.requireNonNull(values, "values");
        }

        @Override
        public java.util.Set<AttributeId> ids() {
            return values.keySet();
        }

        @Override
        public Optional<AttributeValue> get(AttributeId id) {
            Objects.requireNonNull(id, "id");
            List<AttributeValue> list = values.get(id);
            if (list == null || list.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(list.get(0));
        }

        @Override
        public List<AttributeValue> getAll(AttributeId id) {
            Objects.requireNonNull(id, "id");
            List<AttributeValue> list = values.get(id);
            if (list == null) {
                return List.of();
            }
            return List.copyOf(list);
        }
    }
}
