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
package zeroecho.pki.api.revocation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;

/**
 * Immutable single-file authority for one credential's revocation lifecycle.
 *
 * @param credentialId credential namespace identity
 * @param transitions  ordered committed transitions
 */
public record RevocationJournal(PkiId credentialId, List<RevocationTransition> transitions) {

    /** Current journal format version. */
    public static final int CURRENT_VERSION = 1;

    /**
     * Creates an immutable journal snapshot.
     */
    public RevocationJournal {
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(transitions, "transitions");
        transitions = List.copyOf(transitions);
        validate(transitions);
    }

    private static void validate(List<RevocationTransition> transitions) {
        if (transitions.isEmpty()) {
            throw new IllegalArgumentException("transitions must not be empty");
        }
        RevocationState previous = null;
        Instant previousTime = null;
        long expectedRevision = 1L;
        for (RevocationTransition transition : transitions) {
            if (transition.revision() != expectedRevision
                    || previousTime != null && transition.time().isBefore(previousTime)
                    || !validTransition(previous, transition)) {
                throw new IllegalArgumentException("invalid revocation journal");
            }
            expectedRevision++;
            previous = transition.state();
            previousTime = transition.time();
        }
    }

    private static boolean validTransition(RevocationState previous, RevocationTransition transition) {
        boolean reasonValid = transition.state() == RevocationState.PERMANENTLY_REVOKED
                ? transition.permanentReason().filter(RevocationJournal::isPermanent).isPresent()
                : transition.permanentReason().isEmpty();
        if (!reasonValid || previous == RevocationState.PERMANENTLY_REVOKED) {
            return false;
        }
        if (previous == null) {
            return transition.state() == RevocationState.HELD
                    || transition.state() == RevocationState.PERMANENTLY_REVOKED;
        }
        return switch (previous) {
            case CLEAR ->
                transition.state() == RevocationState.HELD || transition.state() == RevocationState.PERMANENTLY_REVOKED;
            case HELD -> transition.state() == RevocationState.CLEAR
                    || transition.state() == RevocationState.PERMANENTLY_REVOKED;
            case PERMANENTLY_REVOKED -> false;
        };
    }

    private static boolean isPermanent(RevocationReason reason) {
        return reason != RevocationReason.CERTIFICATE_HOLD && reason != RevocationReason.REMOVE_FROM_CRL;
    }

    /**
     * Returns the last committed transition.
     *
     * @return last transition
     * @throws IllegalStateException if the journal is empty
     */
    public RevocationTransition latest() {
        if (transitions.isEmpty()) {
            throw new IllegalStateException("Revocation journal is empty");
        }
        return transitions.get(transitions.size() - 1);
    }

    // Defensive snapshotting necessarily allocates immutable entries while walking
    // the caller-owned attribute collection.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    /* default */ static AttributeSet snapshot(AttributeSet source) {
        Objects.requireNonNull(source, "source");
        List<SnapshotEntry> entries = new ArrayList<>();
        for (AttributeId id : source.ids()) {
            List<AttributeValue> values = new ArrayList<>();
            for (AttributeValue value : source.getAll(id)) {
                values.add(snapshotValue(value));
            }
            entries.add(new SnapshotEntry(id, List.copyOf(values)));
        }
        return new SnapshotAttributeSet(List.copyOf(entries));
    }

    private static AttributeValue snapshotValue(AttributeValue value) {
        Objects.requireNonNull(value, "value");
        if (value instanceof AttributeValue.BytesValue bytesValue) {
            return new AttributeValue.BytesValue(bytesValue.value().clone());
        }
        return value;
    }

    /**
     * One immutable attribute entry owned by the journal.
     */
    private record SnapshotEntry(AttributeId id, List<AttributeValue> values) {
    }

    /**
     * Immutable defensive implementation used for journal metadata ownership.
     */
    private static final class SnapshotAttributeSet implements AttributeSet {
        private final List<SnapshotEntry> entries;

        private SnapshotAttributeSet(List<SnapshotEntry> entries) {
            this.entries = entries;
        }

        @Override
        public Set<AttributeId> ids() {
            Set<AttributeId> ids = new LinkedHashSet<>();
            for (SnapshotEntry entry : entries) {
                ids.add(entry.id());
            }
            return Set.copyOf(ids);
        }

        @Override
        public Optional<AttributeValue> get(AttributeId id) {
            List<AttributeValue> values = getAll(id);
            return values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
        }

        // Byte values are copied per accessor invocation so callers cannot mutate
        // journal-owned storage.
        @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
        @Override
        public List<AttributeValue> getAll(AttributeId id) {
            Objects.requireNonNull(id, "id");
            for (SnapshotEntry entry : entries) {
                if (entry.id().equals(id)) {
                    List<AttributeValue> copies = new ArrayList<>(entry.values().size());
                    for (AttributeValue value : entry.values()) {
                        copies.add(snapshotValue(value));
                    }
                    return List.copyOf(copies);
                }
            }
            return List.of();
        }
    }
}
