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
package zeroecho.pki.server.enrollment;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory enrollment profile registry.
 *
 * <p>Individual map reads and replacements are thread-safe. Compound updates
 * are not compare-and-set transactions: concurrent updates can overwrite each
 * other. Coordinate writers externally when transitions must be serialized.
 * The registry is process-local and does not survive restart.</p>
 *
 * @since 1.0
 */
public final class EnrollmentProfileService {

    private final ConcurrentMap<String, EnrollmentProfile> profiles = new ConcurrentHashMap<>();

    /** Creates an empty process-local registry. */
    public EnrollmentProfileService() {
        super();
    }

    /**
     * Registers a profile, replacing any existing record with the same identifier.
     * @param profile non-null immutable profile to retain
     */
    public void register(EnrollmentProfile profile) {
        Objects.requireNonNull(profile, "profile");
        profiles.put(profile.id(), profile);
    }

    /**
     * Updates an existing enrollment profile.
     *
     * @param profile non-null replacement profile
     * @return the supplied replacement; a concurrent writer may replace it again
     * @throws IllegalArgumentException if no profile with the given id exists
     */
    public EnrollmentProfile update(EnrollmentProfile profile) {
        Objects.requireNonNull(profile, "profile");
        if (!profiles.containsKey(profile.id())) {
            throw new IllegalArgumentException("Enrollment profile not found: " + profile.id());
        }
        profiles.put(profile.id(), profile);
        return profile;
    }

    /**
     * Looks up the current profile by identifier.
     * @param id non-null identifier
     * @return the observed profile, or empty if absent
     */
    public Optional<EnrollmentProfile> find(String id) {
        return Optional.ofNullable(profiles.get(Objects.requireNonNull(id, "id")));
    }

    /**
     * Copies the profiles observed during a weakly consistent traversal.
     * Concurrent updates need not be reflected as one atomic point-in-time view.
     * @return an immutable list in unspecified order
     */
    public List<EnrollmentProfile> list() {
        return List.copyOf(profiles.values());
    }

    /**
     * Transitions the profile to the given state.
     *
     * @param id non-null profile identifier
     * @param state non-null replacement state
     * @return the newly stored profile; concurrent writers may overwrite it
     * @throws IllegalArgumentException if no profile with the given id exists
     */
    public EnrollmentProfile setState(String id, EnrollmentProfileState state) { // NOPMD LinguisticNaming - Public atomic state transition returns the stored immutable profile; preserve consumer API.
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(state, "state");
        EnrollmentProfile existing = profiles.get(id);
        if (existing == null) {
            throw new IllegalArgumentException("Enrollment profile not found: " + id);
        }
        EnrollmentProfile updated = existing.withState(state);
        profiles.put(id, updated);
        return updated;
    }
}
