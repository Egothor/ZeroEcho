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
package zeroecho.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Helper routines for catalog selection by family and roles.
 *
 * <h2>Purpose</h2> This final static nested class provides reusable filtering
 * helpers over {@code CryptoAlgorithms} that can be shared by other CLI
 * utilities. The selection logic iterates the discovered algorithm identifiers
 * and checks metadata exposed by {@code CryptoAlgorithm}.
 */
public final class CatalogSelector {

    private CatalogSelector() {
        // no instances
    }

    /**
     * Returns algorithm ids that belong to the given family and contain all
     * required roles.
     *
     * @param family          required {@link AlgorithmFamily}
     * @param requireAllRoles set of {@link KeyUsage} roles that must be supported
     * @return list of matching algorithm ids in discovery order
     * @throws NullPointerException if {@code family} or {@code requireAllRoles} is
     *                              null
     */
    public static List<String> selectByFamilyAndRoles(AlgorithmFamily family, Collection<KeyUsage> requireAllRoles) {
        Objects.requireNonNull(family, "family");
        Objects.requireNonNull(requireAllRoles, "requireAllRoles");
        List<String> out = new ArrayList<>();
        Set<String> ids = CryptoAlgorithms.available();
        for (String id : ids) {
            CryptoAlgorithm alg = CryptoAlgorithms.require(id);
            boolean familyMatch = alg.listCapabilities().stream().anyMatch(c -> c.family() == family);
            if (!familyMatch) {
                continue;
            }
            if (!alg.roles().containsAll(requireAllRoles)) {
                continue;
            }
            out.add(id);
        }
        return out;
    }

    /**
     * Returns algorithm ids that belong to the given family, regardless of roles.
     *
     * @param family required {@link AlgorithmFamily}
     * @return list of matching algorithm ids in discovery order
     */
    public static List<String> selectByFamily(AlgorithmFamily family) {
        return selectByFamilyAndRoles(family, EnumSet.noneOf(KeyUsage.class));
    }

    /**
     * Returns algorithm ids that contain all the given roles, regardless of family.
     *
     * @param requireAllRoles set of roles to be present
     * @return list of matching algorithm ids in discovery order
     */
    public static List<String> selectByRoles(Collection<KeyUsage> requireAllRoles) {
        Objects.requireNonNull(requireAllRoles, "requireAllRoles");
        List<String> out = new ArrayList<>();
        Set<String> ids = CryptoAlgorithms.available();
        for (String id : ids) {
            CryptoAlgorithm alg = CryptoAlgorithms.require(id);
            if (alg.roles().containsAll(requireAllRoles)) {
                out.add(id);
            }
        }
        return out;
    }
}
