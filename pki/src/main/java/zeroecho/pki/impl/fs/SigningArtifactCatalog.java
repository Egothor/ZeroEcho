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
package zeroecho.pki.impl.fs;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Exact owner-created artifact names grouped by generation identity.
 */
@SuppressWarnings({ "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidSynchronizedAtMethodLevel" })
final class SigningArtifactCatalog {
    private final Map<Long, List<Artifact>> byGeneration = new HashMap<>();

    /**
     * Registers one exact artifact name under its immutable generation identity.
     *
     * @param artifact validated generation, local name and closed artifact kind
     * @throws NullPointerException if a required input is null
     * @throws IllegalStateException if the same generation already has that artifact name
     */
    /* default */ synchronized void register(Artifact artifact) {
        Objects.requireNonNull(artifact, "artifact");
        List<Artifact> current = byGeneration.computeIfAbsent(
                artifact.generationIdentity(), ignored -> new ArrayList<>());
        if (current.stream().anyMatch(value -> value.name().equals(artifact.name()))) {
            throw new IllegalStateException("signing artifact is already registered");
        }
        current.add(artifact);
    }

    /**
     * Returns a detached immutable inventory of artifacts registered for one generation.
     *
     * @param generationIdentity exact generation identity to inspect
     * @return immutable artifact list in registration order, or an empty list if none is registered
     */
    /* default */ synchronized List<Artifact> artifacts(long generationIdentity) {
        List<Artifact> artifacts = byGeneration.get(generationIdentity);
        return artifacts == null ? List.of() : List.copyOf(artifacts);
    }

    /**
     * Selects the first registered checkpoint or WAL artifact supporting generation reads.
     *
     * @param generationIdentity exact generation whose physical record source is required
     * @return first readable artifact in registration order
     * @throws IllegalStateException if the generation has no registered checkpoint, sealed WAL or active WAL
     */
    /* default */ synchronized Artifact readable(long generationIdentity) {
        List<Artifact> artifacts = artifacts(generationIdentity);
        for (Artifact artifact : artifacts) {
            if (artifact.kind() == Kind.CHECKPOINT || artifact.kind() == Kind.SEALED_WAL
                    || artifact.kind() == Kind.ACTIVE_WAL) {
                return artifact;
            }
        }
        throw new IllegalStateException("signing generation has no readable artifact");
    }

    /**
     * Removes a generation's inventory after its artifact ownership has been released.
     *
     * @param generationIdentity exact generation identity; an unregistered identity has no effect
     */
    /* default */ synchronized void remove(long generationIdentity) {
        byGeneration.remove(generationIdentity);
    }

    /**
     * Tests whether the catalog retains any registration for one generation.
     *
     * @param generationIdentity exact generation identity to inspect
     * @return true if the generation has a registered inventory entry
     */
    /* default */ synchronized boolean contains(long generationIdentity) {
        return byGeneration.containsKey(generationIdentity);
    }

    /**
     * Closed artifact kinds understood by identity revalidation.
     */
    /* default */ enum Kind {
        /**
         * Self-contained immutable checkpoint.
         */
        CHECKPOINT,
        /**
         * Immutable copied WAL segment.
         */
        SEALED_WAL,
        /**
         * Mutable current WAL path.
         */
        ACTIVE_WAL
    }

    /**
     * Validated artifact identity and closed artifact kind retained during signing-ledger discovery.
     *
     * @param generationIdentity exact immutable artifact generation identity
     * @param name validated store-local artifact name
     * @param kind closed Kind discriminator
     */
    /* default */ record Artifact(long generationIdentity, String name, Kind kind) {
        /**
         * Creates the validated artifact identity and closed artifact kind retained during signing-ledger discovery.
         *
         * @param generationIdentity exact immutable artifact generation identity
         * @param name validated store-local artifact name
         * @param kind closed Kind discriminator
         * @throws IllegalArgumentException if {@code (generationIdentity < 0L)}; or if {@code (!name.equals(canonicalName(generationIdentity, name, kind)))}
         * @throws NullPointerException if {@code name} is null; or if {@code kind} is null
         */
        Artifact {
            if (generationIdentity < 0L) {
                throw new IllegalArgumentException("signing artifact generation is invalid");
            }
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(kind, "kind");
            if (!name.equals(canonicalName(generationIdentity, name, kind))) {
                throw new IllegalArgumentException("signing artifact name is not canonical");
            }
        }

        private static String canonicalName(long identity, String name, Kind kind) {
            if (kind == Kind.ACTIVE_WAL) {
                return SigningManifestCodec.activeName(identity);
            }
            String prefix = kind == Kind.CHECKPOINT ? "checkpoint-" : "wal-";
            String suffix = kind == Kind.CHECKPOINT ? ".zec" : ".zew";
            int expectedLength = prefix.length() + 41 + suffix.length();
            if (name.length() != expectedLength || !name.startsWith(prefix)
                    || !name.endsWith(suffix) || name.charAt(prefix.length() + 20) != '-') {
                return "";
            }
            for (int index = prefix.length(); index < name.length() - suffix.length(); index++) {
                if (index == prefix.length() + 20) {
                    continue;
                }
                char value = name.charAt(index);
                if (value < '0' || value > '9') {
                    return "";
                }
            }
            return name;
        }
    }
}
