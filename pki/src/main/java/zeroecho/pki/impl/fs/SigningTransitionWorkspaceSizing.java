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

/**
 * Pure conservative sizing proof for concurrently prepared signing transitions.
 */
@SuppressWarnings("PMD.LongVariable") // Proof terms remain explicit and auditable.
final class SigningTransitionWorkspaceSizing {
    private static final int DOUBLE_ROTATION_EXTRA_NODES = 5;

    private SigningTransitionWorkspaceSizing() {
        // utility class
    }

    /**
     * Returns the greatest valid AVL height for the supplied entry bound.
     *
     * <p>With empty height zero and leaf height one, the minimum population is
     * {@code N(h) = 1 + N(h - 1) + N(h - 2)}. Therefore every configured tree
     * has height at most the last {@code h} whose minimum population fits.</p>
     * @param maximumRootEntries positive maximum population of the configured AVL root
     * @return greatest possible AVL height using empty height zero and leaf height one
     * @throws IllegalArgumentException if maximumRootEntries is nonpositive
     */
    /* default */ static int maximumAvlHeight(int maximumRootEntries) {
        if (maximumRootEntries <= 0) {
            throw new IllegalArgumentException("maximum root entries must be positive");
        }
        long twoBelow = 0L;
        long oneBelow = 1L;
        int height = 1;
        while (true) {
            long next = Math.addExact(1L, Math.addExact(oneBelow, twoBelow));
            if (next > maximumRootEntries) {
                return height;
            }
            twoBelow = oneBelow;
            oneBelow = next;
            height = Math.incrementExact(height);
        }
    }

    /**
     * Derives the protected accepted-transition workspace floor for one
     * configuration. Ordinary generic, administrative, and retention work is
     * deliberately excluded and must be rejected before WAL admission when the
     * unprotected steady capacity cannot prepare it.
     *
     * <p>An insertion copies at most {@code h + 1} search-path nodes and one
     * double rebalance adds at most five nodes. Replacement copies at most
     * {@code h} nodes and cannot change subtree heights. Deletion performs at
     * most {@code h - 1} allocation-bearing balance levels; each level allocates
     * its path-copy node plus at most five nodes for a double rotation.</p>
     * @param maximumRootEntries positive maximum population of the configured AVL root
     * @param maximumConcurrentPreparedTransitions positive prepared-transition count within the WAL queue limit
     * @return protected admission derivation with node bounds and byte floors for accepted transitions
     * @throws IllegalArgumentException if population or concurrency bounds are invalid
     * @throws ArithmeticException if workspace arithmetic exceeds its integer/long range
     */
    /* default */ static Derivation derive(int maximumRootEntries,
            int maximumConcurrentPreparedTransitions) {
        if (maximumConcurrentPreparedTransitions <= 0
                || maximumConcurrentPreparedTransitions
                        > SigningActiveWal.MAXIMUM_QUEUE_CAPACITY) {
            throw new IllegalArgumentException(
                    "maximum concurrently prepared transitions is invalid");
        }
        int height = maximumAvlHeight(maximumRootEntries);
        int insertNodes = Math.addExact(height,
                Math.addExact(1, DOUBLE_ROTATION_EXTRA_NODES));
        int replaceNodes = height;
        int deleteNodes = Math.multiplyExact(Math.max(0, height - 1),
                Math.addExact(1, DOUBLE_ROTATION_EXTRA_NODES));
        long maximumTransitionNodes = 0L;
        Transition maximumTransition = null;
        for (Transition transition : Transition.values()) {
            long nodes = transition.maximumNodes(insertNodes, replaceNodes, deleteNodes);
            if (nodes > maximumTransitionNodes) {
                maximumTransitionNodes = nodes;
                maximumTransition = transition;
            }
        }
        long bytesPerTransition = Math.multiplyExact(
                maximumTransitionNodes, SigningMvccIndex.ORDERED_NODE_BYTES);
        long floorBytes = Math.multiplyExact(
                bytesPerTransition, maximumConcurrentPreparedTransitions);
        return new Derivation(AdmissionClass.PROTECTED_ACCEPTED_SIGNING,
                maximumRootEntries, height, insertNodes, replaceNodes,
                deleteNodes, maximumConcurrentPreparedTransitions,
                maximumTransition, maximumTransitionNodes, bytesPerTransition, floorBytes);
    }

    /**
     * Derives the largest retention-purge preparation admitted by its current batch bound.
     * @param maximumRootEntries positive maximum population of the configured AVL root
     * @return ordinary retention-purge mutation, node, and byte workspace derivation
     * @throws IllegalArgumentException if maximumRootEntries is nonpositive
     * @throws ArithmeticException if workspace arithmetic exceeds its integer/long range
     */
    /* default */ static OrdinaryDerivation deriveRetentionPurge(int maximumRootEntries) {
        int height = maximumAvlHeight(maximumRootEntries);
        int replaceNodes = height;
        int deleteNodes = Math.multiplyExact(Math.max(0, height - 1),
                Math.addExact(1, DOUBLE_ROTATION_EXTRA_NODES));
        int records = SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS / 3;
        int deletes = SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS;
        int replacements = 1; // Engine-added watermark; purge uses direct commit.
        long nodes = Math.addExact(Math.multiplyExact((long) deletes, deleteNodes),
                Math.multiplyExact((long) replacements, replaceNodes));
        long bytes = Math.multiplyExact(nodes, SigningMvccIndex.ORDERED_NODE_BYTES);
        return new OrdinaryDerivation(OrdinaryOperation.RETENTION_PURGE,
                AdmissionClass.ORDINARY, records, deletes, replacements, nodes, bytes);
    }

    /**
     * Accepted and post-invocation lifecycle paths and their maximum semantic
     * index operations, including engine-added outcome and watermark mutations.
     */
    /* default */ enum Transition {
        /**
         * Creates an ordinary signing intent.
         */
        CREATE_INTENT(3, 1, 0),
        /**
         * Creates a signing intent linked to a domain continuation.
         */
        CREATE_INTENT_WITH_DOMAIN(4, 1, 0),
        /**
         * Creates a signing intent with correlated domain admission.
         */
        CREATE_INTENT_WITH_CORRELATED_DOMAIN(5, 1, 0),
        /**
         * Creates composite CA signing with correlated domain admission.
         */
        CREATE_COMPOSITE_CA_WITH_CORRELATED_DOMAIN(6, 1, 0),
        /**
         * Accepts local signing and its associated metadata atomically.
         */
        ATOMIC_LOCAL_ACCEPTANCE(3, 0, 0),
        /**
         * Advances a retained domain continuation.
         */
        DOMAIN_CONTINUATION(0, 3, 0),
        /**
         * Claims, renews or reconciles signing provider work.
         */
        CLAIM_RENEW_OR_RECONCILE(0, 3, 0),
        /**
         * Records direct cancellation without another provider dispatch.
         */
        DIRECT_CANCEL(0, 2, 0),
        /**
         * Commits the primary terminal transition.
         */
        TERMINAL_PRIMARY(0, 2, 0),
        /**
         * Commits the terminal expiry fallback.
         */
        TERMINAL_EXPIRY_FALLBACK(0, 2, 1),
        /**
         * Expires signing whose authoritative deadline elapsed.
         */
        DEADLINE_EXPIRY(0, 3, 1),
        /**
         * Retires terminal signing content and lifecycle state.
         */
        RETIREMENT(0, 3, 1);

        private final int inserts;
        private final int replacements;
        private final int deletes;

        Transition(int inserts, int replacements, int deletes) {
            this.inserts = inserts;
            this.replacements = replacements;
            this.deletes = deletes;
        }

        /**
         * Counts the semantic insert, replace, and delete mutations required by this accepted transition.
         *
         * @return total semantic mutation count
         * @throws ArithmeticException if the combined count exceeds the integer range
         */
        /* default */ int semanticMutations() {
            return Math.addExact(inserts, Math.addExact(replacements, deletes));
        }

        /**
         * Computes the worst-case persistent AVL node copies for this transition.
         *
         * @param insertionNodes maximum nodes allocated by one insertion
         * @param replacementNodes maximum nodes allocated by one value replacement
         * @param deletionNodes maximum nodes allocated by one deletion
         * @return sum of per-operation bounds weighted by this transition's mutation counts
         * @throws ArithmeticException if weighted node arithmetic exceeds the long range
         */
        /* default */ long maximumNodes(int insertionNodes,
                int replacementNodes, int deletionNodes) {
            long result = Math.multiplyExact((long) inserts, insertionNodes);
            result = Math.addExact(result,
                    Math.multiplyExact((long) replacements, replacementNodes));
            return Math.addExact(result,
                    Math.multiplyExact((long) deletes, deletionNodes));
        }

        /**
         * Returns the protected accepted-signing admission class used by every transition in this enum.
         *
         * @return protected accepted-signing admission class used by every transition in this enum
         */
        /* default */ AdmissionClass admissionClass() {
            return AdmissionClass.PROTECTED_ACCEPTED_SIGNING;
        }
    }

    /**
     * Work that must never consume the accepted-signing transition floor.
     */
    /* default */ enum OrdinaryOperation {
        /**
         * Ordinary metadata work without a protected accepted-signing reservation.
         */
        GENERIC_METADATA,
        /**
         * Administrative repair work admitted under the ordinary operation budget.
         */
        ADMIN_REPAIR,
        /**
         * Retention purge work admitted under the ordinary operation budget.
         */
        RETENTION_PURGE;

        /**
         * Returns the ordinary admission class used by every operation in this enum.
         *
         * @return ordinary admission class used by every operation in this enum
         */
        /* default */ AdmissionClass admissionClass() {
            return AdmissionClass.ORDINARY;
        }
    }

    /**
     * Future admission ownership encoded by this sizing proof.
     */
    /* default */ enum AdmissionClass {
        /**
         * Work required to advance an already accepted signing operation.
         */
        PROTECTED_ACCEPTED_SIGNING,
        /**
         * Work without an accepted-signing progress reservation.
         */
        ORDINARY
    }

    /**
     * Immutable output of the pure sizing derivation.
     * @param admissionClass capacity admission class used by the derivation
     * @param maximumRootEntries maximum permitted number of root entries
     * @param maximumAvlHeight derived maximum AVL tree height
     * @param maximumInsertionNodes maximum persistent nodes allocated by one insertion
     * @param maximumReplacementNodes maximum persistent nodes allocated by one replacement
     * @param maximumDeletionNodes maximum persistent nodes allocated by one deletion
     * @param maximumConcurrentPreparedTransitions maximum number of concurrently prepared transitions
     * @param maximumTransition transition producing the maximum protected workspace demand
     * @param maximumNodesPerTransition maximum persistent nodes allocated by one protected transition
     * @param maximumBytesPerTransition maximum accounted bytes required by one protected transition
     * @param workspaceFloorBytes derived minimum protected workspace reservation in bytes
     */
    /* default */ record Derivation(AdmissionClass admissionClass,
            int maximumRootEntries, int maximumAvlHeight,
            int maximumInsertionNodes, int maximumReplacementNodes,
            int maximumDeletionNodes, int maximumConcurrentPreparedTransitions,
            Transition maximumTransition, long maximumNodesPerTransition,
            long maximumBytesPerTransition, long workspaceFloorBytes) {
    }

    /**
     * Separate evidence for ordinary purge rejection; never part of the protected floor.
     * @param operation ordinary operation category being sized
     * @param admissionClass capacity admission class used by the derivation
     * @param maximumRecords maximum records affected by the operation
     * @param deletes number of deletions included by the sizing model
     * @param replacements number of replacements included by the sizing model
     * @param maximumNodes derived maximum persistent node allocation
     * @param maximumBytes inclusive configured byte reservation limit
     */
    /* default */ record OrdinaryDerivation(OrdinaryOperation operation,
            AdmissionClass admissionClass, int maximumRecords, int deletes,
            int replacements, long maximumNodes, long maximumBytes) {
    }
}
