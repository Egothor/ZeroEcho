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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

/**
 * Strict sequential recovery scanner for one durable append-only metadata log.
 */
final class DurableMetadataLogScanner {

    private static final short SEMANTIC_VERSION = 1;
    private static final short RESERVED_SHORT = 0;
    private static final int ID_BYTES = 16;
    private static final int DIGEST_BYTES = 32;
    private static final int STORE_HEADER_BYTES = 2 + 2 + ID_BYTES;
    private static final int ISSUANCE_BYTES = 2 + 2 + ID_BYTES + ID_BYTES;
    private static final int COMMITTED_BYTES = 2 + 2 + ID_BYTES + ID_BYTES + Long.BYTES + DIGEST_BYTES;
    private static final int REJECTED_BYTES = 2 + 2 + ID_BYTES + ID_BYTES + Integer.BYTES + DIGEST_BYTES;
    private static final int RESTART_BYTES = Short.BYTES + Long.BYTES + Long.BYTES
            + Long.BYTES + Short.BYTES;
    private static final long STORE_HEADER_SEQUENCE = 0L;
    private static final long ISSUANCE_SEQUENCE = 0L;
    private static final long FIRST_TRANSACTION_SEQUENCE = 1L;
    private static final long MINIMUM_REVISION = 0L;
    private static final long MINIMUM_COUNT = 0L;
    private static final long NO_MUTATIONS = 0L;
    private static final int MINIMUM_FAILURE_CODE = 1;
    private static final String ZERO_TOKEN = "00000000000000000000000000000000";
    private static final HexFormat LOWERCASE_HEX = HexFormat.of();
    private static final byte[] CHAIN_INITIAL_DOMAIN =
            "zeroecho:pki:posix-metadata-log-chain-initial:v1\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CHAIN_STEP_DOMAIN =
            "zeroecho:pki:posix-metadata-log-chain-step:v1\0".getBytes(StandardCharsets.UTF_8);

    private DurableMetadataLogScanner() {
    }

    /*
     * The scanner is O(log bytes) and keeps O(issued transactions) finite control
     * state. MetadataFrameCodec supplies fixed-buffer payload validation; this
     * scanner reads only exact bounded semantic payloads and 32-byte digests.
    */
    /**
     * Validates the complete structural log and reconstructs finite per-transaction recovery facts.
     *
     * @param channel borrowed seekable source channel; its position may change
     * @return immutable transaction, epoch and complete-prefix recovery facts
     * @throws NullPointerException if a required input is null
     * @throws IOException if framing, integrity, transaction continuity or semantic control records are invalid
     */
    /* default */ static RecoveryResult scan(SeekableByteChannel channel) throws IOException {
        return new ScanEngine(channel).scan();
    }

    /**
     * Validates the complete structural log and reconstructs the current metadata index and terminal outcomes.
     *
     * @param channel borrowed seekable source channel; its position may change
     * @return current-state replay result and its exact recovery boundaries
     * @throws NullPointerException if a required input is null
     * @throws IOException if framing, integrity, transaction continuity or semantic control records are invalid
     */
    /* default */ static ReplayResult replay(SeekableByteChannel channel) throws IOException {
        return new ReplayEngine(channel).replay();
    }

    /**
     * Encodes the exact store identity in its versioned structural header payload.
     *
     * @param storeId validated canonical store identity
     * @return new fixed-size semantic store-header payload
     * @throws NullPointerException if a required input is null
     */
    /* default */ static byte[] encodeStoreHeader(MetadataStoreId storeId) {
        return Semantic.encodeStoreHeader(storeId);
    }

    /**
     * Encodes a store-bound transaction issuance control payload.
     *
     * @param transactionId exact validated transaction identity
     * @return new fixed-size issuance payload
     * @throws NullPointerException if a required input is null
     */
    /* default */ static byte[] encodeIssuance(MetadataTransactionId transactionId) {
        return Semantic.encodeIssuance(transactionId);
    }

    /**
     * Encodes a committed terminal payload binding transaction identity, revision and frame chain.
     *
     * @param transactionId exact validated transaction identity
     * @param revision nonnegative committed metadata revision
     * @param chainState exact 32-byte transaction chain commitment
     * @return new fixed-size committed terminal payload
     * @throws NullPointerException if the transaction identity is null
     * @throws IllegalArgumentException if revision or chain commitment length is invalid
     */
    /* default */ static byte[] encodeCommitted(
            MetadataTransactionId transactionId, long revision, byte[] chainState) {
        return Semantic.encodeCommitted(transactionId, revision, chainState);
    }

    /**
     * Encodes a noncommitted terminal payload binding transaction identity, failure and frame chain.
     *
     * @param transactionId exact validated transaction identity
     * @param failureCode positive stable terminal failure code
     * @param chainState exact 32-byte transaction chain commitment
     * @return new fixed-size rejected terminal payload
     * @throws NullPointerException if the transaction identity is null
     * @throws IllegalArgumentException if the failure code or chain commitment length is invalid
     */
    /* default */ static byte[] encodeRejected(
            MetadataTransactionId transactionId, int failureCode, byte[] chainState) {
        return Semantic.encodeRejected(transactionId, failureCode, chainState);
    }

    /**
     * Encodes recovery epoch advancement and its finite repair counters.
     *
     * @param epoch nonnegative new recovery epoch
     * @param abandonedOpenCount nonnegative number of unfinished transactions abandoned by recovery
     * @param truncatedByteCount nonnegative incomplete-tail length removed in bytes
     * @return new fixed-size recovery restart payload
     * @throws IllegalArgumentException if a coordinate or counter is negative
     */
    /* default */ static byte[] encodeRestart(
            long epoch, long abandonedOpenCount, long truncatedByteCount) {
        return Semantic.encodeRestart(epoch, abandonedOpenCount, truncatedByteCount);
    }

    /**
     * Returns the new initial transaction digest chain state.
     *
     * @return new initial transaction digest chain state
     */
    /* default */ static byte[] initialChainState() {
        return TransactionDigest.initial();
    }

    /**
     * Advances the domain-separated transaction commitment with one exact validated frame.
     *
     * @param channel borrowed source channel used to read authenticated frame evidence
     * @param frame exact validated frame locator
     * @param previousState 32-byte transaction chain commitment preceding this frame
     * @return new 32-byte transaction chain commitment
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the prior chain commitment length is invalid
     * @throws IOException if the exact frame integrity evidence cannot be read
     */
    /* default */ static byte[] advanceChain(
            SeekableByteChannel channel,
            MetadataFrameCodec.FrameMetadata frame,
            byte[] previousState) throws IOException {
        return TransactionDigest.advance(channel, frame, previousState);
    }

    /**
     * Returns the fixed zero transaction token used by structural framing.
     *
     * @return fixed zero transaction token used by structural framing
     */
    /* default */ static String zeroToken() {
        return ZERO_TOKEN;
    }

    private static void requireIssuanceAuthority(
            MetadataStoreId storeId,
            MetadataFrameCodec.FrameMetadata frame,
            MetadataTransactionId transactionId) throws IOException {
        if (!storeId.equals(transactionId.storeId()) || !frame.transactionToken().equals(transactionId.token())) {
            throw integrity("Durable metadata transaction issuance authority is inconsistent");
        }
    }

    private static void requireStoreHeaderShape(MetadataFrameCodec.FrameMetadata header)
            throws MetadataStoreException {
        if (header.frameType() != MetadataFrameCodec.FrameType.STORE_HEADER
                || header.sequence() != STORE_HEADER_SEQUENCE
                || !ZERO_TOKEN.equals(header.transactionToken())) {
            throw integrity("Durable metadata log store header is structurally invalid");
        }
    }

    private static boolean isTransactionPrefix(MetadataFrameCodec.FrameType type) {
        return type == MetadataFrameCodec.FrameType.TRANSACTION_ISSUED || isMutation(type);
    }

    private static boolean isMutation(MetadataFrameCodec.FrameType type) {
        return type == MetadataFrameCodec.FrameType.MUTATION_CREATE
                || type == MetadataFrameCodec.FrameType.MUTATION_REPLACE
                || type == MetadataFrameCodec.FrameType.MUTATION_DELETE;
    }

    private static byte descriptorCode(MetadataFrameCodec.FrameType type) {
        return switch (type) {
            case TRANSACTION_ISSUED -> 1;
            case MUTATION_CREATE -> 2;
            case MUTATION_REPLACE -> 3;
            case MUTATION_DELETE -> 4;
            default -> throw new IllegalArgumentException("Frame type is not part of a durable metadata transaction prefix");
        };
    }

    private static MetadataTransactionId transactionId(MetadataStoreId storeId, String token) {
        return new MetadataTransactionId(storeId, token);
    }

    private static void requireDigest(byte[] digest, String message) {
        if (digest == null || digest.length != DIGEST_BYTES) {
            throw new IllegalArgumentException(message);
        }
    }

    private static int readFully(SeekableByteChannel channel, ByteBuffer target) throws IOException {
        int total = 0;
        while (target.hasRemaining()) {
            int read = channel.read(target);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                throw new IOException("Durable metadata log channel made no read progress");
            }
            total += read;
        }
        return total;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    private static MetadataStoreException integrity(String message) {
        return new MetadataStoreException(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message);
    }

    private static MetadataStoreException integrity(String message, Throwable cause) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message, cause);
    }

    /**
     * Advances a validated recovery epoch without silently wrapping signed arithmetic.
     *
     * @param currentEpoch validated current nonnegative recovery epoch
     * @return next representable recovery epoch
     * @throws MetadataStoreException if incrementing the epoch overflows
     */
    /* default */ static long checkedNextRecoveryEpoch(long currentEpoch)
            throws MetadataStoreException {
        try {
            return Math.addExact(currentEpoch, 1L);
        } catch (ArithmeticException failure) {
            throw integrity("Durable metadata recovery epoch is exhausted", failure);
        }
    }

    /**
     * Physical state of the bytes following the last complete validated frame.
     */
    /* default */ enum Tail {
        /**
         * The scan reached the exact end of the committed log.
         */
        CLEAN_END,
        /**
         * The input ends with a partial frame or record.
         */
        INCOMPLETE_TAIL
    }

    /**
     * Semantic terminal result reconstructed without applying opaque mutations.
     * @param kind closed TerminalKind discriminator
     * @param committedRevision authoritative committed revision, absent when no commit occurred
     * @param failureCode stable terminal failure code, absent when not applicable
     */
    /* default */ record Terminal(TerminalKind kind, OptionalLong committedRevision, OptionalInt failureCode) {
        /**
         * Creates the semantic terminal result reconstructed without applying opaque mutations.
         *
         * @param kind closed TerminalKind discriminator
         * @param committedRevision authoritative committed revision, absent when no commit occurred
         * @param failureCode stable terminal failure code, absent when not applicable
         * @throws NullPointerException if {@code kind} is null; or if {@code committedRevision} is
         * null; or if {@code failureCode} is null
         */
        Terminal {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(committedRevision, "committedRevision");
            Objects.requireNonNull(failureCode, "failureCode");
        }
    }

    /**
     * Closed terminal kinds understood by the current log version.
     */
    /* default */ enum TerminalKind {
        /**
         * The transaction has a retained committed terminal outcome.
         */
        COMMITTED,
        /**
         * The transaction has a retained noncommitted terminal outcome.
         */
        NOT_COMMITTED
    }

    /**
     * Stable internal reasons for synthesized or locally authored rejections.
     */
    /* default */ enum FailureReason {
        /**
         * A transaction conflicts with the authoritative record state.
         */
        TRANSACTION_CONFLICT(1),
        /**
         * Recovery terminated an issued transaction without a committed outcome.
         */
        ABANDONED_BY_RECOVERY(2);

        private final int code;

        /**
         * Associates the closed recovery rejection reason with an explicit persisted code.
         *
         * @param code stable positive code assigned by the enum declaration
         */
        FailureReason(int code) {
            this.code = code;
        }

        /**
         * Returns the stable explicitly assigned terminal failure code.
         *
         * @return stable explicitly assigned terminal failure code
         */
        /* default */ int code() {
            return code;
        }

        /**
         * Resolves a known recovery rejection code without inventing a fallback reason.
         *
         * @param code persisted stable failure code
         * @return matching closed reason, or an empty optional for an unknown code
         */
        /* default */ static Optional<FailureReason> fromCode(int code) {
            for (FailureReason reason : values()) {
                if (reason.code == code) {
                    return Optional.of(reason);
                }
            }
            return Optional.empty();
        }
    }

    /**
     * Exact semantic facts carried by one store-scoped recovery restart.
     */
    private record Restart(long epoch, long abandonedOpenCount, long truncatedByteCount) {
    }

    /**
     * Immutable finite transaction facts reconstructed by recovery.
     * @param transactionId exact durable transaction identity
     * @param mutationCount number of mutations observed for the transaction
     * @param terminal retained terminal result, or empty for an unfinished transaction
     */
    /* default */ record RecoveredTransaction(
            MetadataTransactionId transactionId, long mutationCount, Optional<Terminal> terminal) {
        /**
         * Creates an immutable finite transaction facts reconstructed by recovery.
         *
         * @param transactionId exact durable transaction identity
         * @param mutationCount number of mutations observed for the transaction
         * @param terminal retained terminal result, or empty for an unfinished transaction
         * @throws NullPointerException if {@code transactionId} is null; or if {@code terminal} is null
         * @throws IllegalArgumentException if {@code (mutationCount < MINIMUM_COUNT)}
         */
        RecoveredTransaction {
            Objects.requireNonNull(transactionId, "transactionId");
            Objects.requireNonNull(terminal, "terminal");
            if (mutationCount < MINIMUM_COUNT) {
                throw new IllegalArgumentException("Recovered mutation count must be non-negative");
            }
        }
    }

    /**
     * Complete immutable result of one recovery scan.
     * @param storeId exact authoritative metadata store identity
     * @param lastCompleteFrameBoundary exclusive byte boundary after the last structurally complete frame
     * @param physicalEnd observed physical file length in bytes
     * @param tail classification of bytes after the last complete frame
     * @param transactions recovered per-transaction facts keyed by exact transaction identity
     * @param nextTransactionToken next issuable transaction token, or empty when unavailable
     * @param transactionTokensExhausted whether the transaction-token space has been exhausted
     * @param recoveryEpoch authoritative recovery incarnation
     * @param openTransactionCount number of issued transactions without terminal outcomes
     */
    /* default */ record RecoveryResult(
            MetadataStoreId storeId,
            long lastCompleteFrameBoundary,
            long physicalEnd,
            Tail tail,
            Map<MetadataTransactionId, RecoveredTransaction> transactions,
            Optional<String> nextTransactionToken,
            boolean transactionTokensExhausted,
            long recoveryEpoch,
            long openTransactionCount) {
        /**
         * Creates the complete immutable result of one recovery scan.
         *
         * @param storeId exact authoritative metadata store identity
         * @param lastCompleteFrameBoundary exclusive byte boundary after the last structurally complete frame
         * @param physicalEnd observed physical file length in bytes
         * @param tail classification of bytes after the last complete frame
         * @param transactions recovered per-transaction facts keyed by exact transaction identity
         * @param nextTransactionToken next issuable transaction token, or empty when unavailable
         * @param transactionTokensExhausted whether the transaction-token space has been exhausted
         * @param recoveryEpoch authoritative recovery incarnation
         * @param openTransactionCount number of issued transactions without terminal outcomes
         * @throws NullPointerException if {@code storeId} is null; or if {@code tail} is null; or if
         * {@code transactions} is null; or if {@code nextTransactionToken} is null
         * @throws IllegalArgumentException if {@code (lastCompleteFrameBoundary < MINIMUM_COUNT ||
         * physicalEnd < MINIMUM_COUNT)}; or if {@code (lastCompleteFrameBoundary > physicalEnd)}; or
         * if {@code (tail == Tail.CLEAN_END && lastCompleteFrameBoundary != physicalEnd)}; or if
         * {@code (tail == Tail.INCOMPLETE_TAIL && lastCompleteFrameBoundary >= physicalEnd)}; or if
         * {@code (transactionTokensExhausted && nextTransactionToken.isPresent())}; or if {@code
         * (!transactionTokensExhausted && nextTransactionToken.isEmpty())}; or if {@code
         * (recoveryEpoch < MINIMUM_COUNT || openTransactionCount < MINIMUM_COUNT)}
         */
        RecoveryResult {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(tail, "tail");
            Objects.requireNonNull(transactions, "transactions");
            Objects.requireNonNull(nextTransactionToken, "nextTransactionToken");
            if (lastCompleteFrameBoundary < MINIMUM_COUNT || physicalEnd < MINIMUM_COUNT) {
                throw new IllegalArgumentException("Recovery boundaries must be non-negative");
            }
            if (lastCompleteFrameBoundary > physicalEnd) {
                throw new IllegalArgumentException("Last complete frame boundary exceeds physical end");
            }
            if (tail == Tail.CLEAN_END && lastCompleteFrameBoundary != physicalEnd) {
                throw new IllegalArgumentException("Clean recovery boundary must equal physical end");
            }
            if (tail == Tail.INCOMPLETE_TAIL && lastCompleteFrameBoundary >= physicalEnd) {
                throw new IllegalArgumentException("Incomplete recovery boundary must precede physical end");
            }
            if (transactionTokensExhausted && nextTransactionToken.isPresent()) {
                throw new IllegalArgumentException("Exhausted transaction tokens cannot expose a next token");
            }
            if (!transactionTokensExhausted && nextTransactionToken.isEmpty()) {
                throw new IllegalArgumentException("Available transaction tokens require a next token");
            }
            if (!transactionTokensExhausted) {
                TransactionCounter.recovered(nextTransactionToken, false);
            }
            if (recoveryEpoch < MINIMUM_COUNT || openTransactionCount < MINIMUM_COUNT) {
                throw new IllegalArgumentException("Recovery epoch and open count must be non-negative");
            }
            transactions = Map.copyOf(transactions);
        }
    }

    /**
     * Current-state replay result used only by the internal store engine.
     * @param storeId exact authoritative metadata store identity
     * @param lastCompleteFrameBoundary exclusive byte boundary after the last structurally complete frame
     * @param physicalEnd observed physical file length in bytes
     * @param tail classification of bytes after the last complete frame
     * @param nextTransactionToken next issuable transaction token, or empty when unavailable
     * @param transactionTokensExhausted whether the transaction-token space has been exhausted
     * @param stateIndex reconstructed current-state index
     * @param outcomes retained terminal outcomes keyed by exact transaction identity
     * @param restartOutcomes terminal outcomes established by recovery restart handling
     * @param recoveryEpoch authoritative recovery incarnation
     * @param openTransactionCount number of issued transactions without terminal outcomes
     * @param recoveryFullMapCopies number of full-map copies performed during recovery
     * @param recoveryFinalInstalls number of final reconstructed-state installations
     * @param discardedDescriptorCount number of mutation descriptors discarded during replay
     */
    /* default */ record ReplayResult(
            MetadataStoreId storeId,
            long lastCompleteFrameBoundary,
            long physicalEnd,
            Tail tail,
            Optional<String> nextTransactionToken,
            boolean transactionTokensExhausted,
            MetadataStateIndex stateIndex,
            Map<MetadataTransactionId, Terminal> outcomes,
            Map<MetadataTransactionId, Terminal> restartOutcomes,
            long recoveryEpoch,
            long openTransactionCount,
            long recoveryFullMapCopies,
            long recoveryFinalInstalls,
            long discardedDescriptorCount) {
        /**
         * Creates the current-state replay result used only by the internal store engine.
         *
         * @param storeId exact authoritative metadata store identity
         * @param lastCompleteFrameBoundary exclusive byte boundary after the last structurally complete frame
         * @param physicalEnd observed physical file length in bytes
         * @param tail classification of bytes after the last complete frame
         * @param nextTransactionToken next issuable transaction token, or empty when unavailable
         * @param transactionTokensExhausted whether the transaction-token space has been exhausted
         * @param stateIndex reconstructed current-state index
         * @param outcomes retained terminal outcomes keyed by exact transaction identity
         * @param restartOutcomes terminal outcomes established by recovery restart handling
         * @param recoveryEpoch authoritative recovery incarnation
         * @param openTransactionCount number of issued transactions without terminal outcomes
         * @param recoveryFullMapCopies number of full-map copies performed during recovery
         * @param recoveryFinalInstalls number of final reconstructed-state installations
         * @param discardedDescriptorCount number of mutation descriptors discarded during replay
         * @throws NullPointerException if {@code storeId} is null; or if {@code tail} is null; or if
         * {@code nextTransactionToken} is null; or if {@code stateIndex} is null; or if {@code
         * outcomes} is null; or if {@code restartOutcomes} is null
         * @throws IllegalArgumentException if {@code (recoveryEpoch < MINIMUM_COUNT ||
         * openTransactionCount < MINIMUM_COUNT || recoveryFullMapCopies < MINIMUM_COUNT ||
         * recoveryFinalInstalls < MINIMUM_COUNT || discardedDescriptorCount < MINIMUM_COUNT)}; or if
         * {@code (restartOutcomes.size() != openTransactionCount)}
         */
        ReplayResult {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(tail, "tail");
            Objects.requireNonNull(nextTransactionToken, "nextTransactionToken");
            Objects.requireNonNull(stateIndex, "stateIndex");
            Objects.requireNonNull(outcomes, "outcomes");
            Objects.requireNonNull(restartOutcomes, "restartOutcomes");
            if (recoveryEpoch < MINIMUM_COUNT || openTransactionCount < MINIMUM_COUNT
                    || recoveryFullMapCopies < MINIMUM_COUNT || recoveryFinalInstalls < MINIMUM_COUNT
                    || discardedDescriptorCount < MINIMUM_COUNT) {
                throw new IllegalArgumentException("Replay counters must be non-negative");
            }
            outcomes = Map.copyOf(outcomes);
            restartOutcomes = Map.copyOf(restartOutcomes);
            if (restartOutcomes.size() != openTransactionCount) {
                throw new IllegalArgumentException("Replay restart outcomes must match open transactions");
            }
        }
    }

    /**
     * Unsigned 128-bit scalar counter; zero is reserved and maximum is issued once.
     */
    /* default */ static final class TransactionCounter {
        private static final long ALL_ONES = -1L;
        private static final long ZERO_LIMB = 0L;
        private static final long FIRST_LOW_LIMB = 1L;

        private long high;
        private long low;
        private boolean exhausted;

        private TransactionCounter(long high, long low, boolean exhausted) {
            this.high = high;
            this.low = low;
            this.exhausted = exhausted;
        }

        /**
         * Creates a fresh unsigned 128-bit transaction counter after the reserved zero token.
         *
         * @return new counter whose first issuable token is one
         */
        /* default */ static TransactionCounter first() {
            return new TransactionCounter(ZERO_LIMB, FIRST_LOW_LIMB, false);
        }

        /**
         * Creates a counter from the exact unsigned high and low token limbs.
         *
         * @param high high 64-bit token limb, interpreted as an unsigned bit pattern
         * @param low low 64-bit token limb, interpreted as an unsigned bit pattern
         * @return new counter beginning at the supplied nonzero 128-bit token
         * @throws IllegalArgumentException if both limbs are zero, which is reserved
         */
        /* default */ static TransactionCounter startingAt(long high, long low) {
            if (high == ZERO_LIMB && low == ZERO_LIMB) {
                throw new IllegalArgumentException("Zero Durable metadata transaction token is reserved");
            }
            return new TransactionCounter(high, low, false);
        }

        /**
         * Restores the next transaction token or a permanently exhausted counter from validated recovery facts.
         *
         * @param nextTransactionToken validated exact 32-character lowercase hexadecimal next token,
         * required when not exhausted
         * @param exhausted whether recovery proved the full token space exhausted
         * @return new restored counter
         * @throws NullPointerException if a required input is null
         * @throws java.util.NoSuchElementException if a nonexhausted recovery result omits its next token
         * @throws IllegalArgumentException if hexadecimal token syntax is invalid or the token is zero
         * @throws java.nio.BufferUnderflowException if the supplied nonexhausted token contains fewer than 16 bytes
         */
        /* default */ static TransactionCounter recovered(
                Optional<String> nextTransactionToken, boolean exhausted) {
            Objects.requireNonNull(nextTransactionToken, "nextTransactionToken");
            if (exhausted) {
                return new TransactionCounter(ALL_ONES, ALL_ONES, true);
            }
            byte[] encoded = LOWERCASE_HEX.parseHex(nextTransactionToken.orElseThrow());
            ByteBuffer token = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
            return startingAt(token.getLong(), token.getLong());
        }

        /**
         * Returns the next exact store-bound token and advances the unsigned counter once.
         *
         * @param storeId validated store identity bound into the issued transaction
         * @return fresh transaction identity; issuing the final token permanently exhausts this counter
         * @throws NullPointerException if a required input is null
         * @throws IllegalStateException if the token space is exhausted
         */
        /* default */ MetadataTransactionId issue(MetadataStoreId storeId) {
            Objects.requireNonNull(storeId, "storeId");
            if (exhausted) {
                throw new IllegalStateException("Durable metadata transaction tokens are exhausted");
            }
            String token = encode(high, low);
            advance();
            return new MetadataTransactionId(storeId, token);
        }

        private void observeIssued(String token) throws MetadataStoreException {
            if (exhausted || !encode(high, low).equals(token)) {
                throw integrity("Durable metadata transaction token sequence is not contiguous");
            }
            advance();
        }

        private Optional<String> nextToken() {
            return exhausted ? Optional.empty() : Optional.of(encode(high, low));
        }

        private boolean exhausted() {
            return exhausted;
        }

        private void advance() {
            if (high == ALL_ONES && low == ALL_ONES) {
                exhausted = true;
            } else if (low == ALL_ONES) {
                high++;
                low = ZERO_LIMB;
            } else {
                low++;
            }
        }

        private static String encode(long high, long low) {
            ByteBuffer token = ByteBuffer.allocate(ID_BYTES).order(ByteOrder.BIG_ENDIAN);
            token.putLong(high).putLong(low);
            return LOWERCASE_HEX.formatHex(token.array());
        }
    }

    /**
     * Sequential scanner that owns recovery control state for one invocation.
     */
    private static final class ScanEngine {
        private final SeekableByteChannel channel;
        private final MetadataFrameCodec codec = new MetadataFrameCodec();
        private final long physicalEnd;
        private final Map<MetadataTransactionId, TransactionState> states = new LinkedHashMap<>();
        private final TransactionCounter transactionCounter = TransactionCounter.first();
        private MetadataStoreId storeId;
        private MetadataTransactionId batchTransaction;
        private long recoveryEpoch;

        private ScanEngine(SeekableByteChannel channel) throws IOException {
            this.channel = Objects.requireNonNull(channel, "channel");
            physicalEnd = channel.size();
        }

        private RecoveryResult scan() throws IOException {
            MetadataFrameCodec.ReadResult first = codec.read(channel, 0L);
            if (first.classification() != MetadataFrameCodec.ReadClassification.COMPLETE_FRAME) {
                throw integrity("Durable metadata log has no complete store header");
            }
            MetadataFrameCodec.FrameMetadata header = first.metadata();
            requireStoreHeaderShape(header);
            storeId = Semantic.decodeStoreHeader(channel, header);
            long offset = header.frameEndOffset();
            while (true) {
                MetadataFrameCodec.ReadResult read = codec.read(channel, offset);
                if (read.classification() == MetadataFrameCodec.ReadClassification.END_OF_INPUT) {
                    return recoveryResult(offset, Tail.CLEAN_END);
                }
                if (read.classification() == MetadataFrameCodec.ReadClassification.INCOMPLETE_TAIL) {
                    return recoveryResult(offset, Tail.INCOMPLETE_TAIL);
                }
                if (read.classification() == MetadataFrameCodec.ReadClassification.CORRUPT_FRAME) {
                    throw integrity("Durable metadata log contains a corrupt frame");
                }
                MetadataFrameCodec.FrameMetadata frame = read.metadata();
                processFrame(frame);
                offset = frame.frameEndOffset();
            }
        }

        private void processFrame(MetadataFrameCodec.FrameMetadata frame) throws IOException {
            if (frame.frameType() == MetadataFrameCodec.FrameType.STORE_HEADER) {
                throw integrity("Durable metadata log contains a duplicate store header");
            }
            if (frame.frameType() == MetadataFrameCodec.FrameType.TRANSACTION_ISSUED) {
                processIssuance(frame);
                return;
            }
            if (frame.frameType() == MetadataFrameCodec.FrameType.RECOVERY_RESTART) {
                processRestart(frame);
                return;
            }
            MetadataTransactionId transactionId = transactionId(storeId, frame.transactionToken());
            TransactionState state = states.get(transactionId);
            requireActiveState(state, frame);
            if (isMutation(frame.frameType())) {
                if (batchTransaction == null) {
                    batchTransaction = transactionId;
                } else if (!batchTransaction.equals(transactionId)) {
                    throw integrity("Durable metadata mutation batches are interleaved");
                }
                state.chainState = advanceChain(channel, frame, state.chainState);
                state.mutationCount++;
                state.nextSequence++;
            } else if (frame.frameType() == MetadataFrameCodec.FrameType.TERMINAL_COMMITTED) {
                requireTerminalBatch(transactionId, state.mutationCount);
                state.terminal = Semantic.decodeCommitted(channel, frame, transactionId, state.chainState);
                batchTransaction = null;
            } else if (frame.frameType() == MetadataFrameCodec.FrameType.TERMINAL_NOT_COMMITTED) {
                if (state.mutationCount != NO_MUTATIONS || batchTransaction != null) {
                    throw integrity("Rejected Durable metadata transaction contains mutation frames");
                }
                state.terminal = Semantic.decodeRejected(channel, frame, transactionId, state.chainState);
            } else {
                throw integrity("Durable metadata log contains an unsupported frame type");
            }
        }

        private void requireTerminalBatch(MetadataTransactionId transactionId, long mutationCount)
                throws MetadataStoreException {
            if (mutationCount == NO_MUTATIONS) {
                if (batchTransaction != null) {
                    throw integrity("Empty committed transaction overlaps a mutation batch");
                }
            } else if (!transactionId.equals(batchTransaction)) {
                throw integrity("Committed Durable metadata terminal does not own its mutation batch");
            }
        }

        private void requireActiveState(
                TransactionState state, MetadataFrameCodec.FrameMetadata frame) throws MetadataStoreException {
            if (state == null) {
                throw integrity("Durable metadata log frame names an unknown transaction");
            }
            if (state.terminal != null) {
                throw integrity("Durable metadata log contains a frame after a terminal outcome");
            }
            if (frame.sequence() != state.nextSequence) {
                throw integrity("Durable metadata log transaction sequence is not contiguous");
            }
        }

        private void processIssuance(MetadataFrameCodec.FrameMetadata frame) throws IOException {
            if (frame.sequence() != ISSUANCE_SEQUENCE) {
                throw integrity("Durable metadata transaction issuance sequence is invalid");
            }
            MetadataTransactionId transactionId = Semantic.decodeIssuance(channel, frame);
            requireIssuanceAuthority(storeId, frame, transactionId);
            transactionCounter.observeIssued(transactionId.token());
            TransactionState state = new TransactionState();
            state.chainState = advanceChain(channel, frame, state.chainState);
            states.put(transactionId, state);
        }

        private void processRestart(MetadataFrameCodec.FrameMetadata frame) throws IOException {
            Restart restart = Semantic.decodeRestart(channel, frame);
            long expectedEpoch = checkedNextRecoveryEpoch(recoveryEpoch);
            if (!zeroToken().equals(frame.transactionToken())
                    || frame.sequence() != expectedEpoch
                    || restart.epoch() != expectedEpoch
                    || restart.abandonedOpenCount() != openTransactionCount()) {
                throw integrity("Durable metadata recovery restart is inconsistent");
            }
            for (TransactionState state : states.values()) {
                if (state.terminal == null) {
                    state.terminal = abandonedTerminal();
                }
            }
            batchTransaction = null;
            recoveryEpoch = expectedEpoch;
        }

        private long openTransactionCount() {
            long count = 0L;
            for (TransactionState state : states.values()) {
                if (state.terminal == null) {
                    count++;
                }
            }
            return count;
        }

        private RecoveryResult recoveryResult(long boundary, Tail tail) {
            Map<MetadataTransactionId, RecoveredTransaction> recovered = new LinkedHashMap<>();
            for (Map.Entry<MetadataTransactionId, TransactionState> entry : states.entrySet()) {
                recovered.put(entry.getKey(), recoveredTransaction(entry));
            }
            return new RecoveryResult(
                    storeId, boundary, physicalEnd, tail, recovered,
                    transactionCounter.nextToken(), transactionCounter.exhausted(),
                    recoveryEpoch, openTransactionCount());
        }

        private static RecoveredTransaction recoveredTransaction(
                Map.Entry<MetadataTransactionId, TransactionState> entry) {
            TransactionState state = entry.getValue();
            return new RecoveredTransaction(
                    entry.getKey(), state.mutationCount, Optional.ofNullable(state.terminal));
        }
    }

    /**
     * Streaming semantic replay retaining only active transactions and one batch.
     */
    private static final class ReplayEngine {
        private final SeekableByteChannel channel;
        private final MetadataFrameCodec codec = new MetadataFrameCodec();
        private final long physicalEnd;
        private final Map<MetadataTransactionId, TransactionState> active = new LinkedHashMap<>();
        private final TransactionCounter transactionCounter = TransactionCounter.first();
        private final MetadataStateIndex.RecoveryBuilder recoveryBuilder =
                MetadataStateIndex.recoveryBuilder();
        private final Map<MetadataTransactionId, Terminal> outcomes = new LinkedHashMap<>();
        private final List<MetadataMutationPayloadCodec.Descriptor> batch = new ArrayList<>();
        private MetadataStoreId storeId;
        private MetadataTransactionId batchTransaction;
        private long recoveryEpoch;

        private ReplayEngine(SeekableByteChannel channel) throws IOException {
            this.channel = Objects.requireNonNull(channel, "channel");
            physicalEnd = channel.size();
        }

        private ReplayResult replay() throws IOException {
            MetadataFrameCodec.ReadResult first = codec.read(channel, 0L);
            if (first.classification() != MetadataFrameCodec.ReadClassification.COMPLETE_FRAME) {
                throw integrity("Durable metadata log has no complete store header");
            }
            MetadataFrameCodec.FrameMetadata header = first.metadata();
            requireStoreHeaderShape(header);
            storeId = Semantic.decodeStoreHeader(channel, header);
            long offset = header.frameEndOffset();
            while (true) {
                MetadataFrameCodec.ReadResult read = codec.read(channel, offset);
                if (read.classification() == MetadataFrameCodec.ReadClassification.END_OF_INPUT) {
                    return result(offset, Tail.CLEAN_END);
                }
                if (read.classification() == MetadataFrameCodec.ReadClassification.INCOMPLETE_TAIL) {
                    return result(offset, Tail.INCOMPLETE_TAIL);
                }
                if (read.classification() == MetadataFrameCodec.ReadClassification.CORRUPT_FRAME) {
                    throw integrity("Durable metadata log contains a corrupt frame");
                }
                process(read.metadata());
                offset = read.metadata().frameEndOffset();
            }
        }

        private void process(MetadataFrameCodec.FrameMetadata frame) throws IOException {
            if (frame.frameType() == MetadataFrameCodec.FrameType.STORE_HEADER) {
                throw integrity("Durable metadata log contains a duplicate store header");
            }
            if (frame.frameType() == MetadataFrameCodec.FrameType.TRANSACTION_ISSUED) {
                processIssuance(frame);
                return;
            }
            if (frame.frameType() == MetadataFrameCodec.FrameType.RECOVERY_RESTART) {
                processRestart(frame);
                return;
            }
            MetadataTransactionId transactionId = transactionId(storeId, frame.transactionToken());
            TransactionState state = requireActive(transactionId, frame);
            if (isMutation(frame.frameType())) {
                processMutation(transactionId, state, frame);
            } else if (frame.frameType() == MetadataFrameCodec.FrameType.TERMINAL_COMMITTED) {
                processCommitted(transactionId, state, frame);
            } else if (frame.frameType() == MetadataFrameCodec.FrameType.TERMINAL_NOT_COMMITTED) {
                processRejected(transactionId, state, frame);
            } else {
                throw integrity("Durable metadata log contains an unsupported frame type");
            }
        }

        private void processIssuance(MetadataFrameCodec.FrameMetadata frame) throws IOException {
            if (frame.sequence() != ISSUANCE_SEQUENCE) {
                throw integrity("Durable metadata transaction issuance sequence is invalid");
            }
            MetadataTransactionId transactionId = Semantic.decodeIssuance(channel, frame);
            requireIssuanceAuthority(storeId, frame, transactionId);
            transactionCounter.observeIssued(transactionId.token());
            TransactionState state = new TransactionState();
            state.chainState = advanceChain(channel, frame, state.chainState);
            active.put(transactionId, state);
        }

        private void processRestart(MetadataFrameCodec.FrameMetadata frame) throws IOException {
            Restart restart = Semantic.decodeRestart(channel, frame);
            long expectedEpoch = checkedNextRecoveryEpoch(recoveryEpoch);
            if (!zeroToken().equals(frame.transactionToken())
                    || frame.sequence() != expectedEpoch
                    || restart.epoch() != expectedEpoch
                    || restart.abandonedOpenCount() != active.size()) {
                throw integrity("Durable metadata recovery restart is inconsistent");
            }
            for (MetadataTransactionId transactionId : active.keySet()) {
                outcomes.put(transactionId, abandonedTerminal());
            }
            active.clear();
            batch.clear();
            batchTransaction = null;
            recoveryEpoch = expectedEpoch;
        }

        private TransactionState requireActive(
                MetadataTransactionId transactionId,
                MetadataFrameCodec.FrameMetadata frame) throws MetadataStoreException {
            TransactionState state = active.get(transactionId);
            if (state == null || frame.sequence() != state.nextSequence) {
                throw integrity("Durable metadata log transaction state is not contiguous");
            }
            return state;
        }

        private void processMutation(
                MetadataTransactionId transactionId,
                TransactionState state,
                MetadataFrameCodec.FrameMetadata frame) throws IOException {
            if (batchTransaction == null) {
                batchTransaction = transactionId;
            } else if (!batchTransaction.equals(transactionId)) {
                throw integrity("Durable metadata mutation batches are interleaved");
            }
            batch.add(MetadataMutationPayloadCodec.decode(channel, frame));
            state.chainState = advanceChain(channel, frame, state.chainState);
            state.mutationCount++;
            state.nextSequence++;
        }

        private void processCommitted(
                MetadataTransactionId transactionId,
                TransactionState state,
                MetadataFrameCodec.FrameMetadata frame) throws IOException {
            Terminal terminal = Semantic.decodeCommitted(channel, frame, transactionId, state.chainState);
            requireBatchOwner(transactionId, state.mutationCount);
            try {
                recoveryBuilder.applyCommitted(
                        terminal.committedRevision().orElseThrow(), List.copyOf(batch));
            } catch (MetadataStoreException failure) {
                throw integrity("Committed Durable metadata transaction cannot be reduced", failure);
            }
            outcomes.put(transactionId, terminal);
            finish(transactionId);
        }

        private void processRejected(
                MetadataTransactionId transactionId,
                TransactionState state,
                MetadataFrameCodec.FrameMetadata frame) throws IOException {
            Terminal terminal = Semantic.decodeRejected(channel, frame, transactionId, state.chainState);
            if (state.mutationCount != NO_MUTATIONS || batchTransaction != null) {
                throw integrity("Rejected Durable metadata transaction contains mutation frames");
            }
            outcomes.put(transactionId, terminal);
            finish(transactionId);
        }

        private void requireBatchOwner(MetadataTransactionId transactionId, long mutationCount)
                throws MetadataStoreException {
            if (mutationCount == NO_MUTATIONS) {
                if (batchTransaction != null || !batch.isEmpty()) {
                    throw integrity("Empty committed transaction overlaps a mutation batch");
                }
            } else if (!transactionId.equals(batchTransaction) || batch.size() != mutationCount) {
                throw integrity("Committed Durable metadata mutation batch is inconsistent");
            }
        }

        private void finish(MetadataTransactionId transactionId) {
            active.remove(transactionId);
            batch.clear();
            batchTransaction = null;
        }

        private ReplayResult result(long boundary, Tail tail) {
            MetadataStateIndex stateIndex = recoveryBuilder.finish();
            Map<MetadataTransactionId, Terminal> restartOutcomes = new LinkedHashMap<>();
            for (MetadataTransactionId transactionId : active.keySet()) {
                restartOutcomes.put(transactionId, abandonedTerminal());
            }
            return new ReplayResult(
                    storeId,
                    boundary,
                    physicalEnd,
                    tail,
                    transactionCounter.nextToken(),
                    transactionCounter.exhausted(),
                    stateIndex,
                    outcomes,
                    restartOutcomes,
                    recoveryEpoch,
                    active.size(),
                    recoveryBuilder.fullMapCopyCount(),
                    recoveryBuilder.finalInstallCount(),
                    recoveryBuilder.discardedDescriptorCount());
        }
    }

    private static Terminal abandonedTerminal() {
        return new Terminal(
                TerminalKind.NOT_COMMITTED,
                OptionalLong.empty(),
                OptionalInt.of(FailureReason.ABANDONED_BY_RECOVERY.code()));
    }

    /**
     * Domain-separated digest mechanics for one transaction prefix.
     */
    private static final class TransactionDigest {
        private static byte[] initial() {
            MessageDigest digest = sha256();
            digest.update(CHAIN_INITIAL_DOMAIN);
            return digest.digest();
        }

        private static byte[] advance(
                SeekableByteChannel channel,
                MetadataFrameCodec.FrameMetadata frame,
                byte[] previousState) throws IOException {
            requireDigest(previousState, "Previous Durable metadata transaction chain state is invalid");
            if (!isTransactionPrefix(frame.frameType())) {
                throw new IllegalArgumentException(
                        "Terminal and store-header frames do not advance a transaction chain");
            }
            byte[] payloadDigest = readPayloadDigest(channel, frame);
            ByteBuffer descriptor = ByteBuffer.allocate(1 + ID_BYTES + Long.BYTES + Long.BYTES + DIGEST_BYTES)
                    .order(ByteOrder.BIG_ENDIAN);
            descriptor.put(descriptorCode(frame.frameType()));
            descriptor.put(LOWERCASE_HEX.parseHex(frame.transactionToken()));
            descriptor.putLong(frame.sequence());
            descriptor.putLong(frame.payloadLength());
            descriptor.put(payloadDigest);
            MessageDigest digest = sha256();
            digest.update(CHAIN_STEP_DOMAIN);
            digest.update(previousState);
            digest.update(descriptor.array());
            return digest.digest();
        }

        private static byte[] readPayloadDigest(
                SeekableByteChannel channel, MetadataFrameCodec.FrameMetadata frame) throws IOException {
            ByteBuffer digest = ByteBuffer.allocate(DIGEST_BYTES);
            channel.position(frame.payloadDigestOffset());
            if (readFully(channel, digest) != DIGEST_BYTES) {
                throw integrity("Durable metadata frame payload digest is incomplete");
            }
            channel.position(frame.frameEndOffset());
            return digest.array();
        }
    }

    /**
     * Scanner-confined O(1) state for one issued transaction.
     */
    private static final class TransactionState {
        private byte[] chainState = initialChainState();
        private long nextSequence = FIRST_TRANSACTION_SEQUENCE;
        private long mutationCount;
        private Terminal terminal;
    }

    /**
     * Exact bounded semantic payload schemas; no opaque mutation is decoded here.
     */
    private static final class Semantic {

        private static byte[] encodeStoreHeader(MetadataStoreId storeId) {
            ByteBuffer payload = buffer(STORE_HEADER_BYTES);
            schema(payload);
            payload.put(hex(storeId.value()));
            return payload.array();
        }

        private static byte[] encodeIssuance(MetadataTransactionId transactionId) {
            ByteBuffer payload = buffer(ISSUANCE_BYTES);
            schema(payload);
            transaction(payload, transactionId);
            return payload.array();
        }

        private static byte[] encodeCommitted(
                MetadataTransactionId transactionId, long revision, byte[] chainState) {
            if (revision < MINIMUM_REVISION) {
                throw new IllegalArgumentException("Committed Durable metadata revision must be non-negative");
            }
            requireDigest(chainState, "Durable metadata terminal chain state is invalid");
            ByteBuffer payload = buffer(COMMITTED_BYTES);
            schema(payload);
            transaction(payload, transactionId);
            payload.putLong(revision).put(chainState);
            return payload.array();
        }

        private static byte[] encodeRejected(
                MetadataTransactionId transactionId, int failureCode, byte[] chainState) {
            if (failureCode < MINIMUM_FAILURE_CODE) {
                throw new IllegalArgumentException("Durable metadata failure code must be positive");
            }
            requireDigest(chainState, "Durable metadata terminal chain state is invalid");
            ByteBuffer payload = buffer(REJECTED_BYTES);
            schema(payload);
            transaction(payload, transactionId);
            payload.putInt(failureCode).put(chainState);
            return payload.array();
        }

        private static byte[] encodeRestart(
                long epoch, long abandonedOpenCount, long truncatedByteCount) {
            if (epoch < MINIMUM_COUNT || abandonedOpenCount < MINIMUM_COUNT
                    || truncatedByteCount < MINIMUM_COUNT) {
                throw new IllegalArgumentException("Durable metadata restart values must be non-negative");
            }
            ByteBuffer payload = buffer(RESTART_BYTES);
            payload.putShort(SEMANTIC_VERSION);
            payload.putLong(epoch);
            payload.putLong(abandonedOpenCount);
            payload.putLong(truncatedByteCount);
            payload.putShort(RESERVED_SHORT);
            return payload.array();
        }

        private static MetadataStoreId decodeStoreHeader(
                SeekableByteChannel channel, MetadataFrameCodec.FrameMetadata frame) throws IOException {
            ByteBuffer payload = payload(channel, frame, STORE_HEADER_BYTES);
            requireSchema(payload);
            return new MetadataStoreId(readHex(payload));
        }

        private static MetadataTransactionId decodeIssuance(
                SeekableByteChannel channel, MetadataFrameCodec.FrameMetadata frame) throws IOException {
            ByteBuffer payload = payload(channel, frame, ISSUANCE_BYTES);
            requireSchema(payload);
            return readTransaction(payload);
        }

        private static Terminal decodeCommitted(
                SeekableByteChannel channel,
                MetadataFrameCodec.FrameMetadata frame,
                MetadataTransactionId expected,
                byte[] expectedChain) throws IOException {
            ByteBuffer payload = payload(channel, frame, COMMITTED_BYTES);
            requireSchema(payload);
            requireTransaction(payload, expected);
            long revision = payload.getLong();
            if (revision < MINIMUM_REVISION) {
                throw integrity("Committed Durable metadata revision is negative");
            }
            requireChain(payload, expectedChain);
            return new Terminal(TerminalKind.COMMITTED, OptionalLong.of(revision), OptionalInt.empty());
        }

        private static Terminal decodeRejected(
                SeekableByteChannel channel,
                MetadataFrameCodec.FrameMetadata frame,
                MetadataTransactionId expected,
                byte[] expectedChain) throws IOException {
            ByteBuffer payload = payload(channel, frame, REJECTED_BYTES);
            requireSchema(payload);
            requireTransaction(payload, expected);
            int failureCode = payload.getInt();
            if (failureCode < MINIMUM_FAILURE_CODE) {
                throw integrity("Rejected Durable metadata failure code is invalid");
            }
            requireChain(payload, expectedChain);
            return new Terminal(TerminalKind.NOT_COMMITTED, OptionalLong.empty(), OptionalInt.of(failureCode));
        }

        private static Restart decodeRestart(
                SeekableByteChannel channel, MetadataFrameCodec.FrameMetadata frame)
                throws IOException {
            ByteBuffer payload = payload(channel, frame, RESTART_BYTES);
            short version = payload.getShort();
            long epoch = payload.getLong();
            long abandonedOpenCount = payload.getLong();
            long truncatedByteCount = payload.getLong();
            short reserved = payload.getShort();
            if (version != SEMANTIC_VERSION || reserved != RESERVED_SHORT
                    || epoch < MINIMUM_COUNT || abandonedOpenCount < MINIMUM_COUNT
                    || truncatedByteCount < MINIMUM_COUNT || payload.hasRemaining()) {
                throw integrity("Durable metadata recovery restart payload is invalid");
            }
            return new Restart(epoch, abandonedOpenCount, truncatedByteCount);
        }

        private static ByteBuffer payload(
                SeekableByteChannel channel,
                MetadataFrameCodec.FrameMetadata frame,
                int exactLength) throws IOException {
            if (frame.payloadLength() != exactLength) {
                throw integrity("Durable metadata semantic payload length is invalid");
            }
            ByteBuffer payload = buffer(exactLength);
            channel.position(frame.payloadOffset());
            if (readFully(channel, payload) != exactLength) {
                throw integrity("Durable metadata semantic payload is incomplete");
            }
            payload.flip();
            return payload;
        }

        private static void requireSchema(ByteBuffer payload) throws MetadataStoreException {
            if (payload.getShort() != SEMANTIC_VERSION || payload.getShort() != RESERVED_SHORT) {
                throw integrity("Durable metadata semantic payload schema is unsupported");
            }
        }

        private static void requireTransaction(ByteBuffer payload, MetadataTransactionId expected)
                throws MetadataStoreException {
            if (!expected.equals(readTransaction(payload))) {
                throw integrity("Durable metadata terminal transaction identity is inconsistent");
            }
        }

        private static void requireChain(ByteBuffer payload, byte[] expected) throws MetadataStoreException {
            byte[] observed = new byte[DIGEST_BYTES];
            payload.get(observed);
            if (!MessageDigest.isEqual(expected, observed)) {
                throw integrity("Durable metadata terminal chain digest is inconsistent");
            }
        }

        private static MetadataTransactionId readTransaction(ByteBuffer payload) {
            return new MetadataTransactionId(new MetadataStoreId(readHex(payload)), readHex(payload));
        }

        private static String readHex(ByteBuffer payload) {
            byte[] value = new byte[ID_BYTES];
            payload.get(value);
            return LOWERCASE_HEX.formatHex(value);
        }

        private static void schema(ByteBuffer payload) {
            payload.putShort(SEMANTIC_VERSION).putShort(RESERVED_SHORT);
        }

        private static void transaction(ByteBuffer payload, MetadataTransactionId transactionId) {
            payload.put(hex(transactionId.storeId().value())).put(hex(transactionId.token()));
        }

        private static byte[] hex(String value) {
            return LOWERCASE_HEX.parseHex(value);
        }

        private static ByteBuffer buffer(int size) {
            return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        }
    }
}
