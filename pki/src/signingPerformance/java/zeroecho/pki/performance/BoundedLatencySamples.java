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
package zeroecho.pki.performance;

import java.util.Arrays;

/** Fixed-memory deterministic reservoir for non-negative nanosecond latencies. */
@SuppressWarnings({ "PMD.CommentDefaultAccessModifier", "PMD.AvoidSynchronizedAtMethodLevel",
        "PMD.AvoidLiteralsInIfCondition" })
final class BoundedLatencySamples {

    private final long[] values;
    private final long seed;
    private long observations;
    private long maximum;

    BoundedLatencySamples(int capacity, long seed) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.values = new long[capacity];
        this.seed = seed;
    }

    synchronized void add(long nanoseconds) {
        if (nanoseconds < 0L) {
            throw new IllegalArgumentException("latency must not be negative");
        }
        observations++;
        maximum = Math.max(maximum, nanoseconds);
        if (observations <= values.length) {
            values[(int) observations - 1] = nanoseconds;
            return;
        }
        long candidate = Long.remainderUnsigned(mix64(seed ^ observations), observations);
        if (candidate < values.length) {
            values[(int) candidate] = nanoseconds;
        }
    }

    synchronized Summary summarize() {
        int sampleCount = (int) Math.min(observations, values.length);
        if (sampleCount == 0) {
            return new Summary(0L, 0, 0L, 0L, 0L, 0L);
        }
        long[] sorted = Arrays.copyOf(values, sampleCount);
        Arrays.sort(sorted);
        return new Summary(observations, sampleCount, percentile(sorted, 0.50), percentile(sorted, 0.95),
                percentile(sorted, 0.99), maximum);
    }

    synchronized void reset() {
        Arrays.fill(values, 0L);
        observations = 0L;
        maximum = 0L;
    }

    private static long percentile(long[] sorted, double quantile) {
        int index = (int) Math.ceil(quantile * sorted.length) - 1;
        return sorted[Math.max(0, index)];
    }

    private static long mix64(long value) {
        long mixed = value;
        mixed = (mixed ^ (mixed >>> 30)) * 0xbf58_476d_1ce4_e5b9L;
        mixed = (mixed ^ (mixed >>> 27)) * 0x94d0_49bb_1331_11ebL;
        return mixed ^ (mixed >>> 31);
    }

    record Summary(long observations, int samples, long p50Nanos, long p95Nanos, long p99Nanos,
            long maxNanos) {
    }
}
