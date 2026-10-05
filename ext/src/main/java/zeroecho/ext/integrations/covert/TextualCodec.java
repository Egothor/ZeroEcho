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
package zeroecho.ext.integrations.covert;

import java.util.ArrayDeque;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Queue;
import java.util.TreeMap;

import zeroecho.core.util.RandomSupport;

/**
 * <strong>Experimental.</strong> This class is part of the {@code zeroecho.ext}
 * module, which carries no API stability guarantees and may change or be removed
 * in any future release.
 *
 * <p>A utility class for generating pseudo-random textual content based on
 * predefined character frequency distributions.</p>
 * <p>
 * The {@code TextualCodec} class contains a nested {@link Generator} class that
 * can be configured with a set of character frequencies (e.g., English letter
 * frequencies) to produce text that mimics the statistical distribution of the
 * given language or character set.
 */
public final class TextualCodec { // NOPMD
    /**
     * Private constructor to prevent instantiation of {@code TextualCodec}.
     * <p>
     * This class is intended to be used as a utility container for static members
     * and should not be instantiated.
     */
    private TextualCodec() {

    }

    /**
     * Generates characters or strings using a frequency-based distribution.
     * <p>
     * This generator uses a cumulative frequency table internally to map random
     * numbers to characters, enabling the creation of realistic-looking text that
     * follows the given character frequency distribution. The generator also avoids
     * consecutive duplicate characters by employing a simple queuing mechanism.
     */
    public static class Generator {
        /**
         * Internal map representing the cumulative frequency ranges mapped to
         * characters.
         */
        private final NavigableMap<Double, Character> ranges = new TreeMap<>();
        /**
         * The maximum value of the cumulative frequency range.
         */
        private final double maxRange;
        /**
         * A predefined English character frequency distribution including the space
         * character, based on typical usage in English text.
         */
        public final static Map<Character, Double> ENGLISH = Map.ofEntries(Map.entry('a', 8.2), Map.entry('b', 1.5),
                Map.entry('c', 2.8), Map.entry('d', 4.3), Map.entry('e', 12.7), Map.entry('f', 2.2),
                Map.entry('g', 2.0), Map.entry('h', 6.1), Map.entry('i', 7.0), Map.entry('j', 0.15),
                Map.entry('k', 0.77), Map.entry('l', 4.0), Map.entry('m', 2.4), Map.entry('n', 6.7),
                Map.entry('o', 7.5), Map.entry('p', 1.9), Map.entry('q', 0.095), Map.entry('r', 6.0),
                Map.entry('s', 6.3), Map.entry('t', 9.1), Map.entry('u', 2.8), Map.entry('v', 0.98),
                Map.entry('w', 2.4), Map.entry('x', 0.15), Map.entry('y', 2.0), Map.entry('z', 0.074),
                Map.entry(' ', 25.4));

        private Character lastChar = '~';
        private final Queue<Character> backlog = new ArrayDeque<>();
        /**
         * Creates a new generator using the {@link #ENGLISH} frequency distribution.
         *
         * <p>{@code Generator} is not thread-safe. This factory returns a fresh instance
         * on every call so each thread can hold its own.</p>
         *
         * @return a new {@code Generator} seeded with the English distribution
         */
        public static Generator english() {
            return new Generator(ENGLISH);
        }

        /**
         * Constructs a new {@code Generator} with the specified character frequency
         * distribution.
         *
         * @param frequencies a map of characters to their relative frequencies (must be
         *                    non-negative)
         */
        public Generator(Map<Character, Double> frequencies) {
            double cumulative = 0.0;
            for (Map.Entry<Character, Double> entry : frequencies.entrySet()) {
                double freq = entry.getValue();
                if (freq <= 0) {
                    continue;
                }
                ranges.put(cumulative, entry.getKey());
                cumulative = cumulative + freq;
            }

            maxRange = cumulative;
        }

        /**
         * Generates a string of the specified length using the configured character
         * frequency distribution. Consecutive duplicate characters are avoided when
         * possible.
         *
         * @param length the number of characters to generate
         * @return a randomly generated string
         */
        public String getText(int length) {
            StringBuilder sb = new StringBuilder(length);

            while (length-- > 0) { // NOPMD
                sb.append(getChar());
            }

            return sb.toString();
        }

        /**
         * Returns the next randomly generated character, avoiding consecutive
         * duplicates when possible.
         *
         * @return the next character in the generated sequence
         */
        public char getChar() {
            if (backlog.isEmpty() || lastChar.equals(backlog.peek())) {
                Character next = getChar(RandomSupport.getRandom().nextDouble(maxRange));
                while (lastChar.equals(next)) {
                    backlog.add(next);
                    next = getChar(RandomSupport.getRandom().nextDouble(maxRange));
                }
                lastChar = next;
                return lastChar;
            }

            return lastChar = backlog.poll();
        }

        /**
         * Returns a character based on the provided value in the frequency range.
         *
         * @param value a value between 0 (inclusive) and {@code maxRange} (exclusive)
         * @return the corresponding character for the specified value
         * @throws IllegalArgumentException if the value is out of range
         */
        public char getChar(double value) {
            if (value < 0.0 || value >= maxRange) {
                throw new IllegalArgumentException("Value must be in [0.0, " + maxRange + ")");
            }

            Map.Entry<Double, Character> entry = ranges.floorEntry(value);
            return (entry == null) ? ranges.firstEntry().getValue() : entry.getValue();
        }
    }
}
