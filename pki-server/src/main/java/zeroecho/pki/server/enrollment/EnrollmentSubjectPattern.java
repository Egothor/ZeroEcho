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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Immutable linear-time matcher for bounded enrollment subject constraints.
 *
 * <p>The grammar accepts literal text and {@code .*} wildcards, with optional
 * leading {@code ^} and trailing {@code $}. Matching always covers the entire
 * subject. Backslash escapes only regex punctuation as literal text; groups,
 * alternatives, character classes, backreferences, and other quantifiers are
 * rejected. Patterns are at most 512 UTF-16 code units and subjects at most
 * 4096. This deliberately restricted grammar avoids regex backtracking.</p>
 *
 * <p>Compilation requires O(M) time and space. Matching requires O(N + M)
 * time and O(1) auxiliary memory, where M and N are pattern and subject lengths.</p>
 */
public final class EnrollmentSubjectPattern {
    private static final int MAXIMUM_SUBJECT_LENGTH = 4_096;
    private static final int SINGLE_LITERAL_COUNT = 1;
    private static final char ESCAPE_CHARACTER = '\\';
    private final List<Literal> parts;

    private EnrollmentSubjectPattern(List<Literal> parts) {
        this.parts = List.copyOf(parts);
    }

    /**
     * Compiles the closed, bounded subject-pattern grammar.
     * @param pattern nonempty pattern, at most 512 code units
     * @return immutable thread-safe matcher
     * @throws IllegalArgumentException if the syntax or size is unsupported
     */
    public static EnrollmentSubjectPattern compile(String pattern) {
        Objects.requireNonNull(pattern, "pattern");
        if (pattern.isEmpty() || pattern.length() > 512) {
            throw new IllegalArgumentException("Invalid subject pattern size");
        }
        int start = pattern.startsWith("^") ? 1 : 0;
        int end = literalEnd(pattern, start);
        List<Literal> parts = new ArrayList<>();
        StringBuilder literal = new StringBuilder();
        int index = start;
        while (index < end) {
            char ch = pattern.charAt(index++);
            if (ch == '.' && index < end && pattern.charAt(index) == '*') {
                parts.add(new Literal(literal.toString()));
                literal.setLength(0);
                index++;
            } else if (ch == ESCAPE_CHARACTER) {
                if (index >= end || "\\.[]{}()*+?^$|".indexOf(pattern.charAt(index)) < 0) {
                    throw invalid();
                }
                literal.append(pattern.charAt(index++));
            } else {
                if (".[]{}()*+?^$|".indexOf(ch) >= 0 || Character.isISOControl(ch)) {
                    throw invalid();
                }
                literal.append(ch);
            }
        }
        parts.add(new Literal(literal.toString()));
        return new EnrollmentSubjectPattern(parts);
    }

    private static int literalEnd(String pattern, int start) {
        int end = pattern.length();
        // An escaped terminal dollar remains literal.
        if (end > start && pattern.charAt(end - 1) == '$') {
            int backslashes = 0;
            for (int index = end - 2; index >= start && pattern.charAt(index) == '\\'; index--) {
                backslashes++;
            }
            if ((backslashes & 1) == 0) {
                end--;
            }
        }
        return end;
    }

    /**
     * Tests the complete subject against the compiled constraint.
     * @param subject canonical subject DN text, at most 4096 code units
     * @return whether the entire subject matches
     * @throws IllegalArgumentException if the subject exceeds the finite bound
     */
    public boolean matches(String subject) {
        Objects.requireNonNull(subject, "subject");
        if (subject.length() > MAXIMUM_SUBJECT_LENGTH) {
            throw new IllegalArgumentException("Subject DN exceeds enrollment bound");
        }
        if (parts.size() == SINGLE_LITERAL_COUNT) {
            return subject.equals(parts.getFirst().text);
        }
        String first = parts.getFirst().text;
        String last = parts.getLast().text;
        if (!subject.startsWith(first) || !subject.endsWith(last)) {
            return false;
        }
        int offset = first.length();
        int limit = subject.length() - last.length();
        if (offset > limit) {
            return false;
        }
        for (int index = 1; index < parts.size() - 1; index++) {
            Literal part = parts.get(index);
            int found = part.find(subject, offset, limit);
            if (found < 0) {
                return false;
            }
            offset = found + part.text.length();
        }
        return offset <= limit;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Subject pattern supports only literals and .* wildcards");
    }

    /** One literal pattern segment and its precomputed linear-time matching table. */
    private static final class Literal {
        private final String text;
        private final int[] prefix;

        private Literal(String text) {
            this.text = text;
            this.prefix = new int[text.length()];
            int matched = 0;
            for (int index = 1; index < text.length(); index++) {
                while (matched > 0 && text.charAt(index) != text.charAt(matched)) {
                    matched = prefix[matched - 1];
                }
                if (text.charAt(index) == text.charAt(matched)) {
                    matched++;
                }
                prefix[index] = matched;
            }
        }

        private int find(String subject, int offset, int limit) {
            if (text.isEmpty()) {
                return offset;
            }
            int matched = 0;
            for (int index = offset; index < limit; index++) {
                while (matched > 0 && subject.charAt(index) != text.charAt(matched)) {
                    matched = prefix[matched - 1];
                }
                if (subject.charAt(index) == text.charAt(matched)) {
                    matched++;
                }
                if (matched == text.length()) {
                    return index - matched + 1;
                }
            }
            return -1;
        }
    }
}
