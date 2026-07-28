/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.marshal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;

import org.junit.jupiter.api.Test;

class PairSeqTest {
    @Test
    void checkedRoundTrip() throws Exception {
        System.out.println("checkedRoundTrip");
        PairSeq empty = PairSeq.of();
        assertEquals(0, empty.size());

        PairSeq original = PairSeq.of("a", "1", "b", "");
        StringBuilder output = new StringBuilder();
        original.writeTo(output);
        PairSeq decoded = PairSeq.readFrom(new StringReader(output.toString()));

        assertEquals(2, decoded.size());
        assertEquals("a", decoded.keyAt(0));
        assertEquals("1", decoded.valAt(0));
        assertEquals("", decoded.valAt(1));
        System.out.println("...pairs=" + decoded.size());
        System.out.println("checkedRoundTrip...ok");
    }

    @Test
    void validationAndOwnership() {
        System.out.println("validationAndOwnership");
        assertThrows(IllegalArgumentException.class, () -> PairSeq.of((String[]) null));
        assertThrows(IllegalArgumentException.class, () -> PairSeq.of("key"));
        assertEquals("pair 0 key must not be null",
                assertThrows(IllegalArgumentException.class, () -> PairSeq.of(null, "value")).getMessage());
        assertEquals("pair 0 value must not be null",
                assertThrows(IllegalArgumentException.class, () -> PairSeq.of("key", null)).getMessage());
        assertEquals("pair 1 key must not be null",
                assertThrows(IllegalArgumentException.class,
                        () -> PairSeq.of("first", "value", null, "other")).getMessage());

        String[] source = { "key", "value" };
        PairSeq sequence = PairSeq.of(source);
        source[0] = "changed";
        assertEquals("key", sequence.keyAt(0));
        assertNotSame(source, sequence);
        System.out.println("...owned=true");
        System.out.println("validationAndOwnership...ok");
    }

    @Test
    void failurePropagation() {
        System.out.println("failurePropagation");
        IOException immediate = new IOException("immediate");
        IOException checked = assertThrows(IOException.class,
                () -> PairSeq.of("a", "b").writeTo(new FailingAppendable(0, immediate)));
        assertSame(immediate, checked);

        IOException partial = new IOException("partial");
        FailingAppendable partialOutput = new FailingAppendable(2, partial);
        IOException partialActual = assertThrows(IOException.class,
                () -> PairSeq.of("a", "b").writeTo(partialOutput));
        assertSame(partial, partialActual);
        assertEquals("a=", partialOutput.output.toString());

        IllegalStateException runtime = new IllegalStateException("runtime");
        IllegalStateException runtimeActual = assertThrows(IllegalStateException.class,
                () -> PairSeq.of("a", "b").writeTo(new RuntimeFailingAppendable(runtime)));
        assertSame(runtime, runtimeActual);
        System.out.println("...partialChars=" + partialOutput.output.length());
        System.out.println("failurePropagation...ok");
    }

    private static final class FailingAppendable implements Appendable {
        private final int acceptedCharacters;
        private final IOException failure;
        private final StringBuilder output = new StringBuilder();

        private FailingAppendable(int acceptedCharacters, IOException failure) {
            this.acceptedCharacters = acceptedCharacters;
            this.failure = failure;
        }

        @Override
        public Appendable append(CharSequence sequence) throws IOException {
            for (int index = 0; index < sequence.length(); index++) {
                append(sequence.charAt(index));
            }
            return this;
        }

        @Override
        public Appendable append(CharSequence sequence, int start, int end) throws IOException {
            return append(sequence.subSequence(start, end));
        }

        @Override
        public Appendable append(char character) throws IOException {
            if (output.length() == acceptedCharacters) {
                throw failure;
            }
            output.append(character);
            return this;
        }
    }

    private static final class RuntimeFailingAppendable implements Appendable {
        private final IllegalStateException failure;

        private RuntimeFailingAppendable(IllegalStateException failure) {
            this.failure = failure;
        }

        @Override
        public Appendable append(CharSequence sequence) {
            throw failure;
        }

        @Override
        public Appendable append(CharSequence sequence, int start, int end) {
            throw failure;
        }

        @Override
        public Appendable append(char character) {
            throw failure;
        }
    }
}
