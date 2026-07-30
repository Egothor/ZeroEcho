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
package zeroecho.core.marshal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

/**
 * Immutable sequence of string key-value pairs with cursor-based iteration and
 * simple text serialization.
 *
 * <p>
 * A {@code PairSeq} stores pairs in a flat {@code String[]} array
 * representation: {@code [k0, v0, k1, v1, ...]}. It is designed for compact
 * transport of structured metadata where keys and values are UTF-8–safe strings
 * (binary data should be Base64 encoded before storing).
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * PairSeq seq = PairSeq.of("type", "SntruPrimePublicKeySpec",
 *                          "x509.b64", "BASE64ENCODED");
 *
 * for (PairSeq.Cursor c = seq.cursor(); c.next();) {
 *     System.out.println(c.key() + " = " + c.value());
 * }
 * }</pre>
 *
 * <h2>Serialization</h2>
 * <ul>
 * <li>{@link #writeTo(Appendable)} outputs each pair as {@code k=v\n} lines
 * without escaping and reports checked I/O failures.</li>
 * <li>{@link #readFrom(java.io.Reader)} parses lines in the same format,
 * ignoring blank lines and comments starting with {@code #}.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances are immutable and safe to share across
 * threads. The {@link Cursor} is not thread-safe and should be confined to a
 * single thread.
 *
 * @since 1.0
 */
public final class PairSeq {
    private final String[] kv; // [k0,v0,k1,v1,...]

    private PairSeq(String... kv) {
        this.kv = kv;
    }

    /**
     * Creates a new sequence from an even-length list of keys and values.
     *
     * @param kv alternating key and value strings; must have even length
     * @return new {@code PairSeq} with the given contents
     * @throws IllegalArgumentException if {@code kv} is {@code null}, has odd
     *                                  length, or contains a null key or value
     */
    public static PairSeq of(String... kv) {
        if (kv == null) {
            throw new IllegalArgumentException("kv must not be null");
        }
        if ((kv.length & 1) != 0) {
            throw new IllegalArgumentException("kv must have even length (k,v pairs)");
        }
        for (int elementIndex = 0; elementIndex < kv.length; elementIndex++) {
            if (kv[elementIndex] == null) {
                int pairIndex = elementIndex >>> 1;
                String role = (elementIndex & 1) == 0 ? "key" : "value";
                throw new IllegalArgumentException("pair " + pairIndex + " " + role + " must not be null");
            }
        }
        return new PairSeq(kv.clone());
    }

    /**
     * Returns the number of key-value pairs in this sequence.
     *
     * @return pair count
     */
    public int size() {
        return kv.length >>> 1;
    }

    /**
     * Returns the key at the given index.
     *
     * @param i index of the pair (0-based)
     * @return key string
     * @throws ArrayIndexOutOfBoundsException if {@code i} is out of range
     */
    public String keyAt(int i) {
        return kv[i << 1];
    }

    /**
     * Returns the value at the given index.
     *
     * @param i index of the pair (0-based)
     * @return value string
     * @throws ArrayIndexOutOfBoundsException if {@code i} is out of range
     */
    public String valAt(int i) {
        return kv[(i << 1) + 1];
    }

    /**
     * Returns a forward-only cursor for iterating the pairs.
     *
     * @return new cursor over this sequence
     */
    public Cursor cursor() {
        return new Cursor();
    }

    /**
     * Forward-only iterator over the pairs of a {@link PairSeq}.
     *
     * <p>
     * The cursor maintains a current index; call {@link #next()} to advance, then
     * {@link #key()} and {@link #value()} to access elements.
     * </p>
     */
    public final class Cursor {
        private int i = -1;
        private final int n = size();

        /**
         * Advances to the next pair if available.
         *
         * @return {@code true} if advanced to a valid pair, {@code false} if end
         *         reached
         */
        public boolean next() {
            int next = i + 1;
            if (next < n) {
                i = next;
                return true;
            }
            return false;
        }

        /**
         * Returns the current key.
         *
         * @return key string
         * @throws IndexOutOfBoundsException if not positioned on a valid pair
         */
        public String key() {
            if (i < 0 || i >= n) {
                throw new IndexOutOfBoundsException();
            }
            return keyAt(i);
        }

        /**
         * Returns the current value.
         *
         * @return value string
         * @throws IndexOutOfBoundsException if not positioned on a valid pair
         */
        public String value() {
            if (i < 0 || i >= n) {
                throw new IndexOutOfBoundsException();
            }
            return valAt(i);
        }
    }

    /**
     * Appends all pairs to the target as {@code key=value} lines, reporting checked
     * I/O failures directly.
     *
     * <p>
     * No escaping is performed; callers must ensure keys and values do not contain
     * newlines. Binary data should be stored as Base64.
     * </p>
     *
     * @param out appendable target
     * @throws IOException if the append fails
     */
    public void writeTo(Appendable out) throws IOException {
        for (int i = 0; i < size(); i++) {
            out.append(keyAt(i)).append('=').append(valAt(i)).append('\n');
        }
    }

    /**
     * Reads a {@code PairSeq} from a line-based text format.
     *
     * <p>
     * Each non-empty, non-comment line must have the form {@code key=value}. Lines
     * without an equals sign or with empty keys are skipped. Comments start with
     * {@code #}.
     * </p>
     *
     * @param reader character source
     * @return parsed {@code PairSeq}
     * @throws IOException if reading fails
     */
    public static PairSeq readFrom(Reader reader) throws IOException {
        BufferedReader br = (reader instanceof BufferedReader) ? (BufferedReader) reader : new BufferedReader(reader);
        List<String> list = new ArrayList<>();
        String line;
        while ((line = br.readLine()) != null) {
            if (line.isEmpty() || line.charAt(0) == '#') {
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                continue; // skip malformed/section markers handled elsewhere
            }
            String k = line.substring(0, eq);
            String v = line.substring(eq + 1);
            list.add(k);
            list.add(v);
        }
        return of(list.toArray(String[]::new));
    }
}
