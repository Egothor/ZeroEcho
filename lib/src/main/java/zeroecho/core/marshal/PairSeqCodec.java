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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;

/**
 * Reflection-based {@link Codec} that marshals and unmarshals domain objects to
 * and from {@link PairSeq}.
 *
 * <p>
 * A {@code PairSeqCodec} adapts any domain type {@code T} to the
 * {@link PairSeq} representation by convention, using reflection. The domain
 * type must implement one or both of the following:
 * </p>
 * <ul>
 * <li>Instance method {@code marshal()} returning {@code PairSeq}.</li>
 * <li>Either a public static factory {@code unmarshal(PairSeq)} or a public
 * constructor {@code T(PairSeq)}.</li>
 * </ul>
 *
 * <h2>Conventions</h2>
 * <ul>
 * <li><b>Marshalling</b>: calls {@code value.marshal()} and requires its return
 * type to be {@code PairSeq}.</li>
 * <li><b>Unmarshalling</b>: prefers a public static {@code unmarshal(PairSeq)}
 * on {@code T}; if absent, falls back to a public constructor
 * {@code T(PairSeq)}.</li>
 * <li>Failures in lookup or invocation are reported as
 * {@link IllegalStateException} with the cause attached.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * public final class User {
 *     private final String id;
 *     private final String name;
 *
 *     public User(String id, String name) {
 *         this.id = id; this.name = name;
 *     }
 *
 *     // Required by PairSeqCodec for marshalling:
 *     public PairSeq marshal() {
 *         return PairSeq.of("id", id, "name", name);
 *     }
 *
 *     // Preferred unmarshal entrypoint:
 *     public static User unmarshal(PairSeq ps) {
 *         PairSeq.Cursor c = ps.cursor();
 *         String id = null, name = null;
 *         while (c.next()) {
 *             if ("id".equals(c.key())) id = c.value();
 *             else if ("name".equals(c.key())) name = c.value();
 *         }
 *         return new User(id, name);
 *     }
 * }
 *
 * PairSeqCodec<User> codec = new PairSeqCodec<>(User.class);
 * PairSeq repr = codec.marshal(new User("u-1", "Alice"));
 * User u = codec.unmarshal(repr);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are immutable and thread-safe. Reflection
 * lookups are performed per call and are not cached.
 *
 * @param <T> domain type that follows the marshalling and unmarshalling
 *            conventions
 * @since 1.0
 */
public final class PairSeqCodec<T> implements Codec<T, PairSeq> {
    private final Class<T> type;

    /**
     * Creates a codec bound to a specific domain type.
     *
     * @param type domain class that provides {@code marshal()} and either
     *             {@code static unmarshal(PairSeq)} or {@code T(PairSeq)}
     * @throws NullPointerException if {@code type} is {@code null}
     */
    public PairSeqCodec(Class<T> type) {
        this.type = Objects.requireNonNull(type, "type");
    }

    /**
     * Encodes a domain object to {@link PairSeq} by invoking its {@code marshal()}
     * method.
     *
     * <p>
     * The domain object's {@code marshal()} method must be public (or otherwise
     * accessible) and return {@code PairSeq}. Any exception thrown by the target
     * method is wrapped in {@link IllegalStateException}.
     * </p>
     *
     * @param value domain object to encode
     * @return the {@code PairSeq} produced by {@code value.marshal()}
     * @throws NullPointerException  if {@code value} is {@code null}
     * @throws IllegalStateException if no {@code marshal()} method exists, if it
     *                               does not return {@code PairSeq}, or if the
     *                               invocation fails
     */
    @Override
    public PairSeq marshal(T value) {
        Objects.requireNonNull(value, "value");
        try {
            Method m = value.getClass().getMethod("marshal");
            if (!PairSeq.class.isAssignableFrom(m.getReturnType())) {
                throw new IllegalStateException("marshal() must return PairSeq in " + value.getClass().getName());
            }
            return (PairSeq) m.invoke(value);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(value.getClass().getName() + " must implement marshal():PairSeq", e);
        } catch (IllegalAccessException | InvocationTargetException t) {
            throw new IllegalStateException("marshal() failed for " + value.getClass().getName(), t);
        }
    }

    /**
     * Decodes a {@link PairSeq} back into a domain object by convention.
     *
     * <p>
     * Resolution order:
     * </p>
     * <ol>
     * <li>Invoke a public static {@code unmarshal(PairSeq)} on {@code type}, if
     * present.</li>
     * <li>Otherwise, invoke a public constructor {@code type(PairSeq)}.</li>
     * </ol>
     *
     * <p>
     * If neither entrypoint is available, or invocation fails, an
     * {@link IllegalStateException} is thrown with the original cause attached for
     * diagnostics.
     * </p>
     *
     * @param repr serialized representation to decode
     * @return reconstructed domain object
     * @throws NullPointerException  if {@code repr} is {@code null}
     * @throws IllegalStateException if neither a suitable static factory nor
     *                               constructor exists, or if either invocation
     *                               fails
     */
    @SuppressWarnings("unchecked")
    @Override
    public T unmarshal(PairSeq repr) {
        Objects.requireNonNull(repr, "repr");
        // Prefer static unmarshal(PairSeq)
        try {
            Method m = type.getMethod("unmarshal", PairSeq.class);
            if ((m.getModifiers() & java.lang.reflect.Modifier.STATIC) != 0) {
                return (T) m.invoke(null, repr);
            }
        } catch (NoSuchMethodException ignore) { // NOPMD
            // fall through
        } catch (IllegalAccessException | InvocationTargetException t) {
            throw new IllegalStateException("static unmarshal(PairSeq) failed for " + type.getName(), t);
        }
        // Or constructor T(PairSeq)
        try {
            Constructor<T> c = type.getConstructor(PairSeq.class);
            return c.newInstance(repr);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(type.getName() + " must provide static unmarshal(PairSeq) or ctor(PairSeq)",
                    e);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException
                | InstantiationException t) {
            throw new IllegalStateException("ctor(PairSeq) failed for " + type.getName(), t);
        }
    }
}
