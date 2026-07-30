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

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

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
 * <h2>Thread-safety</h2> Instances are immutable and thread-safe. Public
 * accessors are resolved once per runtime class and operation type, then
 * invoked through cached method handles. The unload-safe {@link ClassValue}
 * caches do not retain otherwise unreachable class loaders.
 *
 * @param <T> domain type that follows the marshalling and unmarshalling
 *            conventions
 * @since 1.0
 */
public final class PairSeqCodec<T> implements Codec<T, PairSeq> {
    private static final ClassValue<PlanHolder<MarshalPlan>> MARSHAL_PLANS = new ClassValue<>() {
        @Override
        protected PlanHolder<MarshalPlan> computeValue(Class<?> type) {
            return new PlanHolder<>(() -> MarshalPlan.resolve(type));
        }
    };
    private static final ClassValue<PlanHolder<UnmarshalPlan>> UNMARSHAL_PLANS = new ClassValue<>() {
        @Override
        protected PlanHolder<UnmarshalPlan> computeValue(Class<?> type) {
            return new PlanHolder<>(() -> UnmarshalPlan.resolve(type));
        }
    };

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
        return MARSHAL_PLANS.get(value.getClass()).get().invoke(value);
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
    @Override
    public T unmarshal(PairSeq repr) {
        Objects.requireNonNull(repr, "repr");
        return type.cast(UNMARSHAL_PLANS.get(type).get().invoke(repr));
    }

    /* default */ static Object cachedMarshalPlan(Class<?> runtimeType) {
        return MARSHAL_PLANS.get(runtimeType).get();
    }

    /* default */ static Object cachedUnmarshalPlan(Class<?> runtimeType) {
        return UNMARSHAL_PLANS.get(runtimeType).get();
    }

    /* default */ static int marshalResolutionCount(Class<?> runtimeType) {
        return MARSHAL_PLANS.get(runtimeType).resolutionCount();
    }

    /* default */ static int unmarshalResolutionCount(Class<?> runtimeType) {
        return UNMARSHAL_PLANS.get(runtimeType).resolutionCount();
    }

    /**
     * Once-only lazy plan resolver stored as the canonical {@link ClassValue}
     * value.
     *
     * @param <P> plan type
     */
    private static final class PlanHolder<P> {
        private final AtomicReference<P> plan = new AtomicReference<>();
        private final ReentrantLock resolutionLock = new ReentrantLock();
        private Supplier<P> resolver;
        private int resolutionCount;

        private PlanHolder(Supplier<P> resolver) {
            this.resolver = resolver;
        }

        private P get() {
            P resolved = plan.get();
            if (resolved == null) {
                resolved = resolveOnce();
            }
            return resolved;
        }

        private P resolveOnce() {
            resolutionLock.lock();
            try {
                P resolved = plan.get();
                if (resolved == null) {
                    resolutionCount++;
                    resolved = resolver.get();
                    resolver = null;
                    plan.set(resolved);
                }
                return resolved;
            } finally {
                resolutionLock.unlock();
            }
        }

        private int resolutionCount() {
            resolutionLock.lock();
            try {
                return resolutionCount;
            } finally {
                resolutionLock.unlock();
            }
        }
    }

    /**
     * Cached success or structural failure for one marshal runtime class.
     */
    private static final class MarshalPlan {
        private final MethodHandle handle;
        private final String failureMessage;
        private final Throwable failureCause;

        private MarshalPlan(MethodHandle handle, String failureMessage, Throwable failureCause) {
            this.handle = handle;
            this.failureMessage = failureMessage;
            this.failureCause = failureCause;
        }

        private static MarshalPlan resolve(Class<?> runtimeType) {
            try {
                Method method = runtimeType.getMethod("marshal");
                if (!PairSeq.class.isAssignableFrom(method.getReturnType())) {
                    return new MarshalPlan(null, "marshal() must return PairSeq in " + runtimeType.getName(), null);
                }
                MethodHandle handle = MethodHandles.lookup().unreflect(method);
                return new MarshalPlan(handle, null, null);
            } catch (NoSuchMethodException exception) {
                return new MarshalPlan(null, runtimeType.getName() + " must implement marshal():PairSeq", exception);
            } catch (IllegalAccessException exception) {
                return new MarshalPlan(null, "marshal() failed for " + runtimeType.getName(), exception);
            }
        }

        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private PairSeq invoke(Object value) {
            if (handle == null) {
                throw new IllegalStateException(failureMessage, failureCause);
            }
            try {
                return (PairSeq) handle.invoke(value);
            } catch (Throwable failure) {
                throw new IllegalStateException("marshal() failed for " + value.getClass().getName(),
                        new InvocationTargetException(failure));
            }
        }
    }

    /**
     * Cached success or structural failure for one unmarshal runtime class.
     */
    private static final class UnmarshalPlan {
        private final MethodHandle handle;
        private final String invocationFailureMessage;
        private final String resolutionFailureMessage;
        private final Throwable resolutionFailureCause;

        private UnmarshalPlan(MethodHandle handle, String invocationFailureMessage, String resolutionFailureMessage,
                Throwable resolutionFailureCause) {
            this.handle = handle;
            this.invocationFailureMessage = invocationFailureMessage;
            this.resolutionFailureMessage = resolutionFailureMessage;
            this.resolutionFailureCause = resolutionFailureCause;
        }

        private static UnmarshalPlan resolve(Class<?> runtimeType) {
            try {
                Method method = runtimeType.getMethod("unmarshal", PairSeq.class);
                if (Modifier.isStatic(method.getModifiers())) {
                    Class<?> returnType = method.getReturnType();
                    if (!runtimeType.isAssignableFrom(returnType) && !returnType.isAssignableFrom(runtimeType)) {
                        return new UnmarshalPlan(null, null,
                                "static unmarshal(PairSeq) must return " + runtimeType.getName(), null);
                    }
                    MethodHandle handle = MethodHandles.lookup().unreflect(method);
                    return new UnmarshalPlan(handle, "static unmarshal(PairSeq) failed for " + runtimeType.getName(),
                            null, null);
                }
            } catch (NoSuchMethodException ignored) {
                // Resolve the constructor fallback below.
            } catch (IllegalAccessException exception) {
                return new UnmarshalPlan(null, null, "static unmarshal(PairSeq) failed for " + runtimeType.getName(),
                        exception);
            }

            try {
                MethodHandle handle = MethodHandles.lookup()
                        .unreflectConstructor(runtimeType.getConstructor(PairSeq.class));
                return new UnmarshalPlan(handle, "ctor(PairSeq) failed for " + runtimeType.getName(), null, null);
            } catch (NoSuchMethodException exception) {
                return new UnmarshalPlan(null, null,
                        runtimeType.getName() + " must provide static unmarshal(PairSeq) or ctor(PairSeq)", exception);
            } catch (IllegalAccessException exception) {
                return new UnmarshalPlan(null, null, "ctor(PairSeq) failed for " + runtimeType.getName(), exception);
            }
        }

        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private Object invoke(PairSeq representation) {
            if (handle == null) {
                throw new IllegalStateException(resolutionFailureMessage, resolutionFailureCause);
            }
            try {
                return handle.invoke(representation);
            } catch (Throwable failure) {
                throw new IllegalStateException(invocationFailureMessage, new InvocationTargetException(failure));
            }
        }
    }
}
