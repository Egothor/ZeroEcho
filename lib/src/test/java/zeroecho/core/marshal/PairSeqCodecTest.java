/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.marshal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

/**
 * Verifies cached accessor plans for {@link PairSeqCodec}.
 */
class PairSeqCodecTest {

    @Test
    void marshalAndStaticFactoryUnmarshalSucceed() {
        System.out.println("marshalAndStaticFactoryUnmarshalSucceed");
        PairSeqCodec<FactoryValue> codec = new PairSeqCodec<>(FactoryValue.class);

        PairSeq representation = codec.marshal(new FactoryValue("alpha"));
        FactoryValue decoded = codec.unmarshal(representation);

        assertEquals("alpha", representation.valAt(0));
        assertEquals("alpha", decoded.value);
        System.out.println("...decoded=" + decoded.value);
        System.out.println("marshalAndStaticFactoryUnmarshalSucceed...ok");
    }

    @Test
    void repeatedOperationsReuseCachedPlans() {
        System.out.println("repeatedOperationsReuseCachedPlans");
        PairSeqCodec<FactoryValue> codec = new PairSeqCodec<>(FactoryValue.class);
        Object marshalPlan = PairSeqCodec.cachedMarshalPlan(FactoryValue.class);
        Object unmarshalPlan = PairSeqCodec.cachedUnmarshalPlan(FactoryValue.class);

        for (int index = 0; index < 20; index++) {
            PairSeq representation = codec.marshal(new FactoryValue(Integer.toString(index)));
            assertEquals(Integer.toString(index), codec.unmarshal(representation).value);
        }
        assertSame(marshalPlan, PairSeqCodec.cachedMarshalPlan(FactoryValue.class));
        assertSame(unmarshalPlan, PairSeqCodec.cachedUnmarshalPlan(FactoryValue.class));
        assertEquals(1, PairSeqCodec.marshalResolutionCount(FactoryValue.class));
        assertEquals(1, PairSeqCodec.unmarshalResolutionCount(FactoryValue.class));

        System.out.println("...iterations=20");
        System.out.println("repeatedOperationsReuseCachedPlans...ok");
    }

    @Test
    void separateRuntimeClassesUseSeparateMarshalPlans() {
        System.out.println("separateRuntimeClassesUseSeparateMarshalPlans");
        Object first = PairSeqCodec.cachedMarshalPlan(FactoryValue.class);
        Object second = PairSeqCodec.cachedMarshalPlan(ConstructorValue.class);
        Object firstUnmarshal = PairSeqCodec.cachedUnmarshalPlan(FactoryValue.class);
        Object secondUnmarshal = PairSeqCodec.cachedUnmarshalPlan(ConstructorValue.class);

        assertNotSame(first, second);
        assertNotSame(firstUnmarshal, secondUnmarshal);

        System.out.println("...separatePlans=true");
        System.out.println("separateRuntimeClassesUseSeparateMarshalPlans...ok");
    }

    @Test
    void constructorFallbackUnmarshalsSuccessfully() {
        System.out.println("constructorFallbackUnmarshalsSuccessfully");
        PairSeqCodec<ConstructorValue> codec = new PairSeqCodec<>(ConstructorValue.class);

        ConstructorValue decoded = codec.unmarshal(PairSeq.of("value", "beta"));

        assertEquals("beta", decoded.value);
        System.out.println("...decoded=" + decoded.value);
        System.out.println("constructorFallbackUnmarshalsSuccessfully...ok");
    }

    @Test
    void broadlyDeclaredFactoryReturnRemainsCompatible() {
        System.out.println("broadlyDeclaredFactoryReturnRemainsCompatible");
        PairSeqCodec<BroadFactoryValue> codec = new PairSeqCodec<>(BroadFactoryValue.class);

        BroadFactoryValue decoded = codec.unmarshal(PairSeq.of("value", "broad"));

        assertEquals("broad", decoded.value);
        System.out.println("...decoded=" + decoded.value);
        System.out.println("broadlyDeclaredFactoryReturnRemainsCompatible...ok");
    }

    @Test
    void missingAndIncompatibleMethodsReportContext() {
        System.out.println("missingAndIncompatibleMethodsReportContext");
        PairSeqCodec<MissingValue> missingCodec = new PairSeqCodec<>(MissingValue.class);
        PairSeqCodec<WrongMarshalValue> wrongMarshalCodec = new PairSeqCodec<>(WrongMarshalValue.class);
        PairSeqCodec<WrongFactoryValue> wrongFactoryCodec = new PairSeqCodec<>(WrongFactoryValue.class);

        IllegalStateException missingMarshal = assertThrows(IllegalStateException.class,
                () -> missingCodec.marshal(new MissingValue()));
        IllegalStateException missingUnmarshal = assertThrows(IllegalStateException.class,
                () -> missingCodec.unmarshal(PairSeq.of()));
        IllegalStateException wrongMarshal = assertThrows(IllegalStateException.class,
                () -> wrongMarshalCodec.marshal(new WrongMarshalValue()));
        IllegalStateException wrongFactory = assertThrows(IllegalStateException.class,
                () -> wrongFactoryCodec.unmarshal(PairSeq.of()));

        assertTrue(missingMarshal.getMessage().contains("marshal"));
        assertTrue(missingUnmarshal.getMessage().contains("unmarshal"));
        assertTrue(wrongMarshal.getMessage().contains("must return PairSeq"));
        assertTrue(wrongFactory.getMessage().contains("must return"));
        System.out.println("...negativeCases=4");
        System.out.println("missingAndIncompatibleMethodsReportContext...ok");
    }

    @Test
    void targetFailuresRetainInvocationContext() {
        System.out.println("targetFailuresRetainInvocationContext");
        PairSeqCodec<ThrowingValue> codec = new PairSeqCodec<>(ThrowingValue.class);

        IllegalStateException marshalFailure = assertThrows(IllegalStateException.class,
                () -> codec.marshal(new ThrowingValue()));
        IllegalStateException unmarshalFailure = assertThrows(IllegalStateException.class,
                () -> codec.unmarshal(PairSeq.of()));

        assertTrue(marshalFailure.getMessage().contains("marshal() failed"));
        assertTrue(unmarshalFailure.getMessage().contains("unmarshal(PairSeq) failed"));
        assertTrue(marshalFailure.getCause() instanceof java.lang.reflect.InvocationTargetException);
        assertTrue(unmarshalFailure.getCause() instanceof java.lang.reflect.InvocationTargetException);
        System.out.println("...causesPreserved=true");
        System.out.println("targetFailuresRetainInvocationContext...ok");
    }

    @Test
    void nullInputsAreRejected() {
        System.out.println("nullInputsAreRejected");
        PairSeqCodec<FactoryValue> codec = new PairSeqCodec<>(FactoryValue.class);

        assertThrows(NullPointerException.class, () -> new PairSeqCodec<FactoryValue>(null));
        assertThrows(NullPointerException.class, () -> codec.marshal(null));
        assertThrows(NullPointerException.class, () -> codec.unmarshal(null));

        System.out.println("...nullCases=3");
        System.out.println("nullInputsAreRejected...ok");
    }

    @Test
    void concurrentFirstAccessUsesOneCachedPlan() throws Exception {
        System.out.println("concurrentFirstAccessUsesOneCachedPlan");
        int taskCount = 24;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<PlanPair>> futures = new ArrayList<>();
            for (int index = 0; index < taskCount; index++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    PairSeqCodec<ConcurrentValue> codec = new PairSeqCodec<>(ConcurrentValue.class);
                    ConcurrentValue value = codec.unmarshal(codec.marshal(new ConcurrentValue("gamma")));
                    assertEquals("gamma", value.value);
                    return new PlanPair(PairSeqCodec.cachedMarshalPlan(ConcurrentValue.class),
                            PairSeqCodec.cachedUnmarshalPlan(ConcurrentValue.class));
                }));
            }
            start.countDown();
            PlanPair expectedPlans = futures.get(0).get();
            for (Future<PlanPair> future : futures) {
                PlanPair actualPlans = future.get();
                assertSame(expectedPlans.marshal(), actualPlans.marshal());
                assertSame(expectedPlans.unmarshal(), actualPlans.unmarshal());
            }
            assertEquals(1, PairSeqCodec.marshalResolutionCount(ConcurrentValue.class));
            assertEquals(1, PairSeqCodec.unmarshalResolutionCount(ConcurrentValue.class));
        } finally {
            executor.shutdownNow();
        }

        System.out.println("...completedTasks=" + taskCount);
        System.out.println("concurrentFirstAccessUsesOneCachedPlan...ok");
    }

    /**
     * Test value exposing marshal and static-factory conventions.
     */
    public static final class FactoryValue {
        private final String value;

        /**
         * Creates a test value.
         *
         * @param value stored value
         */
        public FactoryValue(String value) {
            this.value = value;
        }

        /**
         * Marshals this test value.
         *
         * @return pair representation
         */
        public PairSeq marshal() {
            return PairSeq.of("value", value);
        }

        /**
         * Reconstructs a test value.
         *
         * @param representation pair representation
         * @return reconstructed value
         */
        public static FactoryValue unmarshal(PairSeq representation) {
            return new FactoryValue(representation.valAt(0));
        }
    }

    /**
     * Test value exposing marshal and constructor conventions.
     */
    public static final class ConstructorValue {
        private final String value;

        /**
         * Creates a test value.
         *
         * @param value stored value
         */
        public ConstructorValue(String value) {
            this.value = value;
        }

        /**
         * Reconstructs a test value.
         *
         * @param representation pair representation
         */
        public ConstructorValue(PairSeq representation) {
            this(representation.valAt(0));
        }

        /**
         * Marshals this test value.
         *
         * @return pair representation
         */
        public PairSeq marshal() {
            return PairSeq.of("value", value);
        }
    }

    /**
     * Test value with no codec conventions.
     */
    public static final class MissingValue {
    }

    /**
     * Test value with an incompatible marshal return.
     */
    public static final class WrongMarshalValue {
        /**
         * Returns an intentionally incompatible representation.
         *
         * @return incompatible value
         */
        public String marshal() {
            return "wrong";
        }
    }

    /**
     * Test value with an incompatible factory return.
     */
    public static final class WrongFactoryValue {
        /**
         * Returns an intentionally incompatible value.
         *
         * @param representation ignored representation
         * @return incompatible value
         */
        public static String unmarshal(PairSeq representation) {
            return representation.valAt(0);
        }
    }

    /**
     * Test value whose codec operations fail.
     */
    public static final class ThrowingValue {
        /**
         * Fails during marshalling.
         *
         * @return no value
         * @throws IllegalArgumentException always
         */
        public PairSeq marshal() {
            throw new IllegalArgumentException("marshal target");
        }

        /**
         * Fails during unmarshalling.
         *
         * @param representation ignored representation
         * @return no value
         * @throws IllegalArgumentException always
         */
        public static ThrowingValue unmarshal(PairSeq representation) {
            throw new IllegalArgumentException("unmarshal target");
        }
    }

    /**
     * Test value whose factory declares a compatible broad return type.
     */
    public static final class BroadFactoryValue {
        private final String value;

        /**
         * Creates a test value.
         *
         * @param value stored value
         */
        public BroadFactoryValue(String value) {
            this.value = value;
        }

        /**
         * Reconstructs a test value through a broadly declared return type.
         *
         * @param representation pair representation
         * @return reconstructed value as {@link Object}
         */
        public static Object unmarshal(PairSeq representation) {
            return new BroadFactoryValue(representation.valAt(0));
        }
    }

    /**
     * Test value reserved for concurrent cold-cache access.
     */
    public static final class ConcurrentValue {
        private final String value;

        /**
         * Creates a test value.
         *
         * @param value stored value
         */
        public ConcurrentValue(String value) {
            this.value = value;
        }

        /**
         * Marshals this test value.
         *
         * @return pair representation
         */
        public PairSeq marshal() {
            return PairSeq.of("value", value);
        }

        /**
         * Reconstructs a test value.
         *
         * @param representation pair representation
         * @return reconstructed value
         */
        public static ConcurrentValue unmarshal(PairSeq representation) {
            return new ConcurrentValue(representation.valAt(0));
        }
    }

    private record PlanPair(Object marshal, Object unmarshal) {
    }
}
