/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.junit.jupiter.api.Test;

import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.sdk.ZeroEchoSession;

class KeyringStoreSecurityTest {
    private static final AtomicBoolean UNREGISTERED_INITIALIZED = new AtomicBoolean();

    @Test
    void rejectsUnregisteredPersistedSpecBeforeClassInitialization() throws Exception {
        System.out.println("rejectsUnregisteredPersistedSpecBeforeClassInitialization");
        KeyringStore store = new KeyringStore(new ZeroEchoSession());
        String text = "# KeyringStore v1\n"
                + "@entry\n"
                + "alias=attacker.pub\n"
                + "algorithm=RSA\n"
                + "kind=PUBLIC_KEY\n"
                + "spec=zeroecho.core.storage.KeyringStoreSecurityTest$UnregisteredSpec\n\n";
        store.importText(text, false);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> store.getPublic("attacker"));

        assertFalse(UNREGISTERED_INITIALIZED.get());
        assertTrue(failure.getMessage().contains("not registered"));
        System.out.println("...classInitialized=false");
        System.out.println("rejectsUnregisteredPersistedSpecBeforeClassInitialization...ok");
    }

    @Test
    void rejectsSpecRegisteredForDifferentOperation() throws Exception {
        System.out.println("rejectsSpecRegisteredForDifferentOperation");
        KeyringStore store = new KeyringStore(new ZeroEchoSession());
        String text = "# KeyringStore v1\n"
                + "@entry\n"
                + "alias=mismatch.pub\n"
                + "algorithm=RSA\n"
                + "kind=PUBLIC_KEY\n"
                + "spec=zeroecho.core.alg.rsa.RsaPrivateKeySpec\n\n";
        store.importText(text, false);

        assertThrows(IllegalArgumentException.class, () -> store.getPublic("mismatch"));
        System.out.println("...mismatchedOperationRejected=true");
        System.out.println("rejectsSpecRegisteredForDifferentOperation...ok");
    }

    @Test
    void temporarySpecDestructionIsIdempotentAndObservable() throws Exception {
        System.out.println("temporarySpecDestructionIsIdempotentAndObservable");
        ControlledDestroyableSpec spec = new ControlledDestroyableSpec(false);

        KeyringStore.destroyTemporarySpec(spec, null);
        KeyringStore.destroyTemporarySpec(spec, null);

        assertTrue(spec.isDestroyed());
        assertEquals(1, spec.destroyCalls);
        System.out.println("...destroyCalls=" + spec.destroyCalls);
        System.out.println("temporarySpecDestructionIsIdempotentAndObservable...ok");
    }

    @Test
    void destructionFailureIsSuppressedOnPrimaryFailure() throws Exception {
        System.out.println("destructionFailureIsSuppressedOnPrimaryFailure");
        ControlledDestroyableSpec spec = new ControlledDestroyableSpec(true);
        IllegalStateException primary = new IllegalStateException("controlled primary");

        KeyringStore.destroyTemporarySpec(spec, primary);

        assertEquals(1, primary.getSuppressed().length);
        assertTrue(primary.getSuppressed()[0] instanceof DestroyFailedException);
        System.out.println("...suppressedFailures=1");
        System.out.println("destructionFailureIsSuppressedOnPrimaryFailure...ok");
    }

    @Test
    void destructionFailureWithoutPrimaryUsesSecurityExceptionFamily() {
        System.out.println("destructionFailureWithoutPrimaryUsesSecurityExceptionFamily");
        ControlledDestroyableSpec spec = new ControlledDestroyableSpec(true);

        GeneralSecurityException failure = assertThrows(GeneralSecurityException.class,
                () -> KeyringStore.destroyTemporarySpec(spec, null));

        assertSame(DestroyFailedException.class, failure.getCause().getClass());
        System.out.println("...failureType=" + failure.getClass().getSimpleName());
        System.out.println("destructionFailureWithoutPrimaryUsesSecurityExceptionFamily...ok");
    }

    /**
     * A deliberately unregistered type whose initialization must never occur.
     */
    public static final class UnregisteredSpec implements AlgorithmKeySpec {
        static {
            UNREGISTERED_INITIALIZED.set(true);
        }
    }

    private static final class ControlledDestroyableSpec implements AlgorithmKeySpec, Destroyable {
        private final boolean fail;
        private boolean destroyed;
        private int destroyCalls;

        private ControlledDestroyableSpec(boolean fail) {
            this.fail = fail;
        }

        @Override
        public void destroy() throws DestroyFailedException {
            destroyCalls++;
            if (fail) {
                throw new DestroyFailedException("controlled destruction failure");
            }
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }
}
