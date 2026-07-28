/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.core.audit;

import java.lang.reflect.Proxy;
import java.util.Objects;

/**
 * Utilities for enforcing the best-effort audit-listener contract.
 *
 * <p>The returned listener suppresses listener failures without logging callback
 * arguments, because those arguments may refer to sensitive cryptographic
 * objects. Cryptographic operation outcomes therefore never depend on an audit
 * sink's availability.</p>
 *
 * @since 1.0
 */
public final class AuditListeners {
    private AuditListeners() {
        // utility class
    }

    /**
     * Returns a listener facade that cannot interrupt the caller.
     *
     * @param listener listener to protect
     * @return non-throwing listener facade
     * @throws NullPointerException if {@code listener} is {@code null}
     */
    public static AuditListener bestEffort(AuditListener listener) {
        AuditListener target = Objects.requireNonNull(listener, "listener");
        ClassLoader contextLoader = Thread.currentThread().getContextClassLoader();
        ClassLoader loader = contextLoader == null ? ClassLoader.getSystemClassLoader() : contextLoader;
        return (AuditListener) Proxy.newProxyInstance(loader,
                new Class<?>[] { AuditListener.class }, (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return method.invoke(target, arguments);
                    }
                    try {
                        return method.invoke(target, arguments);
                    } catch (ReflectiveOperationException ignored) {
                        return null;
                    }
                });
    }
}
