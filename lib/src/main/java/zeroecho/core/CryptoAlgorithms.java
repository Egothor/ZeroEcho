/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeMap;

/**
 * Immutable registry of {@link CryptoAlgorithm} providers.
 *
 * <p>Providers are discovered once through {@link ServiceLoader}, sorted by
 * canonical algorithm identifier, and retained in one immutable registry.
 * Runtime policy and auditing belong exclusively to explicitly created
 * {@link zeroecho.sdk.ZeroEchoSession} instances.</p>
 *
 * @since 1.0
 */
public final class CryptoAlgorithms {
    private static final Map<String, CryptoAlgorithm> BY_ID = loadRegistry();

    private CryptoAlgorithms() {
    }

    private static Map<String, CryptoAlgorithm> loadRegistry() {
        Map<String, CryptoAlgorithm> algorithms = new TreeMap<>();
        for (CryptoAlgorithm algorithm : ServiceLoader.load(CryptoAlgorithm.class)) {
            CryptoAlgorithm previous = algorithms.put(algorithm.id(), algorithm);
            if (previous != null) {
                throw new IllegalStateException("Duplicate algorithm id: " + algorithm.id());
            }
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(algorithms));
    }

    /* default */ static Map<String, CryptoAlgorithm> registry() {
        return BY_ID;
    }

    /**
     * Returns registered algorithm identifiers in deterministic order.
     *
     * @return unmodifiable set of canonical identifiers
     */
    public static Set<String> available() {
        return BY_ID.keySet();
    }

    /**
     * Resolves an algorithm by canonical identifier.
     *
     * @param id canonical algorithm identifier
     * @return registered algorithm
     * @throws IllegalArgumentException if no algorithm is registered with
     *                                  {@code id}
     */
    public static CryptoAlgorithm require(String id) {
        CryptoAlgorithm algorithm = BY_ID.get(id);
        if (algorithm == null) {
            throw new IllegalArgumentException("Unknown algorithm id: " + id);
        }
        return algorithm;
    }
}
