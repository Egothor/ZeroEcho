/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.core.alg.common.agreement;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import javax.crypto.KeyAgreement;

/**
 * Package-private reusable JCA agreement mechanics.
 */
final class JcaAgreementEngine {
    private final PrivateKey privateKey;
    private final String jcaName;
    private final String provider;
    private PublicKey peer;

    /* default */ JcaAgreementEngine(PrivateKey privateKey, String jcaName, String provider) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
        this.jcaName = Objects.requireNonNull(jcaName, "jcaName must not be null");
        this.provider = provider;
    }

    /* default */ PrivateKey privateKey() {
        return privateKey;
    }

    /* default */ void setPeerPublic(PublicKey peer) {
        this.peer = peer;
    }

    /* default */ byte[] deriveSecret() {
        if (peer == null) {
            throw new IllegalStateException("Peer public key not set");
        }
        try {
            KeyAgreement agreement = provider == null ? KeyAgreement.getInstance(jcaName)
                    : KeyAgreement.getInstance(jcaName, provider);
            agreement.init(privateKey);
            agreement.doPhase(peer, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("KeyAgreement failed for " + jcaName, exception);
        }
    }
}
