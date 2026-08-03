/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project license are met.
 *******************************************************************************/
package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.content.DurableContentReference;

final class CredentialContentBoundaryTest {

    @Test
    void certificateLimitPrecedesStagingValidationAndMaterialization() {
        System.out.println("certificateLimitPrecedesStagingValidationAndMaterialization");
        byte[] oversized = new byte[CredentialContent.MAXIMUM_CERTIFICATE_BYTES + 1];
        DurableContentReference oversizedReference = reference(oversized.length);
        DurableContentReference negativeLengthReference = reference(-1L);
        DurableContentReference zeroLengthReference = reference(0L);
        DurableContentReference nonDerReference = reference(1L, Encoding.PEM);
        assertThrows(PkiException.class, () -> CredentialContent.stage(null, oversized));
        assertThrows(PkiException.class, () -> CredentialContent.materializeForBc(null, oversizedReference));
        assertThrows(PkiException.class,
                () -> CredentialContent.validateCertificate(null, oversizedReference, null, Optional.empty()));
        assertThrows(PkiException.class, () -> CredentialContent.materializeForBc(null, negativeLengthReference));
        assertThrows(PkiException.class,
                () -> CredentialContent.validateCertificate(null, negativeLengthReference, null, Optional.empty()));
        assertThrows(PkiException.class, () -> CredentialContent.materializeForBc(null, zeroLengthReference));
        assertThrows(PkiException.class,
                () -> CredentialContent.validateCertificate(null, zeroLengthReference, null, Optional.empty()));
        assertThrows(PkiException.class, () -> CredentialContent.materializeForBc(null, nonDerReference));
        assertThrows(PkiException.class,
                () -> CredentialContent.validateCertificate(null, nonDerReference, null, Optional.empty()));
        System.out.println("...rejected=staging, validation, materialization, invalid length and encoding");
        System.out.println("certificateLimitPrecedesStagingValidationAndMaterialization...ok");
    }

    private static DurableContentReference reference(long length) {
        return reference(length, Encoding.DER);
    }

    private static DurableContentReference reference(long length, Encoding encoding) {
        return new DurableContentReference() {
            @Override
            public String storeId() {
                return "test:store";
            }

            @Override
            public String contentId() {
                return "test:oversized";
            }

            @Override
            public Encoding encoding() {
                return encoding;
            }

            @Override
            public long length() {
                return length;
            }

            @Override
            public String sha256() {
                return "0".repeat(64);
            }

            @Override
            public Lifecycle lifecycle() {
                return Lifecycle.PERSISTED;
            }
        };
    }
}
