/* *****************************************************************************
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
