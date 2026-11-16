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
package zeroecho.pki.api.ca;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.*;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Contract and regression tests for ca rotation selection.
 */
class CaRotationSelectionTest {
    /**
     * Primary key replacement preserves alternative and exact outgoing algorithm.
     */
    @Test void primaryKeyReplacementPreservesAlternativeAndExactOutgoingAlgorithm() {
        var retained = binding(true);
        var effective = CaRotationSelection.primaryKey(new KeyRef("replacement")).effective(retained);
        assertEquals(new KeyRef("replacement"), effective.primary().orElseThrow().keyRef().orElseThrow());
        assertEquals(retained.primary().signatureAlgorithm().canonicalForm(),
                effective.primary().orElseThrow().signatureAlgorithmId().orElseThrow());
        assertEquals(retained.alternative().orElseThrow().keyRef(),
                effective.alternative().orElseThrow().keyRef().orElseThrow());
    }

    /**
     * Alternative algorithm only retains both keys and cannot add missing role.
     */
    @Test void alternativeAlgorithmOnlyRetainsBothKeysAndCannotAddMissingRole() {
        var change = new CaRotationSelection(1, Optional.empty(), Optional.of(new CaRotationSelection.RoleChange(
                Optional.empty(), Optional.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm()))));
        var retained = binding(true);
        var effective = change.effective(retained);
        assertEquals(retained.primary().keyRef(), effective.primary().orElseThrow().keyRef().orElseThrow());
        assertEquals(retained.alternative().orElseThrow().keyRef(), effective.alternative().orElseThrow().keyRef().orElseThrow());
        assertEquals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm(),
                effective.alternative().orElseThrow().signatureAlgorithmId().orElseThrow());
        assertThrows(IllegalArgumentException.class, () -> change.effective(binding(false)));
    }

    /**
     * Rejects missing role and ambiguous algorithm input.
     */
    @Test void rejectsMissingRoleAndAmbiguousAlgorithmInput() {
        assertThrows(IllegalArgumentException.class, () -> new CaRotationSelection(1, Optional.empty(), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new CaRotationSelection.RoleChange(Optional.empty(), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new CaRotationSelection.RoleChange(Optional.empty(), Optional.of(" RSA ")));
        assertThrows(NullPointerException.class, () -> CaRotationSelection.primaryKey(null));
    }

    private static IssuerCryptographicBinding binding(boolean alternative) {
        var ca = new PkiId("ca"); var credential = new PkiId("credential");
        var key = new IssuerKeyBinding(new KeyRef("primary"), BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, new EncodedObject(Encoding.DER,
                        java.util.HexFormat.of().parseHex("300d06092a864886f70d01010b0500")), "0".repeat(64));
        var alt = new IssuerKeyBinding(new KeyRef("alternative"), key.publicKeyAlgorithm(), key.signatureAlgorithm(),
                key.signatureAlgorithmIdentifier(), "1".repeat(64));
        return new IssuerCryptographicBinding(1, IssuerGeneration.idFor(ca, credential), ca, credential, "x509", key,
                alternative ? Optional.of(alt) : Optional.empty(), "2".repeat(64),
                new CertificateProfileRef("root", 1, new byte[32]), "3".repeat(64), alternative
                        ? IssuerCryptographicBinding.HybridSignatureBaseline.COR3_SIGNED_WRAPPER
                        : IssuerCryptographicBinding.HybridSignatureBaseline.NONE, "4".repeat(64));
    }
}
