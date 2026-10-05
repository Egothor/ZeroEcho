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
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.elgamal.ElgamalAlgorithm;
import zeroecho.core.alg.elgamal.ElgamalKeyGenSpec;
import zeroecho.core.alg.elgamal.ElgamalParamSpec;
import zeroecho.core.alg.hmac.HmacAlgorithm;
import zeroecho.core.alg.rsa.RsaAlgorithm;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;

class ParameterDescriptorTest {
    private static final SecurityLevel LEVEL = SecurityLevel.classical(112);

    @Test
    void rejectsInvalidMapsBeforeCallingDelegateAndAppliesDefaults() {
        AtomicInteger calls = new AtomicInteger();
        List<TemplateParameter> parameters = new ArrayList<>(List.of(
                new TemplateParameter("bits", "Bits", Integer.class, "Modulus size"),
                new TemplateParameter("exponent", "Exponent", Integer.class, "Public exponent")));
        List<ParameterConstraint> constraints = new ArrayList<>(List.of(
                new ParameterConstraint("bits", ParameterConstraint.ValueKind.INTEGER, true,
                        null, List.of(1024, 2048), 1024L, 4096L, 1, 0),
                new ParameterConstraint("exponent", ParameterConstraint.ValueKind.INTEGER, false,
                        65537, List.of(), 3L, null, 2, 1)));
        ParameterSetDescriptor.Template<RsaKeyGenSpec> template = new ParameterSetDescriptor.Template<>(
                "rsa", "RSA", LEVEL, parameters, constraints, values -> {
                    calls.incrementAndGet();
                    assertThrows(UnsupportedOperationException.class, () -> values.put("other", 1));
                    return new RsaKeyGenSpec((Integer) values.get("bits"), (Integer) values.get("exponent"));
                });
        parameters.clear();
        constraints.clear();
        assertEquals(2, template.parameters().size());
        assertEquals(2, template.constraints().size());
        assertThrows(UnsupportedOperationException.class, () -> template.constraints().clear());
        for (Map<String, Object> invalid : List.<Map<String, Object>>of(Map.of(), Map.of("bits", "2048"),
                Map.of("bits", 2048L), Map.of("bits", 512), Map.of("bits", 3072),
                Map.of("bits", 8192), Map.of("bits", 2048, "unknown", 0),
                Map.of("bits", 2048, "exponent", 4))) {
            assertThrows(IllegalArgumentException.class, () -> template.factory().apply(invalid));
        }
        Map<String, Object> nullValue = new HashMap<>();
        nullValue.put("bits", null);
        assertThrows(IllegalArgumentException.class, () -> template.factory().apply(nullValue));
        assertThrows(IllegalArgumentException.class, () -> template.factory().apply(null));
        assertEquals(0, calls.get());
        assertEquals(65537, template.factory().apply(Map.of("bits", 2048)).publicExponent());
        assertEquals(1, calls.get());
    }

    @Test
    void validatesMetadataAndLegacyConstructorWithoutChangingRecordShape() {
        assertEquals(4, TemplateParameter.class.getRecordComponents().length);
        assertEquals(5, ParameterSetDescriptor.Template.class.getRecordComponents().length);
        TemplateParameter bits = new TemplateParameter("bits", "Bits", Integer.class, "Size");
        assertThrows(IllegalArgumentException.class, () -> new TemplateParameter(" ", "Bits", Integer.class, "Size"));
        assertThrows(IllegalArgumentException.class, () -> new ParameterSetDescriptor.Concrete<>(
                "", "RSA", LEVEL, RsaKeyGenSpec.rsa2048()));
        assertThrows(IllegalArgumentException.class, () -> new ParameterSetDescriptor.Template<>(
                "rsa", " ", LEVEL, List.of(bits), values -> RsaKeyGenSpec.rsa2048()));
        assertThrows(IllegalArgumentException.class, () -> new ParameterSetDescriptor.Template<>(
                "rsa", "RSA", LEVEL, List.of(bits, bits), values -> RsaKeyGenSpec.rsa2048()));
        ParameterSetDescriptor.Template<RsaKeyGenSpec> legacy = new ParameterSetDescriptor.Template<>(
                "rsa", "RSA", LEVEL, List.of(bits), values -> new RsaKeyGenSpec(
                        (Integer) values.getOrDefault("bits", 2048), 65537));
        assertEquals(2048, legacy.factory().apply(Map.of()).keySize());
        assertThrows(IllegalArgumentException.class, () -> legacy.factory().apply(Map.of("bits", "2048")));
        assertThrows(IllegalArgumentException.class, () -> ParameterSetDescriptor.snapshot(List.of(legacy, legacy)));
        assertThrows(IllegalArgumentException.class, () -> new ParameterConstraint("bits",
                ParameterConstraint.ValueKind.INTEGER, true, 512, List.of(), 1024L, null, 1, 0));
    }

    @Test
    void builtInTemplatesDeclareExecutableConstraints() {
        ParameterSetDescriptor.Template<?> rsa = (ParameterSetDescriptor.Template<?>) new RsaAlgorithm()
                .parameterSets().stream().filter(item -> item instanceof ParameterSetDescriptor.Template<?>).findFirst().orElseThrow();
        RsaKeyGenSpec spec = (RsaKeyGenSpec) rsa.factory().apply(Map.of("keySizeBits", 1024));
        assertEquals(65537, spec.publicExponent());
        assertThrows(IllegalArgumentException.class, () -> rsa.factory().apply(Map.of("keySizeBits", 2048, "publicExponent", 2)));
        ParameterSetDescriptor.Template<?> hmac = (ParameterSetDescriptor.Template<?>) new HmacAlgorithm()
                .parameterSets().stream().filter(item -> item instanceof ParameterSetDescriptor.Template<?>).findFirst().orElseThrow();
        assertThrows(IllegalArgumentException.class, () -> hmac.factory().apply(Map.of("macName", "HmacSHA256", "keySizeBits", 9)));
        assertThrows(IllegalArgumentException.class, () -> hmac.factory().apply(Map.of("macName", "missing", "keySizeBits", 128)));
        assertTrue(hmac.factory().apply(Map.of("macName", "HmacSHA256", "keySizeBits", 128)) != null);
        ElgamalAlgorithm elgamal = new ElgamalAlgorithm();
        assertFalse(elgamal.parameterSets().stream().anyMatch(item -> item.id().equals("elgamal-custom")));
        assertTrue(((ParameterSetDescriptor.Concrete<?>) elgamal.parameterSets().getFirst()).spec() instanceof ElgamalParamSpec);
        assertThrows(IllegalArgumentException.class, () -> elgamal.asymmetricKeyPairGenerator(ElgamalKeyGenSpec.class));
    }
}
