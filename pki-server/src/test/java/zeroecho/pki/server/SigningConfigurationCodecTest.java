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

package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class SigningConfigurationCodecTest {
    private static final String SIGNING = """
        "signing": {
          "provider": {"id": "zeroecho-lib", "properties": {}},
          "signatureAlgorithm": "configured-signature",
          "signingTtlMillis": 30000,
          "pureEdDsaMaximumTbsBytes": 1048576,
          "topology": {
            "coordinator": {"pageSize": 2, "claimLeaseMillis": 10000,
              "providerCallTimeoutMillis": 5000, "idlePollIntervalMillis": 10, "closeTimeoutMillis": 5000},
            "exactGroups": [{"keyRefs": ["key:a"], "lanePool": {"laneCount": 1, "prefetchSize": 1}}],
            "catchAll": {"laneCount": 1, "prefetchSize": 1}
          }
        },
        """;

    @Test
    void decodesOnlyCurrentProviderAndFiniteTopology() throws Exception {
        PkiServerConfiguration result = decode(SIGNING);
        zeroecho.pki.application.PkiSessionConfiguration.SigningConfiguration signing =
                result.realm().pkiSessionConfiguration().signing().orElseThrow();
        assertEquals("zeroecho-lib", signing.provider().backendId());
        assertEquals(2, signing.topology().totalLaneCount());
        assertEquals(1, signing.topology().exactGroups().size());
        assertEquals("key:a", signing.topology().exactGroups().getFirst().keyRefs().getFirst().value());
        assertEquals(1048576L, signing.pureEdDsaMaximumTbsBytes().orElseThrow());
    }

    @Test
    void rejectsRemovedRoutingAndDefaultFieldsWithoutAdapters() throws Exception {
        for (String field : java.util.List.of("workflow", "framework", "signingServices", "caRouting",
                "laneCount", "queueCapacity", "certificateSignatureBinding")) {
            assertThrows(IllegalArgumentException.class, () -> decode(
                    SIGNING.replace("\"provider\":", "\"" + field + "\":{},\"provider\":")));
        }
        assertThrows(IllegalArgumentException.class, () -> decode(
                SIGNING.replace("\"provider\":", "\"workflow\":")));
    }

    @Test
    void rejectsMissingCatchAllAndOverlappingExactKeys() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> decode(
                SIGNING.replace("\"catchAll\":", "\"unknownPool\":")));
        assertThrows(IllegalArgumentException.class, () -> decode(
                SIGNING.replace("[\"key:a\"]", "[\"key:a\",\"key:a\"]")));
    }

    private static PkiServerConfiguration decode(String signing) throws Exception {
        String example = Files.readString(Path.of("..", "docs", "pki-server-production-example.json"));
        return PkiServerConfigurationCodec.decode(example.replace("\"publishers\": []",
                signing + "\"publishers\": []").getBytes(StandardCharsets.UTF_8));
    }
}
