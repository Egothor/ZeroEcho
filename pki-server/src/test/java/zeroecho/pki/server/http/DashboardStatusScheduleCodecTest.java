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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.RealmId;

class DashboardStatusScheduleCodecTest {
    private static final OperationSecurityDescriptors DESCRIPTORS = new OperationSecurityDescriptors();

    @Test void realmMetricsAndScheduleListingRejectAuthorityScopes() {
        for (String operation : new String[]{"dashboard.server", "status.schedule.list"}) {
            String arguments = operation.equals("dashboard.server") ? "{}" : "{\"limit\":10}";
            assertEquals(Optional.empty(), decode(operation, "{\"version\":1,\"arguments\":" + arguments + "}").resource().scope().authorityId());
            assertThrows(IllegalArgumentException.class, () -> decode(operation,
                    "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":" + arguments + "}"));
        }
    }

    @Test void authorityMetricsAndSchedulesRequireMatchingAuthority() {
        for (String operation : new String[]{"dashboard.authority", "dashboard.certificate", "dashboard.revocation",
                "dashboard.publication", "status.schedule.inspect", "status.schedule.set"}) {
            String extra = operation.startsWith("status.") ? ",\"statusType\":\"CRL\"" : "";
            if (operation.equals("status.schedule.set")) extra += ",\"formatId\":\"x509\",\"interval\":\"PT1M\",\"graceSeconds\":0,\"enabled\":true";
            String arguments = "{\"caId\":\"ca-a\"" + extra + "}";
            assertEquals(Optional.of(new PkiId("ca-a")), decode(operation,
                    "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":" + arguments + "}").resource().scope().authorityId());
            assertThrows(IllegalArgumentException.class, () -> decode(operation,
                    "{\"version\":1,\"authorityId\":\"ca-b\",\"arguments\":" + arguments + "}"));
            assertThrows(IllegalArgumentException.class, () -> decode(operation,
                    "{\"version\":1,\"arguments\":" + arguments + "}"));
        }
    }

    private static HttpOperationCodec.Decoded decode(String operation, String body) {
        return HttpOperationCodec.decode(operation, body.getBytes(StandardCharsets.UTF_8), 8192, new RealmId("production"),
                id -> DESCRIPTORS.descriptors().get(id));
    }
}
