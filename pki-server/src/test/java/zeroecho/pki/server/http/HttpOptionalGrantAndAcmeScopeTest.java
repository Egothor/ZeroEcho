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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.server.*;

/**
 * Regression coverage for optional grant conditions and complete ACME registration scope.
 */
class HttpOptionalGrantAndAcmeScopeTest {
    private static final OperationSecurityDescriptors DESCRIPTORS=new OperationSecurityDescriptors();
    private static final RealmId REALM=new RealmId("codec-regression");
    private static final String GRANT="\"grantId\":\"owned-grant\",\"principalId\":\"owned-user\",\"effect\":\"ALLOW\",\"action\":\"REALM_READ\",\"resourceType\":\"REALM\",\"relationship\":\"ANY\",\"dataView\":\"METADATA_REDACTED\"";

    /**
     * Checks that omitted and explicitly empty grant conditions both decode to an empty immutable condition set.
     */
    @Test void omittedAndExplicitEmptyConditionsHaveIdenticalEmptyMeaning() {
        for(String suffix:new String[]{"",",\"conditions\":[]"}) {
            var decoded=decode("security.grant.create","{\"version\":1,\"arguments\":{"+GRANT+suffix+"}}");
            var control=assertInstanceOf(AdministrativeOperation.Control.class,decoded.operation());
            var grant=assertInstanceOf(ServerControlOperation.CreateGrant.class,control.operation()).grant();
            assertEquals(Set.of(),grant.conditions());
        }
    }

    /**
     * Rejects null/scalar/unknown/duplicate condition forms and accepts one explicit reason-required condition.
     */
    @Test void presentConditionsRemainStrictAndUnique() {
        for(String invalid:new String[]{"null","true","\"REASON_REQUIRED\"","[\"UNKNOWN\"]","[\"REASON_REQUIRED\",\"REASON_REQUIRED\"]"}) {
            assertThrows(IllegalArgumentException.class,()->decode("security.grant.create","{\"version\":1,\"arguments\":{"+GRANT+",\"conditions\":"+invalid+"}}"));
        }
        var decoded=decode("security.grant.create","{\"version\":1,\"arguments\":{"+GRANT+",\"conditions\":[\"REASON_REQUIRED\"]}}");
        var grant=assertInstanceOf(ServerControlOperation.CreateGrant.class,assertInstanceOf(AdministrativeOperation.Control.class,decoded.operation()).operation()).grant();
        assertEquals(Set.of(Permission.Condition.REASON_REQUIRED),grant.conditions());
    }

    /**
     * Checks preservation of directory authority/profile scope and rejection when only the outer authority is changed.
     */
    @Test void acmeRegistrationCarriesAuthorityAndProfileAndRejectsWrongAuthority() {
        String json="{\"version\":1,\"authorityId\":\"owned-ca\",\"arguments\":{\"alias\":\"owned-directory\",\"authorityId\":\"owned-ca\",\"profileId\":\"server-tls\",\"enrollmentProfileId\":\"owned-enrollment\",\"dnsNamespaces\":[\"example.invalid\"],\"maximumValidityMillis\":3600000,\"publicKeyAlgorithms\":[\"ECDSA\"],\"x509BindingPolicies\":[\"STANDARD_ONLY\"],\"challengeTypes\":[\"DNS_01\"],\"challengeProviderIds\":[\"owned-dns\"],\"eabRequired\":false}}";
        var decoded=decode("acme.directory.register",json);
        assertEquals(Optional.of(new PkiId("owned-ca")),decoded.resource().scope().authorityId());
        assertEquals(Optional.of("server-tls"),decoded.resource().scope().profileId());
        assertThrows(IllegalArgumentException.class,()->decode("acme.directory.register",json.replaceFirst("owned-ca","other-ca")));
    }

    private static HttpOperationCodec.Decoded decode(String operation,String document) {
        return HttpOperationCodec.decode(operation,document.getBytes(StandardCharsets.UTF_8),262144,REALM,DESCRIPTORS::require);
    }
}
