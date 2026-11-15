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

package zeroecho.pki.api.issuance;

import static org.junit.jupiter.api.Assertions.*;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;

class ManagedOcspProvisioningIdentityTest {
    @Test void matchesIndependentLengthFramedVectorsAndSeparatesCoreFromRealmMapping() {
        // Public synthetic DER fixtures: Python hashlib/struct independently generated these framed hash vectors.
        var primary = new EncodedObject(Encoding.DER, HexFormat.of().parseHex("302a300506032b6570032100" + "00".repeat(32)));
        var alternative = new EncodedObject(Encoding.DER, HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        var authority = new PkiId("authority"); var issuer = new PkiId("issuer");
        String core = ManagedOcspProvisioningIdentity.coreSlotId(authority,issuer,primary,alternative);
        assertEquals("45102be8ed3784fb9f41b86ee1f3a4d51cd173e151ef1991a8640242c11a1c27",core);
        assertEquals("8b9f832f5b3b81b1eeb392be4fa96b806835c28c8f559670424f1f378dcc20eb",
                ManagedOcspProvisioningIdentity.serverSlotId("realm",core));
        assertEquals(core,ManagedOcspProvisioningIdentity.coreSlotId(authority,issuer,
                new EncodedObject(Encoding.DER,primary.bytes()),new EncodedObject(Encoding.DER,alternative.bytes())));
        assertNotEquals(core,ManagedOcspProvisioningIdentity.coreSlotId(authority,issuer,alternative,primary));
        assertNotEquals(core,ManagedOcspProvisioningIdentity.coreSlotId(authority,new PkiId("next-issuer"),primary,alternative));
        assertNotEquals(ManagedOcspProvisioningIdentity.serverSlotId("realm",core),ManagedOcspProvisioningIdentity.serverSlotId("other-realm",core));
        assertEquals("ocsp-prov:"+core+":r1",ManagedOcspProvisioningIdentity.coreIssuanceId(core,1));
        assertThrows(IllegalArgumentException.class,()->ManagedOcspProvisioningIdentity.coreIssuanceId(core,0));
        assertThrows(IllegalArgumentException.class,()->ManagedOcspProvisioningIdentity.serverSlotId("untrusted realm",core));
    }
}
