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
package zeroecho.pki.api.hybrid.sdk;

import static org.junit.jupiter.api.Assertions.*;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.PkiId;

/**
 * Contract and regression tests for SDK lifecycle target.
 */
class SdkLifecycleTargetTest {
    /**
     * Lifecycle commitment distinguishes operation predecessor and requested keys.
     */
    @Test void lifecycleCommitmentDistinguishesOperationPredecessorAndRequestedKeys() {
        var target = target("credential.renew", "old", "a");
        assertEquals(target, SdkLifecycleTarget.decode(target.value()));
        assertFalse(java.util.Arrays.equals(target.value().encode(), target("credential.reissue", "old", "a").value().encode()));
        assertFalse(java.util.Arrays.equals(target.value().encode(), target("credential.renew", "other", "a").value().encode()));
        assertFalse(java.util.Arrays.equals(target.value().encode(), target("credential.renew", "old", "b").value().encode()));
    }

    /**
     * Rejects unknown missing and wrong typed extension members.
     */
    @Test void rejectsUnknownMissingAndWrongTypedExtensionMembers() {
        var fields = new TreeMap<>(target("credential.replace", "old", "a").value().objectFields());
        fields.put("unexpected", HybridSdkValue.text("ignored"));
        assertThrows(IllegalArgumentException.class, () -> SdkLifecycleTarget.decode(HybridSdkValue.object(fields)));
        fields.remove("unexpected"); fields.remove("predecessorId");
        assertThrows(IllegalArgumentException.class, () -> SdkLifecycleTarget.decode(HybridSdkValue.object(fields)));
        fields.put("predecessorId", HybridSdkValue.text("old")); fields.put("version", HybridSdkValue.text("1"));
        assertThrows(IllegalArgumentException.class, () -> SdkLifecycleTarget.decode(HybridSdkValue.object(fields)));
        assertThrows(IllegalArgumentException.class, () -> target("credential.issue", "old", "a"));
    }

    private static SdkLifecycleTarget target(String operation, String predecessor, String primary) {
        return new SdkLifecycleTarget(1, operation, new PkiId(predecessor), "sha256:" + "0".repeat(64),
                "sha512:" + primary.repeat(128), "sha512:" + "c".repeat(128));
    }
}
