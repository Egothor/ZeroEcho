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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.backup.BackupArtifact;
import zeroecho.pki.api.backup.RestoreRequest;
import zeroecho.pki.spi.store.PkiStore;

class StoreBackedBackupServiceTest {
    @Test
    void restoreNeverDelegatesToCustomStore() {
        PkiStore store = (PkiStore) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                    throw new AssertionError("Store must not be invoked: " + method.getName());
                });
        StoreBackedBackupService service = new StoreBackedBackupService(store);
        BackupArtifact artifact = new BackupArtifact(new PkiId("backup-test"),
                new EncodedObject(Encoding.BINARY, new byte[] { 0, 1, 2 }));
        AttributeSet attributes = new AttributeSet() {
            public java.util.Set<zeroecho.pki.api.attr.AttributeId> ids() { return java.util.Set.of(); }
            public java.util.Optional<zeroecho.pki.api.attr.AttributeValue> get(zeroecho.pki.api.attr.AttributeId id) {
                return java.util.Optional.empty();
            }
            public java.util.List<zeroecho.pki.api.attr.AttributeValue> getAll(zeroecho.pki.api.attr.AttributeId id) {
                return java.util.List.of();
            }
        };
        RestoreRequest request = new RestoreRequest(artifact, attributes);
        assertThrows(UnsupportedOperationException.class, () -> service.restoreBackup(request));
    }
}
