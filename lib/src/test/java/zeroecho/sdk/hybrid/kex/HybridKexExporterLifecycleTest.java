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
package zeroecho.sdk.hybrid.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class HybridKexExporterLifecycleTest {

    @Test
    void constructorOwnsDefensiveCopies() throws Exception {
        System.out.println("constructorOwnsDefensiveCopies");
        byte[] root = filled(32, (byte) 1);
        byte[] salt = filled(16, (byte) 2);
        HybridKexExporter exporter = new HybridKexExporter(root, salt);
        Arrays.fill(root, (byte) 0);
        Arrays.fill(salt, (byte) 0);

        assertFalse(Arrays.equals(root, exporter.rootSecretCopy()));
        assertArrayEquals(filled(32, (byte) 1), internal(exporter, "rootSecret"));
        assertArrayEquals(filled(16, (byte) 2), internal(exporter, "salt"));
        exporter.close();
        System.out.println("...ownedCopies=true");
        System.out.println("constructorOwnsDefensiveCopies...ok");
    }

    @Test
    void destructionClearsSecretsAndRejectsFurtherUse() throws Exception {
        System.out.println("destructionClearsSecretsAndRejectsFurtherUse");
        HybridKexExporter exporter = new HybridKexExporter(filled(32, (byte) 3), filled(16, (byte) 4));
        byte[] internalRoot = internal(exporter, "rootSecret");
        byte[] internalSalt = internal(exporter, "salt");

        exporter.destroy();
        exporter.destroy();
        exporter.close();

        assertTrue(exporter.isDestroyed());
        assertArrayEquals(new byte[internalRoot.length], internalRoot);
        assertArrayEquals(new byte[internalSalt.length], internalSalt);
        assertThrows(IllegalStateException.class, () -> exporter.export("label", null, 16));
        assertThrows(IllegalStateException.class, exporter::rootSecretCopy);
        System.out.println("...destroyed=true...postDestroyRejected=true");
        System.out.println("destructionClearsSecretsAndRejectsFurtherUse...ok");
    }

    @Test
    void successfulExportDoesNotDestroyExporter() {
        System.out.println("successfulExportDoesNotDestroyExporter");
        HybridKexExporter exporter = new HybridKexExporter(filled(32, (byte) 5), null);

        byte[] first = exporter.export("first", null, 16);
        byte[] second = exporter.export("second", new byte[] { 1 }, 16);

        assertFalse(exporter.isDestroyed());
        assertFalse(Arrays.equals(first, second));
        exporter.close();
        Arrays.fill(first, (byte) 0);
        Arrays.fill(second, (byte) 0);
        System.out.println("...derivedLengths=16,16");
        System.out.println("successfulExportDoesNotDestroyExporter...ok");
    }

    private static byte[] internal(HybridKexExporter exporter, String fieldName) throws Exception {
        Field field = HybridKexExporter.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (byte[]) field.get(exporter);
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }
}
