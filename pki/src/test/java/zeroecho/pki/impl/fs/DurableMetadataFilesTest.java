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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests bounded durable metadata mutation and failure classification. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class DurableMetadataFilesTest {

    @AfterEach
    void clearFault() {
        DurableMetadataFiles.clearFault();
    }

    @Test
    void moveAndDeleteDirectoryForceFailuresAreUncertain(@TempDir Path directory) throws Exception {
        System.out.println("moveAndDeleteDirectoryForceFailuresAreUncertain");
        Path record = directory.resolve("record.bin");
        failAt(DurableMetadataFiles.FaultPoint.DIRECTORY_FORCE_AFTER_MOVE);
        DurableMetadataFiles.UncertainAfterMutationException moved = assertThrows(
                DurableMetadataFiles.UncertainAfterMutationException.class,
                () -> DurableMetadataFiles.create(record, 32L, output -> output.writeInt(7)));
        assertEquals(DurableMetadataFiles.Mutation.MOVE, moved.mutation(), "move must be classified explicitly");
        DurableMetadataFiles.clearFault();
        assertEquals(Integer.valueOf(7), DurableMetadataFiles.read(record, 32L, input -> input.readInt()),
                "record must remain committed after uncertain move");

        failAt(DurableMetadataFiles.FaultPoint.DIRECTORY_FORCE_AFTER_DELETE);
        DurableMetadataFiles.UncertainAfterMutationException deleted = assertThrows(
                DurableMetadataFiles.UncertainAfterMutationException.class,
                () -> DurableMetadataFiles.delete(record));
        assertEquals(DurableMetadataFiles.Mutation.DELETE, deleted.mutation(),
                "delete must be classified explicitly");
        assertFalse(Files.exists(record), "record must be absent after uncertain delete");
        System.out.println("moveAndDeleteDirectoryForceFailuresAreUncertain...ok");
    }

    @Test
    void preMoveFailureCleansTemporaryAndBoundedDecodeRejectsOversize(@TempDir Path directory) throws Exception {
        System.out.println("preMoveFailureCleansTemporaryAndBoundedDecodeRejectsOversize");
        Path record = directory.resolve("record.bin");
        failAt(DurableMetadataFiles.FaultPoint.FILE_FORCE);
        assertThrows(IOException.class,
                () -> DurableMetadataFiles.create(record, 32L, output -> output.writeLong(9L)));
        DurableMetadataFiles.clearFault();
        assertFalse(Files.exists(record), "pre-move failure must not publish the record");
        assertTrue(DurableMetadataFiles.list(directory, ".tmp").isEmpty(), "temporary metadata must be cleaned");

        DurableMetadataFiles.create(record, 32L, output -> output.writeLong(9L));
        assertThrows(IOException.class, () -> DurableMetadataFiles.read(record, 4L, input -> input.readInt()));
        System.out.println("preMoveFailureCleansTemporaryAndBoundedDecodeRejectsOversize...ok");
    }

    @Test
    @RequiresSymlinkCreation
    void secureOpenRejectsSymlinkAndFaultsExplicitly(@TempDir Path directory) throws Exception {
        System.out.println("secureOpenRejectsSymlinkAndFaultsExplicitly");
        Path external = directory.resolve("external.bin");
        DurableMetadataFiles.create(external, 32L, output -> output.writeInt(3));
        Path link = directory.resolve("link.bin");
        Files.createSymbolicLink(link, external.getFileName());
        assertThrows(IOException.class, () -> DurableMetadataFiles.read(link, 32L, input -> input.readInt()));

        failAt(DurableMetadataFiles.FaultPoint.SECURE_OPEN);
        assertThrows(IOException.class, () -> DurableMetadataFiles.read(external, 32L, input -> input.readInt()));
        System.out.println("secureOpenRejectsSymlinkAndFaultsExplicitly...ok");
    }

    private static void failAt(DurableMetadataFiles.FaultPoint expected) {
        DurableMetadataFiles.installFault(actual -> {
            if (actual == expected) {
                throw new IOException("injected metadata fault");
            }
        });
    }
}
