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

package zeroecho.pki.server.enrollment;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EnrollmentKeygenSpoolTest {
    @TempDir Path directory;
    private static final String ID = "a".repeat(64);
    private static final byte[] BODY = new byte[] {1, 3, 7, 15};

    @Test void forcedPublicationSurvivesRestartAndBorrowersPinDeletionAndClose() throws Exception {
        EnrollmentRuntimeConfiguration.KeygenArtifacts configuration = configuration();
        try (EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration, 1)) {
            spool.publish(ID, BODY, EnrollmentKeygenSpool.hash(BODY));
            Set<String> names = new HashSet<>();
            spool.inspectFiles(names::add);
            assertEquals(Set.of(ID), names);
        }
        EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration, 1);
        EnrollmentKeygenSpool.Lease lease = spool.acquire(ID, BODY.length, EnrollmentKeygenSpool.hash(BODY));
        assertThrows(IOException.class, () -> spool.acquire(ID, BODY.length, EnrollmentKeygenSpool.hash(BODY)));
        assertFalse(spool.deleteExpired(ID));
        assertThrows(IOException.class, spool::close);
        assertThrows(IOException.class, () -> spool.acquire(ID, BODY.length, EnrollmentKeygenSpool.hash(BODY)));
        try (InputStream source = lease.openStream()) { assertArrayEquals(BODY, source.readAllBytes()); }
        spool.close();
        try (EnrollmentKeygenSpool reopened = new EnrollmentKeygenSpool(configuration, 1)) {
            assertTrue(reopened.deleteExpired(ID));
            assertTrue(reopened.deleteExpired(ID));
        }
    }

    @Test void uncertainForceRenameAndDirectoryAcknowledgementsFenceUntilReopen() throws Exception {
        EnrollmentRuntimeConfiguration.KeygenArtifacts configuration = configuration();
        for (EnrollmentKeygenSpool.Phase fault : new EnrollmentKeygenSpool.Phase[] {
                EnrollmentKeygenSpool.Phase.CIPHERTEXT_FORCED, EnrollmentKeygenSpool.Phase.CIPHERTEXT_RENAMED,
                EnrollmentKeygenSpool.Phase.DIRECTORY_FORCED}) {
            try (EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration, 1,
                    phase -> { if (phase == fault) throw new IOException("Injected publication acknowledgement loss"); })) {
                assertThrows(IOException.class, () -> spool.publish(ID, BODY, EnrollmentKeygenSpool.hash(BODY)));
                assertThrows(IOException.class, () -> spool.deleteExpired(ID));
            }
            try (EnrollmentKeygenSpool reopened = new EnrollmentKeygenSpool(configuration, 1)) {
                Set<String> names = new HashSet<>(); reopened.inspectFiles(names::add); assertEquals(Set.of(ID), names);
                if (fault != EnrollmentKeygenSpool.Phase.CIPHERTEXT_FORCED) reopened.verify(ID, BODY.length, EnrollmentKeygenSpool.hash(BODY));
                assertTrue(reopened.deleteExpired(ID)); // Caller has independently established the terminal descriptor.
            }
        }
    }

    @Test void strictBoundsIntegrityAndExclusiveOwnerRejectInvalidBodiesAndNames() throws Exception {
        EnrollmentRuntimeConfiguration.KeygenArtifacts configuration = configuration();
        try (EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration, 1)) {
            assertThrows(RuntimeException.class, () -> new EnrollmentKeygenSpool(configuration, 1));
            assertThrows(IOException.class, () -> spool.publish(ID, new byte[33], EnrollmentKeygenSpool.hash(new byte[33])));
            assertThrows(IOException.class, () -> spool.publish(ID, BODY, "b".repeat(64)));
            spool.publish(ID, BODY, EnrollmentKeygenSpool.hash(BODY));
            assertThrows(IOException.class, () -> spool.verify(ID, BODY.length + 1, EnrollmentKeygenSpool.hash(BODY)));
            assertThrows(IOException.class, () -> spool.verify(ID, BODY.length, "b".repeat(64)));
            Files.write(directory.resolve(ID + ".cms"), new byte[] {2, 3, 7, 15});
            assertThrows(IOException.class, () -> spool.acquire(ID, BODY.length, EnrollmentKeygenSpool.hash(BODY)));
            Files.write(directory.resolve("unknown"), new byte[] {1});
            assertThrows(IOException.class, () -> spool.inspectFiles(ignored -> { }));
        }
    }

    @Test void failedDeletionAcknowledgementFencesWithoutClaimingCapacityRelease() throws Exception {
        EnrollmentRuntimeConfiguration.KeygenArtifacts configuration = configuration();
        try (EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration, 1)) {
            spool.publish(ID, BODY, EnrollmentKeygenSpool.hash(BODY));
        }
        try (EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration, 1,
                phase -> { if (phase == EnrollmentKeygenSpool.Phase.DIRECTORY_FORCED) throw new IOException("Injected deletion acknowledgement loss"); })) {
            assertThrows(IOException.class, () -> spool.deleteExpired(ID));
            assertThrows(IOException.class, () -> spool.acquire(ID, BODY.length, EnrollmentKeygenSpool.hash(BODY)));
        }
        try (EnrollmentKeygenSpool spool = new EnrollmentKeygenSpool(configuration, 1)) { assertTrue(spool.deleteExpired(ID)); }
    }

    private EnrollmentRuntimeConfiguration.KeygenArtifacts configuration() throws IOException {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        return new EnrollmentRuntimeConfiguration.KeygenArtifacts(directory, 32, 64, 2, 1, Duration.ofMinutes(5));
    }
}

