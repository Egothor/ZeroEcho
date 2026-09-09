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
package zeroecho.pki.impl.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditChainHead;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditIntegrityReport;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

/** Tamper-evidence and verification coverage for the durable audit log chain. */
public final class FileAuditSinkIntegrityTest {

    @TempDir
    public Path tempDir;

    @Test
    public void verifiesIntactChainAndReportsHead() {
        System.out.println("verifiesIntactChainAndReportsHead");
        Path dir = tempDir.resolve("intact");
        FileAuditSink sink = new FileAuditSink(dir);
        for (int i = 0; i < 5; i++) {
            sink.record(event(i, "decision", i % 2 == 0 ? "ALLOW" : "DENY"));
        }

        AuditIntegrityReport report = sink.verifyIntegrity(Optional.empty());
        assertEquals(AuditIntegrityReport.Status.INTACT, report.status());
        assertEquals(5L, report.recordCount());
        assertEquals(4L, report.head().sequence());
        assertTrue(report.firstBrokenSequence().isEmpty());

        // The head anchor round-trips: verifying against the observed head still passes.
        assertTrue(sink.verifyIntegrity(Optional.of(report.head())).intact());
        System.out.println("...head-seq=" + report.head().sequence());
    }

    @Test
    public void detectsRecordContentMutation() throws Exception {
        System.out.println("detectsRecordContentMutation");
        Path dir = tempDir.resolve("mutation");
        FileAuditSink sink = new FileAuditSink(dir);
        for (int i = 0; i < 4; i++) {
            sink.record(event(i, "decision", "ALLOW"));
        }

        Path log = onlyDayFile(dir);
        List<String> lines = readRawLines(log);
        // Alter the decision value of record 2 without touching its stored record hash.
        lines.set(2, lines.get(2).replace("decision=ALLOW", "decision=BLOCK"));
        writeRawLines(log, lines);

        AuditIntegrityReport report = sink.verifyIntegrity(Optional.empty());
        assertEquals(AuditIntegrityReport.Status.RECORD_MUTATED, report.status());
        assertEquals(Optional.of(2L), report.firstBrokenSequence());
        System.out.println("...status=" + report.status() + " at=" + report.firstBrokenSequence());
    }

    @Test
    public void detectsRecordDeletionAsSequenceGap() throws Exception {
        System.out.println("detectsRecordDeletionAsSequenceGap");
        Path dir = tempDir.resolve("deletion");
        FileAuditSink sink = new FileAuditSink(dir);
        for (int i = 0; i < 5; i++) {
            sink.record(event(i, "n", Integer.toString(i)));
        }

        Path log = onlyDayFile(dir);
        List<String> lines = readRawLines(log);
        lines.remove(2); // delete the record carrying sequence 2
        writeRawLines(log, lines);

        AuditIntegrityReport report = sink.verifyIntegrity(Optional.empty());
        assertEquals(AuditIntegrityReport.Status.SEQUENCE_GAP, report.status());
        assertEquals(Optional.of(2L), report.firstBrokenSequence());
        System.out.println("...status=" + report.status());
    }

    @Test
    public void detectsTailTruncationOnlyAgainstTrustedHead() throws Exception {
        System.out.println("detectsTailTruncationOnlyAgainstTrustedHead");
        Path dir = tempDir.resolve("truncation");
        FileAuditSink sink = new FileAuditSink(dir);
        for (int i = 0; i < 4; i++) {
            sink.record(event(i, "n", Integer.toString(i)));
        }
        AuditChainHead trusted = sink.currentHead();
        assertEquals(3L, trusted.sequence());

        Path log = onlyDayFile(dir);
        List<String> lines = readRawLines(log);
        lines.remove(lines.size() - 1); // truncate the last record
        writeRawLines(log, lines);

        // Without a trusted anchor a truncated prefix looks internally consistent.
        assertTrue(sink.verifyIntegrity(Optional.empty()).intact());
        // With the retained head, truncation is a head mismatch.
        AuditIntegrityReport report = sink.verifyIntegrity(Optional.of(trusted));
        assertEquals(AuditIntegrityReport.Status.HEAD_MISMATCH, report.status());
        assertEquals(2L, report.head().sequence());
        System.out.println("...status=" + report.status());
    }

    @Test
    public void anchoredPrefixToleratesGrowthButDetectsRewriteAndTruncation() {
        System.out.println("anchoredPrefixToleratesGrowthButDetectsRewriteAndTruncation");
        Path dir = tempDir.resolve("anchor");
        FileAuditSink sink = new FileAuditSink(dir);
        for (int i = 0; i < 3; i++) {
            sink.record(event(i, "n", Integer.toString(i)));
        }
        AuditChainHead anchor = sink.currentHead();
        assertEquals(2L, anchor.sequence());

        // Records appended after the anchor (e.g. a crash restart continuing the chain) are legitimate growth.
        for (int i = 3; i < 6; i++) {
            sink.record(event(i, "n", Integer.toString(i)));
        }
        AuditIntegrityReport grown = sink.verifyAnchoredPrefix(anchor);
        assertEquals(AuditIntegrityReport.Status.INTACT, grown.status());
        assertEquals(5L, grown.head().sequence());

        // A genesis anchor is a valid prefix of any consistent chain.
        assertEquals(AuditIntegrityReport.Status.INTACT,
                sink.verifyAnchoredPrefix(AuditChainHead.empty()).status());

        // A differing hash at the anchored sequence means history before the anchor was rewritten.
        AuditChainHead forged = new AuditChainHead(anchor.sequence(), "f".repeat(64));
        assertEquals(AuditIntegrityReport.Status.RECORD_MUTATED, sink.verifyAnchoredPrefix(forged).status());

        // An anchor beyond the current log is truncation below the anchor.
        AuditChainHead beyond = new AuditChainHead(99L, anchor.recordHash());
        assertEquals(AuditIntegrityReport.Status.HEAD_MISMATCH, sink.verifyAnchoredPrefix(beyond).status());
        System.out.println("...ok");
    }

    @Test
    public void recoversHeadAcrossReopenAndContinuesOneChain() {
        System.out.println("recoversHeadAcrossReopenAndContinuesOneChain");
        Path dir = tempDir.resolve("reopen");
        FileAuditSink first = new FileAuditSink(dir);
        for (int i = 0; i < 3; i++) {
            first.record(event(i, "phase", "first"));
        }

        FileAuditSink second = new FileAuditSink(dir);
        for (int i = 0; i < 2; i++) {
            second.record(event(10 + i, "phase", "second"));
        }

        AuditIntegrityReport report = second.verifyIntegrity(Optional.empty());
        assertEquals(AuditIntegrityReport.Status.INTACT, report.status());
        assertEquals(5L, report.recordCount());
        assertEquals(4L, report.head().sequence());
        System.out.println("...continued-head-seq=" + report.head().sequence());
    }

    @Test
    public void integrityReportIsPayloadFree() {
        System.out.println("integrityReportIsPayloadFree");
        Path dir = tempDir.resolve("payload");
        FileAuditSink sink = new FileAuditSink(dir);
        sink.record(new AuditEvent(Instant.parse("2025-03-01T00:00:00Z"), "SECRETS", "READ",
                new Principal("USER", "top-secret-officer"), new Purpose("AUDIT"),
                Optional.of(new PkiId("classified-object")), Optional.empty(),
                Map.of("sensitive", "do-not-disclose-value")));

        String rendered = sink.verifyIntegrity(Optional.empty()).toString();
        assertFalse(rendered.contains("top-secret-officer"));
        assertFalse(rendered.contains("classified-object"));
        assertFalse(rendered.contains("do-not-disclose-value"));
        System.out.println("...report=" + rendered);
    }

    private AuditEvent event(int index, String detailKey, String detailValue) {
        return new AuditEvent(Instant.parse("2025-02-01T00:00:00Z").plusSeconds(index), "CAT", "ACT",
                new Principal("USER", "actor"), new Purpose("TEST"), Optional.of(new PkiId("obj-" + index)),
                Optional.empty(), Map.of(detailKey, detailValue));
    }

    private static Path onlyDayFile(Path dir) throws IOException {
        try (Stream<Path> walk = Files.walk(dir)) {
            List<Path> files = walk.filter(p -> p.getFileName().toString().endsWith(".audit.log.gz"))
                    .sorted().toList();
            assertEquals(1, files.size(), "expected exactly one day file");
            return files.get(0);
        }
    }

    private static List<String> readRawLines(Path file) throws IOException {
        List<String> lines = new ArrayList<>();
        try (InputStream fis = new BufferedInputStream(Files.newInputStream(file));
                PushbackInputStream pb = new PushbackInputStream(fis, 1)) {
            while (true) {
                int peek = pb.read();
                if (peek == -1) {
                    break;
                }
                pb.unread(peek);
                try (GZIPInputStream gzip = new GZIPInputStream(new CloseShield(pb))) {
                    StringBuilder sb = new StringBuilder();
                    int b;
                    while ((b = gzip.read()) != -1) {
                        if (b == '\n') {
                            lines.add(sb.toString());
                            sb.setLength(0);
                        } else {
                            sb.append((char) b);
                        }
                    }
                    if (sb.length() > 0) {
                        lines.add(sb.toString());
                    }
                }
            }
        }
        return lines;
    }

    private static void writeRawLines(Path file, List<String> lines) throws IOException {
        Files.deleteIfExists(file);
        for (String line : lines) {
            try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(file, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.APPEND));
                    GZIPOutputStream gzip = new GZIPOutputStream(os, true)) {
                gzip.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private static final class CloseShield extends FilterInputStream {
        private CloseShield(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // Keep the underlying stream open across concatenated gzip members.
        }
    }
}
