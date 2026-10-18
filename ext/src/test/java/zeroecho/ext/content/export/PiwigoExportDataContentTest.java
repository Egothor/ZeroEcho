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
package zeroecho.ext.content.export;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;

import zeroecho.sdk.content.api.ExportableDataContent.ExportMode;

class PiwigoExportDataContentTest {
    private static final String CREDENTIAL_SENTINEL = "M7_SECRET_5c9d7f";
    private static final byte[] IMAGE = { 0x01, 0x23, 0x45, 0x67 };

    @Test
    void validStructuredUploadPreservesOpaqueValues() throws Exception {
        System.out.println("validStructuredUploadPreservesOpaqueValues");
        RecordingTransport transport = new RecordingTransport();
        String fileName = "photo ; $() && 日本語.jpg";
        String password = CREDENTIAL_SENTINEL + " ;&&||>$()`\r\n";
        PiwigoExportDataContent content = new PiwigoExportDataContent(fileName,
                "https://gallery.example.test/piwigo/ws.php?format=json", "user name | value", password,
                "Album Ω", transport);
        content.setInput(() -> new ByteArrayInputStream(IMAGE));

        byte[] response;
        try (InputStream input = content.getStream()) {
            response = input.readAllBytes();
        }

        assertEquals(URI.create("https://gallery.example.test/piwigo/ws.php?format=json"), transport.endpoint);
        assertEquals(fileName, transport.imageFileName);
        assertEquals("user name | value", transport.username);
        assertEquals(password, new String(transport.passwordCopy));
        assertEquals("Album Ω", transport.albumId);
        assertArrayEquals(IMAGE, transport.image);
        assertArrayEquals("ok".getBytes(StandardCharsets.UTF_8), response);
        assertTrue(allZero(transport.passwordArgument), "Request password copy must be cleared after transport use.");
        System.out.println("...endpoint host: " + transport.endpoint.getHost());
        System.out.println("...opaque filename length: " + fileName.length());
        System.out.println("...ok");
    }

    @Test
    void multipartEncodingPreservesSafeSemantics() throws Exception {
        System.out.println("multipartEncodingPreservesSafeSemantics");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        char[] password = "opaque-password".toCharArray();

        PiwigoExportDataContent.writeMultipart(output, "ZeroEchoBoundary", "image name Ω.jpg", "user name",
                password, "album Ω", new ByteArrayInputStream(IMAGE));

        byte[] encoded = output.toByteArray();
        String prefix = new String(encoded, 0, encoded.length - IMAGE.length - "\r\n--ZeroEchoBoundary--\r\n".length(),
                StandardCharsets.UTF_8);
        assertTrue(prefix.contains("name=\"method\"\r\n\r\npwg.images.add\r\n"));
        assertTrue(prefix.contains("name=\"username\"\r\n\r\nuser name\r\n"));
        assertTrue(prefix.contains("name=\"password\"\r\n\r\nopaque-password\r\n"));
        assertTrue(prefix.contains("name=\"category\"\r\n\r\nalbum Ω\r\n"));
        assertTrue(prefix.contains("name=\"image\"; filename=\"image name Ω.jpg\"\r\n"));
        assertTrue(containsSubsequence(encoded, IMAGE));
        System.out.println("...multipart bytes: " + encoded.length);
        System.out.println("...ok");
    }

    @Test
    void rejectsUnsafeEndpointsConsistently() {
        System.out.println("rejectsUnsafeEndpointsConsistently");
        String[] endpoints = {
            "http://gallery.example.test/ws.php",
            "ftp://gallery.example.test/ws.php",
            "file:///tmp/ws.php",
            "jar:https://gallery.example.test/archive.jar!/ws.php",
            "relative/ws.php",
            "//gallery.example.test/ws.php",
            "https:///ws.php",
            "https://user:pass@gallery.example.test/ws.php",
            "https://gallery.example.test/ws.php#fragment",
            "https://gallery.example.test/\rheader",
            "https://gallery.example.test/\nheader",
            "https://gallery.example.test/\0header",
            "https://gallery.example.test/%0dheader",
            "https://gallery.example.test/%0Aheader",
            "https://gallery.example.test/%00header",
            "https:////gallery.example.test/ws.php",
            "https://:443/ws.php"
        };

        for (String endpoint : endpoints) {
            IllegalArgumentException direct = assertThrows(IllegalArgumentException.class,
                    () -> new PiwigoExportDataContent("image.jpg", endpoint, "user", "password", "album"));
            IllegalArgumentException injected = assertThrows(IllegalArgumentException.class,
                    () -> new PiwigoExportDataContent("image.jpg", endpoint, "user", "password", "album",
                            new RecordingTransport()));
            assertEquals("Invalid Piwigo endpoint.", direct.getMessage());
            assertEquals(direct.getMessage(), injected.getMessage());
        }
        System.out.println("...rejected endpoint cases: " + endpoints.length);
        System.out.println("...ok");
    }

    @Test
    void rejectsMultipartHeaderInjection() {
        System.out.println("rejectsMultipartHeaderInjection");
        String[] fileNames = {
            "image\rX-Injected: true.jpg",
            "image\nX-Injected: true.jpg",
            "image\r\n--boundary.jpg",
            "image\0.jpg",
            "image\"; name=\"injected.jpg",
            "image\\\"; filename=\"injected.jpg"
        };

        for (String fileName : fileNames) {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new PiwigoExportDataContent(fileName, "https://gallery.example.test/ws.php", "user",
                            "password", "album"));
            assertEquals("Invalid Piwigo image file name.", exception.getMessage());
        }
        System.out.println("...rejected header cases: " + fileNames.length);
        System.out.println("...ok");
    }

    @Test
    void rejectsExecutableScriptModes() {
        System.out.println("rejectsExecutableScriptModes");
        PiwigoExportDataContent content = new PiwigoExportDataContent("image.jpg",
                "https://gallery.example.test/ws.php", "user", "password", "album", new RecordingTransport());

        IllegalArgumentException bash = assertThrows(IllegalArgumentException.class,
                () -> content.setExportMode(ExportMode.BASH_SCRIPT));
        IllegalArgumentException command = assertThrows(IllegalArgumentException.class,
                () -> content.setExportMode(ExportMode.CMD_SCRIPT));

        assertEquals("Piwigo export supports RAW mode only.", bash.getMessage());
        assertEquals(bash.getMessage(), command.getMessage());
        assertEquals(ExportMode.RAW, content.getExportMode());
        System.out.println("...authoritative mode: RAW");
        System.out.println("...ok");
    }

    @Test
    void redactsCredentialsFromDiagnosticsAndLogs() throws Exception {
        System.out.println("redactsCredentialsFromDiagnosticsAndLogs");
        RecordingTransport transport = new RecordingTransport();
        PiwigoExportDataContent content = new PiwigoExportDataContent("image.jpg",
                "https://gallery.example.test/ws.php", "user", CREDENTIAL_SENTINEL, "album", transport);
        content.setInput(() -> new ByteArrayInputStream(IMAGE));
        List<String> messages = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                messages.add(record.getMessage());
            }

            @Override
            public void flush() {
                // Nothing buffered.
            }

            @Override
            public void close() {
                // Nothing owned.
            }
        };
        Logger logger = Logger.getLogger("");
        logger.addHandler(handler);
        try (InputStream ignored = content.getStream()) {
            assertFalse(content.toString().contains(CREDENTIAL_SENTINEL));
            assertFalse(new String(ignored.readAllBytes(), StandardCharsets.UTF_8).contains(CREDENTIAL_SENTINEL));
        } finally {
            logger.removeHandler(handler);
        }
        assertTrue(messages.stream().noneMatch(message -> message != null && message.contains(CREDENTIAL_SENTINEL)));

        IllegalArgumentException invalid = assertThrows(IllegalArgumentException.class,
                () -> new PiwigoExportDataContent("image.jpg", "https://example.test/%0d", "user",
                        CREDENTIAL_SENTINEL, "album"));
        assertFalse(invalid.getMessage().contains(CREDENTIAL_SENTINEL));
        System.out.println("...diagnostic fields checked: 4");
        System.out.println("...ok");
    }

    private static boolean allZero(char[] value) {
        for (char character : value) {
            if (character != '\0') {
                return false;
            }
        }
        return true;
    }

    private static boolean containsSubsequence(byte[] source, byte[] expected) {
        for (int start = 0; start <= source.length - expected.length; start++) {
            if (Arrays.equals(Arrays.copyOfRange(source, start, start + expected.length), expected)) {
                return true;
            }
        }
        return false;
    }

    private static final class RecordingTransport implements PiwigoExportDataContent.PiwigoTransport {
        private URI endpoint;
        private String imageFileName;
        private String username;
        private char[] passwordArgument;
        private char[] passwordCopy;
        private String albumId;
        private byte[] image;

        @Override
        public InputStream upload(URI requestEndpoint, String requestImageFileName, String requestUsername,
                char[] requestPassword, String requestAlbumId, InputStream dataStream) throws IOException {
            endpoint = requestEndpoint;
            imageFileName = requestImageFileName;
            username = requestUsername;
            passwordArgument = requestPassword;
            passwordCopy = requestPassword.clone();
            albumId = requestAlbumId;
            try (InputStream source = dataStream) {
                image = source.readAllBytes();
            }
            return new ByteArrayInputStream("ok".getBytes(StandardCharsets.UTF_8));
        }
    }
}
