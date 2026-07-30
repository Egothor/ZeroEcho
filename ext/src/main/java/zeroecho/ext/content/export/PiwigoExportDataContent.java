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
package zeroecho.ext.content.export;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

import javax.net.ssl.HttpsURLConnection;

import zeroecho.sdk.content.api.AbstractExportableDataContent;

/**
 * {@code PiwigoExportDataContent} is a specialized exportable content class
 * that uploads an image file to a Piwigo photo gallery server using a
 * structured HTTPS multipart request.
 *
 * <p>
 * Only {@link ExportMode#RAW} is supported. Script export is deliberately
 * unavailable because credentials and request values must never be represented
 * as executable shell text.
 *
 * <p>
 * This class integrates with {@code AbstractExportableDataContent} and expects
 * its {@code input} field to be set before invoking {@link #getStream()}.
 * </p>
 *
 * <p>
 * The image is uploaded using the {@code pwg.images.add} method of the Piwigo
 * API.
 * </p>
 */
class PiwigoExportDataContent extends AbstractExportableDataContent {
    private static final String INVALID_ENDPOINT = "Invalid Piwigo endpoint.";
    private static final String INVALID_FILE_NAME = "Invalid Piwigo image file name.";
    private static final String UNSUPPORTED_MODE = "Piwigo export supports RAW mode only.";
    private static final int BOUNDARY_BYTES = 18;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String imageFileName;
    private final URI endpoint;
    private final String username;
    private final char[] password;
    private final String albumId;
    private final PiwigoTransport transport;

    /**
     * Constructs a new exportable Piwigo upload object.
     *
     * @param imageFileName the name of the image file to assign during upload or
     *                      script output
     * @param piwigoUrl     the absolute HTTPS URI of the Piwigo API endpoint
     * @param username      the Piwigo username for authentication
     * @param password      the Piwigo password
     * @param albumId       the ID of the Piwigo album to which the image will be
     *                      uploaded
     * @throws IllegalArgumentException if the endpoint or image filename is not
     *                                  safe for the structured request
     * @throws NullPointerException     if any argument is {@code null}
     */
    public PiwigoExportDataContent(String imageFileName, String piwigoUrl, String username, String password,
            String albumId) {
        this(imageFileName, piwigoUrl, username, password, albumId, new HttpsPiwigoTransport());
    }

    /* package */ PiwigoExportDataContent(String imageFileName, String piwigoUrl, String username, String password,
            String albumId, PiwigoTransport transport) {
        super();

        this.imageFileName = requireHeaderFileName(imageFileName);
        this.endpoint = requireEndpoint(piwigoUrl);
        this.username = Objects.requireNonNull(username, "Piwigo username is required.");
        this.password = Objects.requireNonNull(password, "Piwigo password is required.").toCharArray();
        this.albumId = Objects.requireNonNull(albumId, "Piwigo album ID is required.");
        this.transport = Objects.requireNonNull(transport, "Piwigo transport is required.");
    }

    /**
     * Selects the export mode.
     *
     * <p>
     * Piwigo requests support only {@link ExportMode#RAW}; executable script
     * representations are rejected.
     *
     * @param mode the requested export mode
     * @throws IllegalArgumentException if {@code mode} is not
     *                                  {@link ExportMode#RAW}
     * @throws NullPointerException     if {@code mode} is {@code null}
     */
    @Override
    public void setExportMode(ExportMode mode) {
        ExportMode requiredMode = Objects.requireNonNull(mode, "Export mode is required.");
        if (requiredMode != ExportMode.RAW) {
            throw new IllegalArgumentException(UNSUPPORTED_MODE);
        }
        super.setExportMode(requiredMode);
    }

    /**
     * Uploads the configured input through a structured HTTPS multipart request.
     *
     * @return the Piwigo response stream
     * @throws IOException           if the HTTPS upload fails
     * @throws IllegalStateException if input has not been configured
     */
    @Override
    public InputStream getStream() throws IOException {
        if (input == null) {
            throw new IllegalStateException("Input not set.");
        }
        if (mode != ExportMode.RAW) {
            throw new IllegalStateException(UNSUPPORTED_MODE);
        }
        char[] requestPassword = password.clone();
        try {
            return transport.upload(endpoint, imageFileName, username, requestPassword, albumId, input.getStream());
        } finally {
            java.util.Arrays.fill(requestPassword, '\0');
        }
    }

    @Override
    public String toString() {
        return "PiwigoExportDataContent[endpoint=" + endpoint.getScheme() + "://" + endpoint.getHost()
                + ", configured=true]";
    }

    private static URI requireEndpoint(String value) {
        Objects.requireNonNull(value, "Piwigo endpoint is required.");
        if (containsControl(value) || containsEncodedControl(value)) {
            throw new IllegalArgumentException(INVALID_ENDPOINT);
        }
        URI candidate;
        try {
            candidate = URI.create(value);
        } catch (IllegalArgumentException exception) {
            candidate = null;
        }
        if (candidate == null || !candidate.isAbsolute() || candidate.isOpaque()
                || !"https".equalsIgnoreCase(candidate.getScheme())
                || candidate.getHost() == null || candidate.getHost().isBlank() || candidate.getRawAuthority() == null
                || candidate.getRawUserInfo() != null || candidate.getRawFragment() != null) {
            throw new IllegalArgumentException(INVALID_ENDPOINT);
        }
        return candidate;
    }

    private static String requireHeaderFileName(String value) {
        Objects.requireNonNull(value, "Piwigo image file name is required.");
        if (value.isBlank() || containsControl(value) || value.indexOf('"') >= 0 || value.indexOf('\\') >= 0) {
            throw new IllegalArgumentException(INVALID_FILE_NAME);
        }
        return value;
    }

    private static boolean containsControl(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character <= 0x1f || character == 0x7f) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsEncodedControl(String value) {
        int index = 0;
        while (index + 2 < value.length()) {
            if (value.charAt(index) == '%' && isHex(value.charAt(index + 1)) && isHex(value.charAt(index + 2))) {
                int decoded = Character.digit(value.charAt(index + 1), 16) * 16
                        + Character.digit(value.charAt(index + 2), 16);
                if (decoded <= 0x1f || decoded == 0x7f) {
                    return true;
                }
                index += 3;
            } else {
                index++;
            }
        }
        return false;
    }

    private static boolean isHex(char character) {
        return Character.digit(character, 16) >= 0;
    }

    /**
     * Executes one validated Piwigo upload while retaining URI and value
     * boundaries.
     */
    /* package */
    @FunctionalInterface
    interface PiwigoTransport {
        /**
         * Uploads one image using already validated request metadata.
         *
         * @param endpoint      absolute HTTPS endpoint
         * @param imageFileName validated multipart filename
         * @param username      opaque username value
         * @param password      caller-owned password copy
         * @param albumId       opaque album value
         * @param dataStream    image data
         * @return response stream
         * @throws IOException if the transport fails
         */
        InputStream upload(URI endpoint, String imageFileName, String username, char[] password, String albumId,
                InputStream dataStream) throws IOException;
    }

    /**
     * Default structured HTTPS multipart transport.
     */
    private static final class HttpsPiwigoTransport implements PiwigoTransport {
        @Override
        public InputStream upload(URI endpoint, String imageFileName, String username, char[] password, String albumId,
                InputStream dataStream) throws IOException {
            byte[] boundaryRandom = new byte[BOUNDARY_BYTES];
            RANDOM.nextBytes(boundaryRandom);
            String boundary = "----ZeroEcho" + HexFormat.of().formatHex(boundaryRandom);

            HttpsURLConnection connection = (HttpsURLConnection) endpoint.toURL().openConnection();
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setChunkedStreamingMode(8192);
            connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);

            try (InputStream source = dataStream;
                    OutputStream output = connection.getOutputStream()) {
                writeMultipart(output, boundary, imageFileName, username, password, albumId, source);
            }

            InputStream response = null;
            try {
                response = connection.getInputStream();
            } catch (IOException exception) {
                InputStream errorStream = connection.getErrorStream();
                if (errorStream != null) {
                    return errorStream;
                }
            }
            if (response == null) {
                throw new IOException("Piwigo HTTPS upload failed.");
            }
            return response;
        }
    }

    /* package */ static void writeMultipart(OutputStream output, String boundary, String imageFileName,
            String username, char[] password, String albumId, InputStream source) throws IOException {
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8));
        writeFormField(writer, boundary, "method", "pwg.images.add");
        writeFormField(writer, boundary, "username", username);
        writeSecretFormField(writer, boundary, "password", password);
        writeFormField(writer, boundary, "category", albumId);
        writer.write("--" + boundary + "\r\n");
        writer.write("Content-Disposition: form-data; name=\"image\"; filename=\"");
        writer.write(imageFileName);
        writer.write("\"\r\nContent-Type: image/jpeg\r\n\r\n");
        writer.flush();
        source.transferTo(output);
        output.flush();
        writer.write("\r\n--" + boundary + "--\r\n");
        writer.flush();
    }

    private static void writeFormField(Writer writer, String boundary, String name, String value) throws IOException {
        writer.write("--" + boundary + "\r\n");
        writer.write("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n");
        writer.write(value + "\r\n");
    }

    private static void writeSecretFormField(Writer writer, String boundary, String name, char... value)
            throws IOException {
        writer.write("--" + boundary + "\r\n");
        writer.write("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n");
        writer.write(value);
        writer.write("\r\n");
    }
}
