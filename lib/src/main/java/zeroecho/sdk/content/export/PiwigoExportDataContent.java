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
package zeroecho.sdk.content.export;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.SequenceInputStream;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import zeroecho.sdk.content.api.AbstractExportableDataContent;

/**
 * {@code PiwigoExportDataContent} is a specialized exportable content class
 * that supports uploading an image file to a Piwigo photo gallery server,
 * either directly via HTTP POST or by generating platform-specific scripts for
 * deferred uploading.
 *
 * <p>
 * Depending on the export mode (RAW, BASH_SCRIPT, CMD_SCRIPT), it can:
 * <ul>
 * <li>Upload the image to a Piwigo server directly using HTTP
 * multipart/form-data</li>
 * <li>Generate a Bash script that decodes the base64-encoded image and uploads
 * it using curl</li>
 * <li>Generate a CMD (Windows batch) script that reconstructs the image using
 * certutil and uploads it</li>
 * </ul>
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
    private final String imageFileName;
    private final String piwigoUrl;
    private final String username;
    private final String password;
    private final String albumId;

    /**
     * Constructs a new exportable Piwigo upload object.
     *
     * @param imageFileName the name of the image file to assign during upload or
     *                      script output
     * @param piwigoUrl     the URL of the Piwigo API endpoint
     * @param username      the Piwigo username for authentication
     * @param password      the Piwigo password
     * @param albumId       the ID of the Piwigo album to which the image will be
     *                      uploaded
     */
    public PiwigoExportDataContent(String imageFileName, String piwigoUrl, String username, String password,
            String albumId) {
        super();

        this.imageFileName = imageFileName;
        this.piwigoUrl = piwigoUrl;
        this.username = username;
        this.password = password;
        this.albumId = albumId;
    }

    /**
     * Returns an {@code InputStream} that provides either the raw upload stream, or
     * a platform-specific script depending on the export mode.
     *
     * @return the resulting {@code InputStream}
     * @throws IOException if reading the input or creating the stream fails
     */
    @Override
    public InputStream getStream() throws IOException {
        if (input == null) {
            throw new IllegalStateException("Input not set.");
        }

        return switch (mode) {
            case RAW -> performDirectUpload(input.getStream());
            case BASH_SCRIPT -> generateBashScript(input.getStream());
            case CMD_SCRIPT -> generateCmdScript(input.getStream());
        };
    }

    /**
     * Performs a direct upload of the image data to the Piwigo server using a
     * multipart/form-data HTTP POST request.
     *
     * @param dataStream the input stream of the binary image data
     * @return the server's response stream
     * @throws IOException if the upload fails
     */
    private InputStream performDirectUpload(InputStream dataStream) throws IOException {
        String boundary = "----Boundary" + System.currentTimeMillis();

        URL url = URI.create(piwigoUrl).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);

        try (OutputStream out = conn.getOutputStream();
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {

            writeFormField(writer, boundary, "method", "pwg.images.add");
            writeFormField(writer, boundary, "username", username);
            writeFormField(writer, boundary, "password", password);
            writeFormField(writer, boundary, "category", albumId);

            writer.write("--" + boundary + "\r\n");
            writer.write("Content-Disposition: form-data; name=\"image\"; filename=\"" + imageFileName + "\"\r\n");
            writer.write("Content-Type: image/jpeg\r\n\r\n");
            writer.flush();

            dataStream.transferTo(out);
            out.flush();
            writer.write("\r\n--" + boundary + "--\r\n");
            writer.flush();
        }

        InputStream responseStream;
        try {
            responseStream = conn.getInputStream();
        } catch (IOException e) {
            InputStream errorStream = conn.getErrorStream();
            if (errorStream != null) {
                return errorStream;
            }
            return new ByteArrayInputStream(("Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8));
        }

        return responseStream;
    }

    /**
     * Writes a single form field as part of a multipart/form-data HTTP request.
     *
     * @param writer   the writer to output the field to
     * @param boundary the multipart boundary
     * @param name     the name of the form field
     * @param value    the value of the form field
     * @throws IOException if writing fails
     */
    private void writeFormField(Writer writer, String boundary, String name, String value) throws IOException {
        writer.write("--" + boundary + "\r\n");
        writer.write("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n");
        writer.write(value + "\r\n");
    }

    /**
     * Generates a Bash script that reconstructs the image using a Base64 heredoc
     * block and uploads it using {@code curl}.
     *
     * @param originalStream the original binary stream of the image
     * @return a stream containing the complete shell script
     */
    private InputStream generateBashScript(InputStream originalStream) {
        InputStream header = new ByteArrayInputStream(("#!/bin/bash\nset -e\n\ncurl -X POST \"" + piwigoUrl + "\" \\\n"
                + "  -F method=\"pwg.images.add\" \\\n" + "  -F username=\"" + username + "\" \\\n" + "  -F password=\""
                + password + "\" \\\n" + "  -F category=\"" + albumId + "\" \\\n" + "  -F image=@<(base64 -d <<'EOF'\n")
                .getBytes(StandardCharsets.UTF_8));

        @SuppressWarnings("resource")
        InputStream body = new Base64Stream(originalStream, null, 76, new byte[] { 10 });
        InputStream footer = new ByteArrayInputStream("EOF\n)\n".getBytes(StandardCharsets.UTF_8));

        return new SequenceInputStream(new SequenceInputStream(header, body), footer);
    }

    /**
     * Generates a CMD batch script that reconstructs the image using certutil and
     * uploads it using {@code curl}.
     *
     * @param originalStream the original binary stream of the image
     * @return a stream containing the complete Windows batch script
     */
    private InputStream generateCmdScript(InputStream originalStream) {
        InputStream header = new ByteArrayInputStream(
                "@echo off\nsetlocal\necho -----BEGIN BASE64----- > tmp.b64\n".getBytes(StandardCharsets.UTF_8));

        @SuppressWarnings("resource")
        InputStream body = new Base64Stream(originalStream, "echo ".getBytes(), 76, " >> tmp.b64\r\n".getBytes());
        InputStream footer = new ByteArrayInputStream(
                ("echo -----END BASE64----- >> tmp.b64\n" + "certutil -decode tmp.b64 \"" + imageFileName + "\" >nul\n"
                        + "del tmp.b64\n" + "curl -X POST \"" + piwigoUrl + "\" ^\n" + "  -F method=pwg.images.add ^\n"
                        + "  -F username=" + username + " ^\n" + "  -F password=" + password + " ^\n" + "  -F category="
                        + albumId + " ^\n" + "  -F image=@" + imageFileName + "\n" + "del \"" + imageFileName + "\"\n")
                        .getBytes(StandardCharsets.UTF_8));

        return new SequenceInputStream(new SequenceInputStream(header, body), footer);
    }
}
