/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import zeroecho.sdk.integrations.covert.jpeg.JpegExifEmbedder;
import zeroecho.sdk.integrations.covert.jpeg.Slot;

/**
 * Command-line extension of ZeroEcho for covert embedding and extraction of
 * binary payloads in JPEG files using EXIF metadata slots.
 *
 * <p>
 * This extension operates in two primary modes:
 * </p>
 * <ul>
 * <li>Embedding a binary payload across one or more EXIF metadata fields</li>
 * <li>Extracting a previously embedded payload from those fields</li>
 * </ul>
 *
 * <p>
 * The embedding process preserves all original metadata except for the specific
 * slots being reused. Slot selection can be customized, or a default set of
 * predefined high-capacity EXIF fields will be used automatically.
 * </p>
 *
 * <p>
 * The following command-line options are supported:
 * </p>
 * <ul>
 * <li>{@code --embed}: Activate embedding mode (requires
 * {@code --payload})</li>
 * <li>{@code --extract}: Activate extraction mode</li>
 * <li>{@code --jpeg <input.jpg>}: Input JPEG file to embed into or extract from
 * (required)</li>
 * <li>{@code --payload <file>}: File containing payload data to embed (required
 * for {@code --embed})</li>
 * <li>{@code --output <file>}: Output file (JPEG with embedded data, or raw
 * extracted payload) (required)</li>
 * <li>{@code --slots <s1;s2;...>}: Optional semicolon-separated list of EXIF
 * slot definitions, each in the form {@code [group.]name[:capacity]} or a fully
 * defined custom tag like
 * {@code [group.]name/tag=tagId,type,count,dir[:capacity]}</li>
 * </ul>
 *
 * <p>
 * If {@code --slots} is omitted, a default list of slots is used with realistic
 * capacities suitable for several kilobytes of covert data. Slots are defined
 * using EXIF field tags grouped by logical metadata regions (e.g., IFD0, Exif
 * IFD, GPS IFD).
 * </p>
 *
 * <p>
 * Text-based EXIF slots (e.g., ASCII) will automatically encode binary payloads
 * using Base64. Extraction decodes them back transparently.
 * </p>
 *
 * <p>
 * This class is not meant to be instantiated.
 * </p>
 * 
 * @author Leo Galambos
 */
public final class CovertCommand {
    private CovertCommand() {
    }

    /**
     * Entry point for command-line usage of the covert embedding and extraction
     * tool.
     * <p>
     * Parses command-line arguments to embed or extract binary payloads in JPEG
     * files using EXIF metadata slots. Embedding requires a payload file, a JPEG
     * input, and an output destination. Extraction requires only the JPEG input and
     * output file. Slot behavior can be customized using semicolon-separated slot
     * specifications.
     * </p>
     *
     * @param args    Command-line arguments
     * @param options An {@link Options} instance to populate with supported CLI
     *                options
     * @return {@code 0} on success, {@code 1} on I/O error
     * @throws ParseException if the arguments are invalid or incomplete
     */
    public static int main(String[] args, Options options) throws ParseException {
        final Option EMBED_OPTION = Option.builder().longOpt("embed").desc("Embed a payload into a JPEG").get();
        final Option EXTRACT_OPTION = Option.builder().longOpt("extract").desc("Extract a payload from a JPEG").get();
        final Option JPEG_OPTION = Option.builder().longOpt("jpeg").hasArg().argName("input.jpg")
                .desc("Input JPEG file").required().get();
        final Option PAYLOAD_OPTION = Option.builder().longOpt("payload").hasArg().argName("payload.dat")
                .desc("Binary payload file to embed").get();
        final Option OUTPUT_OPTION = Option.builder().longOpt("output").hasArg().argName("outputFile")
                .desc("Output JPEG or payload file").required().get();
        final Option SLOTS_OPTION = Option.builder().longOpt("slots").hasArgs().valueSeparator(';')
                .argName("slot1;slot2;...")
                .desc("Custom EXIF slots (e.g. Exif.UserComment:4096;Exif.Custom/tag=700,ascii,64,exif:1024)").get();

        OptionGroup modeGroup = new OptionGroup();
        modeGroup.addOption(EMBED_OPTION);
        modeGroup.addOption(EXTRACT_OPTION);
        modeGroup.setRequired(true);

        options.addOptionGroup(modeGroup);
        options.addOption(JPEG_OPTION);
        options.addOption(PAYLOAD_OPTION);
        options.addOption(OUTPUT_OPTION);
        options.addOption(SLOTS_OPTION);

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        Path jpegPath = Path.of(cmd.getOptionValue("jpeg"));

        List<Slot> slots;
        if (cmd.hasOption("slots")) {
            slots = Arrays.stream(cmd.getOptionValues("slots")).map(Slot::parse).collect(Collectors.toList());
        } else {
            slots = Slot.defaults();
        }

        JpegExifEmbedder processor = new JpegExifEmbedder();
        processor.setSlots(slots);

        try {
            if (cmd.hasOption("embed")) {
                if (!cmd.hasOption("payload")) {
                    throw new ParseException("--payload is required for embedding");
                }
                try (InputStream payload = Files.newInputStream(Paths.get(cmd.getOptionValue("payload")));
                        OutputStream output = Files.newOutputStream(Paths.get(cmd.getOptionValue("output")))) {
                    processor.embed(jpegPath, payload, output);
                }
            } else if (cmd.hasOption("extract")) {
                try (OutputStream output = Files.newOutputStream(Paths.get(cmd.getOptionValue("output")))) {
                    processor.extract(jpegPath, output);
                }
            }
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
            return 1;
        }

        return 0;
    }
}
