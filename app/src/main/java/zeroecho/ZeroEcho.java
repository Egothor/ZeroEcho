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
package zeroecho;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.MissingOptionException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.help.HelpFormatter;

import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * ZeroEcho is a command-line utility for managing asymmetric keys and
 * certificates, primarily focusing on Certificate Authority (CA) operations
 * such as issuing, revoking, and listing certificates.
 * <p>
 * It supports command-line options for asymmetric key management, including
 * issuing certificates from CSRs or subject names, revoking certificates, and
 * retrieving all certificates for a user.
 * </p>
 * <p>
 * This class initializes Bouncy Castle security provider and uses Apache
 * Commons CLI for command-line parsing.
 * </p>
 * 
 * @author Leo Galambos
 */
public final class ZeroEcho {
    /**
     * Logger instance for the {@code ZeroEcho} class used to log messages and
     * events.
     * <p>
     * This logger is configured with the name of the {@code ZeroEcho} class,
     * allowing for fine-grained logging control specific to this class.
     * </p>
     */
    public static final Logger LOG = Logger.getLogger(ZeroEcho.class.getName());

    static {
        BouncyCastleActivator.init();
    }

    /**
     * Default constructor for ZeroEcho.
     * <p>
     * This constructor does not perform any initialization since all operations are
     * handled via static methods and blocks.
     * </p>
     */
    private ZeroEcho() {
        // No initialization needed
    }

    /**
     * Main entry point for the ZeroEcho application. Parses command-line arguments
     * and dispatches to the appropriate subcommand for asymmetric key management or
     * prints the help message.
     *
     * @param args command-line arguments passed to the program
     * @throws IOException If the output could not be written
     */
    public static void main(final String[] args) throws IOException {
        final int errorCode = mainProcess(args);

        if (errorCode == 0) {
            System.out.println("OK");
        } else {
            System.out.println("ERR: " + errorCode);
        }
    }

    /**
     * Entry point for the ZeroEcho application. Parses command-line arguments and
     * dispatches to the appropriate subcommand for asymmetric key management or
     * prints the help message.
     *
     * @param args command-line arguments passed to the program
     * @return error-code
     * @throws IOException If the output could not be written
     */
    public static int mainProcess(final String... args) throws IOException {
        final Option KEM_OPTION = Option.builder("E").longOpt("kem").desc("KEM encryption/decryption").get();
        final Option GUARD_OPTION = Option.builder("G").longOpt("guard")
                .desc("multi-recipient encryption/decryption (keys+passwords), AES/ChaCha").get();
        final Option KEYSTORE_OPTION = Option.builder("K").longOpt("ksm").desc("key store management").get();
        final Option COVERT_OPTION = Option.builder("C").longOpt("covert").desc("covert channel processing").get();
        final Option TAG_OPTION = Option.builder("T").longOpt("tag")
                .desc("tag subcommand (signature/digest; produce/verify)").get();

        final OptionGroup OPERATION_GROUP = new OptionGroup();
        OPERATION_GROUP.addOption(GUARD_OPTION);
        OPERATION_GROUP.addOption(KEYSTORE_OPTION);
        OPERATION_GROUP.addOption(KEM_OPTION);
        OPERATION_GROUP.addOption(COVERT_OPTION);
        OPERATION_GROUP.addOption(TAG_OPTION);
        OPERATION_GROUP.setRequired(true); // At least one required

        Options options = new Options();
        options.addOptionGroup(OPERATION_GROUP);

        final CommandLineParser parser = new DefaultParser();

        try {
            // parse the command line arguments (allow remaining arguments for subcommands)
            parser.parse(options, args, true);

            return switch (OPERATION_GROUP.getSelected()) {
                case "E" -> Kem.main(args, options = new Options().addOption(KEM_OPTION));
                case "G" -> Guard.main(args, options = new Options().addOption(GUARD_OPTION));
                case "K" -> KeyStoreManagement.main(args, options = new Options().addOption(KEYSTORE_OPTION));
                case "C" -> CovertCommand.main(args, options = new Options().addOption(COVERT_OPTION));
                case "T" -> Tag.main(args, options = new Options().addOption(TAG_OPTION));
                default -> 1;

            };

        } catch (MissingOptionException ex) {
            if (LOG.isLoggable(Level.SEVERE)) {
                LOG.log(Level.SEVERE, ex.getMessage());
            }
            return help(options);

        } catch (ParseException | GeneralSecurityException ex) {
            if (LOG.isLoggable(Level.WARNING)) {
                LOG.log(Level.WARNING, "Unexpected exception", ex.getMessage());
            }
            return help(options);

        } catch (IOException e) {
            LOG.logp(Level.WARNING, "ZeroEcho", "mainProcess", e.getMessage(), e);
            return -1;

        } finally {
            LOG.log(Level.INFO, "Completed.");
        }
    }

    /**
     * Prints the usage help message for the command-line interface of the ZeroEcho
     * application.
     *
     * <p>
     * This method automatically generates and displays a help statement based on
     * the provided command-line {@link Options}. It then terminates the program
     * with exit status {@code 1}.
     *
     * @param options The {@link Options} instance defining the available
     *                command-line options.
     * @return always {@code 1}
     * @throws IOException If the output could not be written
     */
    private static int help(final Options options) throws IOException {
        // automatically generate the help statement
        final HelpFormatter formatter = HelpFormatter.builder().get();
        formatter.printHelp(ZeroEcho.class.getName(), "", options, "", false);

        return 1;
    }
}
