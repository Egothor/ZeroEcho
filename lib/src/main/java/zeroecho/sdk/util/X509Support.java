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
package zeroecho.sdk.util;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Utility class providing support for working with X.509 certificates, private
 * keys, and certification requests using PEM-encoded files and the Bouncy
 * Castle library.
 * <p>
 * This class includes static helper methods to:
 * <ul>
 * <li>Load an X.509 certificate from a PEM file</li>
 * <li>Load a PKCS#10 certification request (CSR) from a PEM file</li>
 * <li>Print a {@link java.security.PrivateKey} in PEM format</li>
 * <li>Print a {@link java.security.cert.Certificate}, including its PEM-encoded
 * form</li>
 * </ul>
 * <p>
 * All methods are static and the class cannot be instantiated.
 *
 * <p>
 * <b>Note:</b> This class relies on the Bouncy Castle library and assumes the
 * Bouncy Castle provider is correctly configured.
 *
 * @author Leo Galambos
 */
public final class X509Support {
    private static final Logger LOG = Logger.getLogger(X509Support.class.getName());

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private X509Support() {
        // this is a utility class
    }

    /**
     * Loads an X509Certificate from a PEM file.
     *
     * @param path the file path to the certificate PEM file
     * @return the loaded {@link X509Certificate} or null if invalid
     * @throws IOException if an I/O error occurs reading the file
     */
    public static Certificate loadCertificate(final String path) throws IOException {
        try (PEMParser pemParser = new PEMParser(Files.newBufferedReader(Paths.get(path), StandardCharsets.UTF_8))) {
            final Object obj = pemParser.readObject();
            if (obj instanceof org.bouncycastle.cert.X509CertificateHolder) {
                final org.bouncycastle.cert.X509CertificateHolder holder = (org.bouncycastle.cert.X509CertificateHolder) obj;
                return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
            } else {
                System.err.println("File does not contain a valid X509 certificate.");
                return null;
            }
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Error reading certificate file: {0}", path);
            throw e;
        } catch (CertificateException e) {
            LOG.log(Level.SEVERE, "Error reading certificate file: {0}", path);
            return null;
        }
    }

    /**
     * Utility method to print a {@link PrivateKey} in PEM format to standard
     * output.
     * <p>
     * This method writes the private key using a {@link JcaPEMWriter} and prints it
     * to the console in PEM (Base64-encoded) format. If an error occurs during the
     * writing process, it logs a warning.
     *
     * @param privKey the {@link PrivateKey} to print
     */
    public static void printPrivateKey(final PrivateKey privKey) {
        try (StringWriter sw = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(privKey);
            pemWriter.flush();
            System.out.println("Private Key (PEM):\n" + sw.toString());
        } catch (IOException e) {
            LOG.log(Level.WARNING, "Failed to print private key", e);
        }
    }

    /**
     * Prints the certificate details to standard output, including its PEM encoded
     * representation.
     *
     * @param cert the {@link Certificate} to print
     */
    public static void printCertificate(final Certificate cert) {
        try {
            System.out.println("Certificate:");
            System.out.println(cert.toString());

            // Print PEM encoded certificate
            try (StringWriter sw = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
                pemWriter.writeObject(cert);
                pemWriter.flush();
                System.out.println(sw.toString());
            }
        } catch (IOException e) {
            LOG.log(Level.WARNING, "Failed to print certificate", e);
        }
    }

    /**
     * Loads a PKCS#10 Certification Request (CSR) from a PEM file.
     *
     * @param path the file path to the CSR PEM file
     * @return the loaded {@link PKCS10CertificationRequest} or null if invalid
     * @throws IOException if an I/O error occurs reading the file
     */
    public static PKCS10CertificationRequest loadCSR(final String path) throws IOException {
        try (PEMParser pemParser = new PEMParser(Files.newBufferedReader(Paths.get(path), StandardCharsets.UTF_8))) {
            final Object obj = pemParser.readObject();
            if (obj instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) obj;
            } else {
                System.err.println("File does not contain a valid PKCS#10 CSR.");
                return null;
            }
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Error reading CSR file: {0}", path);
            throw e;
        }
    }
}
