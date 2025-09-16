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
package zeroecho.sdk.util;

import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * Provides initialization support for the Bouncy Castle cryptographic provider.
 * <p>
 * This utility class automatically adds the Bouncy Castle provider to the Java
 * Security framework upon class loading. It also offers an explicit
 * initialization method for optional use.
 * <p>
 * The class is declared as {@code final} and has a private constructor to
 * prevent instantiation, emphasizing its utility nature.
 *
 * <p>
 * Example usage:
 * 
 * <pre>{@code
 * BouncyCastleActivator.init();
 * }</pre>
 *
 * @author Leo Galambos
 */
public final class BouncyCastleActivator {
    /**
     * Logger instance for the {@code BouncyCastleActivator} class, used to log
     * messages related to the initialization and management of the Bouncy Castle
     * security provider.
     * <p>
     * Initialized with the class name to ensure logs are specific and traceable to
     * this component. Useful for debugging issues during cryptographic provider
     * setup.
     * </p>
     */
    private static final Logger LOG = Logger.getLogger(BouncyCastleActivator.class.getName());

    /**
     * Static initializer that registers the Bouncy Castle provider with the Java
     * Security framework. Logs the initialization process.
     */
    static {
        LOG.log(Level.INFO, "BouncyCastle provider initialization");
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        LOG.log(Level.INFO, "BouncyCastle PQC provider initialization");
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /**
     * Explicitly logs the activation of the Bouncy Castle provider. This method can
     * be called to confirm provider activation.
     */
    static public void init() {
        LOG.log(Level.INFO, "BrouncyCastle activated");
    }

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private BouncyCastleActivator() {
        // this is a utility class
    }
}
