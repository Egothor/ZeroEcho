/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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
/**
 * ZeroEcho PKI domain: API, SPI, application services, and the default
 * filesystem/BouncyCastle backends discovered via ServiceLoader.
 */
module zeroecho.pki {
    requires java.sql;
    requires com.h2database;
    requires transitive zeroecho.lib;
    requires tools.jackson.core;
    requires java.net.http;
    requires java.logging;

    // Public PKI API.
    exports zeroecho.pki.api;
    exports zeroecho.pki.api.ct;
    exports zeroecho.pki.api.algorithm;
    exports zeroecho.pki.api.attr;
    exports zeroecho.pki.api.audit;
    exports zeroecho.pki.api.backup;
    exports zeroecho.pki.api.ca;
    exports zeroecho.pki.api.confirmation;
    exports zeroecho.pki.api.content;
    exports zeroecho.pki.api.credential;
    exports zeroecho.pki.api.issuance;
    exports zeroecho.pki.api.orch;
    exports zeroecho.pki.api.policy;
    exports zeroecho.pki.api.hybrid;
    exports zeroecho.pki.api.profile;
    exports zeroecho.pki.api.publication;
    exports zeroecho.pki.api.request;
    exports zeroecho.pki.api.revocation;
    exports zeroecho.pki.api.schedule;
    exports zeroecho.pki.api.status;
    exports zeroecho.pki.api.signing;
    exports zeroecho.pki.api.transfer;
    exports zeroecho.pki.application;

    // SPI (extension points).
    exports zeroecho.pki.spi;
    exports zeroecho.pki.spi.audit;
    exports zeroecho.pki.spi.bootstrap;
    exports zeroecho.pki.spi.confirmation;
    exports zeroecho.pki.spi.crypto;
    exports zeroecho.pki.spi.ct;
    exports zeroecho.pki.spi.store;

    // Default backends, exposed only to sibling modules that must construct them.
    exports zeroecho.pki.impl.fs to zeroecho.pki.server, zeroecho.app;
    exports zeroecho.pki.impl.fs.ct to zeroecho.pki.server, zeroecho.app;
    exports zeroecho.pki.impl.secrets to zeroecho.pki.server, zeroecho.app;

    // Service usage (backend selection).
    uses zeroecho.pki.spi.async.AsyncBusProvider;
    uses zeroecho.pki.spi.audit.AuditSinkProvider;
    uses zeroecho.pki.spi.crypto.SigningProviderFactory;
    uses zeroecho.pki.spi.framework.CredentialFrameworkProvider;
    uses zeroecho.pki.spi.publish.PublisherProvider;
    uses zeroecho.pki.spi.store.PkiStoreProvider;
    uses zeroecho.pki.spi.algorithm.X509AlgorithmBindingProvider;
    uses zeroecho.pki.impl.framework.x509.X509BindingRuleProvider;
    uses zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;

    // Default backends provided to the domain.
    provides zeroecho.core.spi.AlgorithmExecutionCapabilityProvider
            with zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSigningProviderFactory;
    provides zeroecho.pki.spi.async.AsyncBusProvider
            with zeroecho.pki.impl.async.FileBackedAsyncBusProvider;
    provides zeroecho.pki.spi.audit.AuditSinkProvider with
            zeroecho.pki.impl.audit.FileAuditSinkProvider,
            zeroecho.pki.impl.audit.InMemoryAuditSinkProvider,
            zeroecho.pki.impl.audit.StdoutAuditSinkProvider,
            zeroecho.pki.impl.audit.SyslogAuditSinkProvider;
    provides zeroecho.pki.spi.crypto.SigningProviderFactory
            with zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSigningProviderFactory,
                 zeroecho.pki.impl.crypto.pkcs11.Pkcs11SigningProviderFactory;
    provides zeroecho.pki.spi.framework.CredentialFrameworkProvider
            with zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFrameworkProvider;
    provides zeroecho.pki.spi.publish.PublisherProvider
            with zeroecho.pki.impl.publish.FilesystemPublisherProvider,
                 zeroecho.pki.impl.publish.HttpsPublisherProvider;
    provides zeroecho.pki.spi.store.PkiStoreProvider
            with zeroecho.pki.impl.fs.FilesystemPkiStoreProvider;
}
