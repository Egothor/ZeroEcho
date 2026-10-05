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
 * ZeroEcho foundation library: cryptographic core ({@code zeroecho.core}) and the
 * high-level SDK ({@code zeroecho.sdk}) kept together in one artifact/module.
 */
module zeroecho.lib {
    // BC implementation is confined here; ElgamalParamSpec.parameters() deliberately
    // exposes a provider type for source/binary compatibility.
    requires org.bouncycastle.pkix;
    requires transitive org.bouncycastle.provider;
    requires org.bouncycastle.util;
    // Conflux marshalling (automatic module, derived from the jar file name).
    requires conflux;
    requires java.logging;

    // Cryptographic core API.
    exports zeroecho.core;
    exports zeroecho.core.alg;
    exports zeroecho.core.alg.aes;
    exports zeroecho.core.alg.common.agreement;
    exports zeroecho.core.alg.common.sig;
    exports zeroecho.core.alg.digest;
    exports zeroecho.core.alg.ecdsa;
    exports zeroecho.core.alg.ed25519;
    exports zeroecho.core.alg.ed448;
    exports zeroecho.core.alg.elgamal;
    exports zeroecho.core.alg.kyber;
    exports zeroecho.core.alg.mldsa;
    exports zeroecho.core.alg.rsa;
    exports zeroecho.core.alg.slhdsa;
    exports zeroecho.core.alg.lms;
    exports zeroecho.core.alg.sphincsplus;
    exports zeroecho.core.alg.xdh;
    exports zeroecho.core.alg.xmss;
    exports zeroecho.core.alg.xwing;
    exports zeroecho.core.context;
    exports zeroecho.core.err;
    exports zeroecho.core.io;
    exports zeroecho.core.spec;
    exports zeroecho.core.spi;
    exports zeroecho.core.storage;
    exports zeroecho.core.tag;
    exports zeroecho.core.util;

    // High-level SDK API.
    exports zeroecho.sdk;
    exports zeroecho.sdk.builders;
    exports zeroecho.sdk.builders.alg;
    exports zeroecho.sdk.builders.core;
    exports zeroecho.sdk.content.api;
    exports zeroecho.sdk.content.builtin;
    exports zeroecho.sdk.guard;
    exports zeroecho.sdk.hybrid.derived;
    exports zeroecho.sdk.hybrid.kex;
    exports zeroecho.sdk.hybrid.signature;
    exports zeroecho.sdk.util;

    // PKIX API (certificates, CSRs, CRLs, OCSP, signing) — JCA-aligned; the
    // BouncyCastle implementation in zeroecho.pkix.bc stays internal to this module.
    exports zeroecho.pkix;
    exports zeroecho.pkix.cert;
    exports zeroecho.pkix.cmp;
    exports zeroecho.pkix.ct;
    exports zeroecho.pkix.crl;
    exports zeroecho.pkix.csr;
    exports zeroecho.pkix.ocsp;
    exports zeroecho.pkix.scep;
    exports zeroecho.pkix.sign;
    exports zeroecho.pkix.spi;

    // Algorithm catalog discovered via ServiceLoader.
    uses zeroecho.core.CryptoAlgorithm;
    uses zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
    uses zeroecho.pkix.spi.PkixProvider;

    provides zeroecho.core.CryptoAlgorithm with
            zeroecho.core.alg.aes.AesAlgorithm,
            zeroecho.core.alg.bike.BikeAlgorithm,
            zeroecho.core.alg.chacha.ChaCha20Poly1305Algorithm,
            zeroecho.core.alg.chacha.ChaChaAlgorithm,
            zeroecho.core.alg.cmce.CmceAlgorithm,
            zeroecho.core.alg.dh.DhAlgorithm,
            zeroecho.core.alg.digest.Sha2Sha3Algorithm,
            zeroecho.core.alg.ecdh.EcdhAlgorithm,
            zeroecho.core.alg.ecdsa.EcdsaAlgorithm,
            zeroecho.core.alg.ed448.Ed448Algorithm,
            zeroecho.core.alg.ed25519.Ed25519Algorithm,
            zeroecho.core.alg.elgamal.ElgamalAlgorithm,
            zeroecho.core.alg.frodo.FrodoAlgorithm,
            zeroecho.core.alg.hmac.HmacAlgorithm,
            zeroecho.core.alg.hqc.HqcAlgorithm,
            zeroecho.core.alg.kyber.KyberAlgorithm,
            zeroecho.core.alg.mldsa.MldsaAlgorithm,
            zeroecho.core.alg.ntru.NtruAlgorithm,
            zeroecho.core.alg.ntruprime.NtrulPrimeAlgorithm,
            zeroecho.core.alg.ntruprime.SntruPrimeAlgorithm,
            zeroecho.core.alg.rsa.RsaAlgorithm,
            zeroecho.core.alg.saber.SaberAlgorithm,
            zeroecho.core.alg.lms.LmsAlgorithm,
            zeroecho.core.alg.slhdsa.SlhDsaAlgorithm,
            zeroecho.core.alg.sphincsplus.SphincsPlusAlgorithm,
            zeroecho.core.alg.xdh.XdhAlgorithm,
            zeroecho.core.alg.xmss.XmssAlgorithm,
            zeroecho.core.alg.xwing.XWingAlgorithm;
}
