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
package zeroecho.pki.impl.crypto.zeroecholib;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * ZeroEcho-lib backed {@link SignatureWorkflow}.
 *
 * <h2>Failure model</h2>
 * <p>
 * Validation and policy failures must not surface as uncaught exceptions.
 * Instead, this provider always returns an operation id and exposes failures
 * via {@link #status(PkiId)} as {@link State#FAILED} with a stable detail code.
 * </p>
 *
 * <h2>Security</h2>
 * <ul>
 * <li>Never logs {@link KeyRef} values.</li>
 * <li>Never logs payload bytes or signature bytes.</li>
 * <li>Never returns private key material; private keys are materialized only
 * within this boundary.</li>
 * </ul>
 */
public final class ZeroEchoLibSignatureWorkflow implements SignatureWorkflow { // NOPMD

    private static final Logger LOG = Logger.getLogger(ZeroEchoLibSignatureWorkflow.class.getName());

    // Stable detail codes (non-secret), intended for audit + transport mapping.
    public static final String DC_SUBMITTED = "SUBMITTED";
    public static final String DC_SIGNED = "SIGNED";
    public static final String DC_VERIFIED = "VERIFIED";
    public static final String DC_REJECTED = "REJECTED";
    public static final String DC_CANCELLED = "CANCELLED";

    public static final String DC_INVALID_KEYREF_SUFFIX = "INVALID_KEYREF_SUFFIX";
    public static final String DC_INVALID_KEYREF_PREFIX = "INVALID_KEYREF_PREFIX";
    public static final String DC_UNSUPPORTED_PUBLICKEY_FORM = "UNSUPPORTED_PUBLICKEY_FORM"; // NOPMD
    public static final String DC_INVALID_ALGORITHM_ID = "INVALID_ALGORITHM_ID";
    public static final String DC_ALGORITHM_MISMATCH = "ALGORITHM_MISMATCH";
    public static final String DC_KEYRING_IO_ERROR = "KEYRING_IO_ERROR";
    public static final String DC_KEY_NOT_FOUND = "KEY_NOT_FOUND";
    public static final String DC_CRYPTO_FAILURE = "CRYPTO_FAILURE";
    public static final String DC_UNSUPPORTED_SIGNATURE_ENCODING = "UNSUPPORTED_SIGNATURE_ENCODING"; // NOPMD
    public static final String DC_UNKNOWN_OPERATION = "UNKNOWN_OPERATION";

    private static final OperationStatus UNKNOWN_OPERATION_STATUS = new OperationStatus(State.FAILED, Instant.EPOCH,
            Optional.of(DC_UNKNOWN_OPERATION), Optional.empty());

    private final String id;
    private final java.nio.file.Path keyringPath;
    private final String keyRefPrefix;
    private final boolean requireComponentSuffix;

    private final Map<PkiId, OperationStatus> statuses;
    private final Map<PkiId, NotificationSink> sinks;

    private volatile KeyringStore keyringOrNull; // NOPMD

    /* default */ ZeroEchoLibSignatureWorkflow(String id, java.nio.file.Path keyringPath, String keyRefPrefix,
            boolean requireComponentSuffix) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (keyringPath == null) {
            throw new IllegalArgumentException("keyringPath must not be null");
        }
        if (keyRefPrefix == null) {
            throw new IllegalArgumentException("keyRefPrefix must not be null");
        }
        this.id = id;
        this.keyringPath = keyringPath;
        this.keyRefPrefix = keyRefPrefix;
        this.requireComponentSuffix = requireComponentSuffix;

        this.statuses = Collections.synchronizedMap(new HashMap<>());
        this.sinks = Collections.synchronizedMap(new HashMap<>());
    }

    @Override
    public String id() {
        return this.id;
    }

    @Override
    public Set<String> supportedAlgorithms() {
        // Informational only; runtime policy/key availability may still reject.
        return CryptoAlgorithms.available();
    }

    @Override
    public PkiId submitSign(SignRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        PkiId opId = newOperationId();
        putStatus(opId, new OperationStatus(State.RUNNING, Instant.now(), Optional.of(DC_SUBMITTED), Optional.empty()));

        try {
            KeyRefParts parts = parseKeyRefOrThrow(request.keyRef(), true);

            if (request.algorithmId() == null || request.algorithmId().isBlank()) {
                throw new InvalidRequestException(DC_INVALID_ALGORITHM_ID);
            }

            KeyringStore ks = requireKeyringOrThrow();

            KeyringStore.PrivateWithId prv;
            KeyringStore.PublicWithId pub;
            try {
                prv = ks.getPrivateWithId(parts.privateAlias);
                pub = ks.getPublicWithId(parts.publicAlias);
            } catch (GeneralSecurityException missing) {
                throw new InvalidRequestException(DC_KEY_NOT_FOUND, missing);
            }

            enforceAlgorithmMatchOrThrow(request.algorithmId(), prv.algorithm());

            byte[] signatureBytes = signStreaming(request.algorithmId(), prv.key(), pub.key(),
                    request.payload().bytes());

            Encoding outEnc = request.preferredSignatureEncoding().orElse(Encoding.BINARY);
            EncodedObject signature = encodeSignatureOrThrow(outEnc, signatureBytes);

            OperationResult result = new OperationResult(Optional.of(signature), Optional.empty());
            putStatus(opId,
                    new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of(DC_SIGNED), Optional.of(result)));
            return opId;

        } catch (InvalidRequestException inv) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(inv.detailCode), Optional.empty()));
            return opId;

        } catch (IOException io) {
            putStatus(opId, new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_KEYRING_IO_ERROR),
                    Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Sign failed due to IO (details suppressed)", io);
            }
            return opId;

        } catch (GeneralSecurityException sec) {
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Sign failed due to security exception (details suppressed)", sec);
            }
            return opId;

        } catch (RuntimeException ex) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Sign failed due to runtime exception (details suppressed)", ex);
            }
            return opId;
        }
    }

    @Override
    public PkiId submitVerify(VerifyRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        PkiId opId = newOperationId();
        putStatus(opId, new OperationStatus(State.RUNNING, Instant.now(), Optional.of(DC_SUBMITTED), Optional.empty()));

        try {
            if (request.algorithmId() == null || request.algorithmId().isBlank()) {
                throw new InvalidRequestException(DC_INVALID_ALGORITHM_ID);
            }

            // Provider choice: full PQC/hybrid support requires KeyRef for public keys.
            // Encoded public keys are not supported here; treat as FAILED (Variant 1).
            if (request.publicKeyRef().isEmpty() && request.publicKeyEncoded().isPresent()) {
                throw new InvalidRequestException(DC_UNSUPPORTED_PUBLICKEY_FORM);
            }

            PublicKey pub = resolvePublicKeyOrThrow(request);

            byte[] sigBytes = decodeSignatureOrThrow(request.signature());
            boolean ok = verifyStreaming(request.algorithmId(), pub, request.payload().bytes(), sigBytes);

            OperationResult result = new OperationResult(Optional.empty(), Optional.of(ok));
            String dc = ok ? DC_VERIFIED : DC_REJECTED;
            putStatus(opId, new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of(dc), Optional.of(result)));
            return opId;

        } catch (InvalidRequestException inv) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(inv.detailCode), Optional.empty()));
            return opId;

        } catch (IOException io) {
            putStatus(opId, new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_KEYRING_IO_ERROR),
                    Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Verify failed due to IO (details suppressed)", io);
            }
            return opId;

        } catch (GeneralSecurityException sec) {
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Verify failed due to security exception (details suppressed)", sec);
            }
            return opId;

        } catch (RuntimeException ex) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Verify failed due to runtime exception (details suppressed)", ex);
            }
            return opId;
        }
    }

    @Override
    public OperationStatus status(PkiId operationId) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        OperationStatus st = this.statuses.get(operationId);
        if (st == null) {
            return UNKNOWN_OPERATION_STATUS;
        }
        return st;
    }

    @Override
    public boolean cancel(PkiId operationId, String reason) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        OperationStatus st = this.statuses.get(operationId);
        if (st == null || st.isTerminal()) {
            return false;
        }
        putStatus(operationId,
                new OperationStatus(State.CANCELLED, Instant.now(), Optional.of(DC_CANCELLED), Optional.empty()));
        return true;
    }

    @Override
    public Registration register(NotificationSink sink) {
        if (sink == null) {
            throw new IllegalArgumentException("sink must not be null");
        }
        PkiId regId = newOperationId();
        this.sinks.put(regId, sink);
        return new Registration() {
            @Override
            public void close() {
                sinks.remove(regId);
            }
        };
    }

    @Override
    public void close() {
        this.statuses.clear();
        this.sinks.clear();
        this.keyringOrNull = null;
    }

    private KeyringStore requireKeyringOrThrow() throws IOException {
        KeyringStore ks = this.keyringOrNull;
        if (ks != null) {
            return ks;
        }
        KeyringStore loaded = KeyringStore.load(this.keyringPath);
        this.keyringOrNull = loaded;
        return loaded;
    }

    private static void enforceAlgorithmMatchOrThrow(String requested, String stored) throws InvalidRequestException {
        if (!requested.equals(stored)) {
            throw new InvalidRequestException(DC_ALGORITHM_MISMATCH);
        }
    }

    private KeyRefParts parseKeyRefOrThrow(KeyRef keyRef, boolean forSigning) throws InvalidRequestException {
        String raw = keyRef.value();
        if (!raw.startsWith(this.keyRefPrefix)) {
            throw new InvalidRequestException(DC_INVALID_KEYREF_PREFIX);
        }

        String v = raw.substring(this.keyRefPrefix.length());
        boolean hasPrv = v.endsWith(".prv");
        boolean hasPub = v.endsWith(".pub");

        if (this.requireComponentSuffix) {
            if (forSigning && !hasPrv) {
                throw new InvalidRequestException(DC_INVALID_KEYREF_SUFFIX);
            }
            if (!forSigning && !hasPub) {
                throw new InvalidRequestException(DC_INVALID_KEYREF_SUFFIX);
            }
        }

        if (forSigning) {
            String privateAlias = hasPrv ? v : (v + ".prv");
            String base = hasPrv ? v.substring(0, v.length() - 4) : v;
            String publicAlias = base + ".pub";
            return new KeyRefParts(privateAlias, publicAlias);
        }

        String publicAlias = hasPub ? v : (v + ".pub");
        return new KeyRefParts(publicAlias, publicAlias);
    }

    private PublicKey resolvePublicKeyOrThrow(VerifyRequest request)
            throws InvalidRequestException, IOException, GeneralSecurityException {

        if (request.publicKeyRef().isPresent()) {
            KeyRefParts parts = parseKeyRefOrThrow(request.publicKeyRef().get(), false);

            KeyringStore ks = requireKeyringOrThrow();

            KeyringStore.PublicWithId pub;
            try {
                pub = ks.getPublicWithId(parts.publicAlias);
            } catch (GeneralSecurityException missing) {
                throw new InvalidRequestException(DC_KEY_NOT_FOUND, missing);
            }

            enforceAlgorithmMatchOrThrow(request.algorithmId(), pub.algorithm());
            return pub.key();
        }

        throw new InvalidRequestException(DC_UNSUPPORTED_PUBLICKEY_FORM);
    }

    private static byte[] signStreaming(String algorithmId, PrivateKey prv, PublicKey pub, byte[] msg)
            throws GeneralSecurityException, IOException {

        int sigLen;
        try (SignatureContext verifier = CryptoAlgorithms.create(algorithmId, KeyUsage.VERIFY, pub)) {
            sigLen = verifier.tagLength();
        }

        try (SignatureContext signer = CryptoAlgorithms.create(algorithmId, KeyUsage.SIGN, prv)) {
            final byte[][] sigHolder = new byte[1][];
            try (InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(msg)), sigLen,
                    8192) {
                @Override
                protected void processTail(byte[] tail) throws IOException {
                    sigHolder[0] = (tail == null) ? null : tail.clone();
                }
            }) {
                in.transferTo(OutputStream.nullOutputStream());
            }

            byte[] sig = sigHolder[0];
            if (sig == null || sig.length == 0) {
                throw new GeneralSecurityException("Signature trailer missing.");
            }
            return sig;
        }
    }

    private static boolean verifyStreaming(String algorithmId, PublicKey pub, byte[] msg, byte[] signature)
            throws GeneralSecurityException, IOException {

        try (SignatureContext verifier = CryptoAlgorithms.create(algorithmId, KeyUsage.VERIFY, pub)) {
            verifier.setExpectedTag(signature);
            try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                in.transferTo(OutputStream.nullOutputStream());
            }
            return true;
        } catch (Exception mismatch) {
            return false;
        }
    }

    private static EncodedObject encodeSignatureOrThrow(Encoding encoding, byte[] sigBytes)
            throws InvalidRequestException {
        if (encoding == Encoding.BINARY || encoding == Encoding.DER) {
            return new EncodedObject(encoding, sigBytes);
        }
        if (encoding == Encoding.PEM) {
            String pem = pemWrap("ZEROECHO SIGNATURE", sigBytes);
            return new EncodedObject(Encoding.PEM, pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
        throw new InvalidRequestException(DC_UNSUPPORTED_SIGNATURE_ENCODING);
    }

    private static byte[] decodeSignatureOrThrow(EncodedObject signature) throws InvalidRequestException {
        if (signature.encoding() == Encoding.BINARY || signature.encoding() == Encoding.DER) {
            return signature.bytes().clone();
        }
        if (signature.encoding() == Encoding.PEM) {
            String text = new String(signature.bytes(), java.nio.charset.StandardCharsets.US_ASCII);
            return pemUnwrap(text);
        }
        throw new InvalidRequestException(DC_UNSUPPORTED_SIGNATURE_ENCODING);
    }

    private static String pemWrap(String label, byte[] data) {
        String b64 = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(data);
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    }

    private static byte[] pemUnwrap(String pem) {
        String[] lines = pem.replace("\r", "").split("\n");
        StringBuilder b64 = new StringBuilder();
        for (String line : lines) {
            if (line.startsWith("-----BEGIN ") || line.startsWith("-----END ")) {
                continue;
            }
            String t = line.trim();
            if (!t.isEmpty()) {
                b64.append(t);
            }
        }
        return Base64.getDecoder().decode(b64.toString());
    }

    private void putStatus(PkiId id, OperationStatus st) {
        this.statuses.put(id, st);
        for (NotificationSink sink : this.sinks.values()) {
            try {
                sink.onStatusChanged(id, st);
            } catch (Throwable ignore) { // NOPMD
                // sink must not break provider
                LOG.log(Level.FINE, "cannot put status, ignoring", ignore);
            }
        }
    }

    private static PkiId newOperationId() {
        return new PkiId(UUID.randomUUID().toString());
    }

    /**
     * Parsed, provider-local representation of a {@link KeyRef}.
     *
     * <p>
     * This is an internal helper that translates an opaque {@link KeyRef} into
     * concrete keyring aliases. The mapping is intentionally provider-specific: PKI
     * must treat {@link KeyRef} as an opaque identifier and must never rely on
     * parsing rules.
     * </p>
     *
     * <h2>Security</h2>
     * <ul>
     * <li>This type must never contain private key material; it only carries alias
     * strings.</li>
     * <li>Instances must not be logged in production, as aliases can be sensitive
     * operational metadata.</li>
     * </ul>
     *
     * <p>
     * For signing requests, {@link #privateAlias} is expected to address the
     * private component (e.g. {@code *.prv}) and {@link #publicAlias} the
     * corresponding public component (e.g. {@code *.pub}). For verification,
     * {@link #privateAlias} is unused and {@link #publicAlias} addresses the public
     * component.
     * </p>
     */
    private static final class KeyRefParts {
        private final String privateAlias;
        private final String publicAlias;

        private KeyRefParts(String privateAlias, String publicAlias) {
            this.privateAlias = privateAlias;
            this.publicAlias = publicAlias;
        }
    }

    /**
     * Internal exception used to signal validation/policy failures that must be
     * surfaced via operation status.
     *
     * <p>
     * This exception must never escape the public boundary of
     * {@link ZeroEchoLibSignatureWorkflow}. It is caught by
     * {@code submitSign}/{@code submitVerify} and converted to a deterministic
     * status: {@link State#FAILED} with a stable {@code detailCode}.
     * </p>
     *
     * <h2>Design constraints</h2>
     * <ul>
     * <li>{@code detailCode} must be non-sensitive and stable, suitable for audit
     * logs and transport-level APIs.</li>
     * <li>The exception message is set to {@code detailCode} for diagnostics only;
     * callers must not depend on it.</li>
     * <li>{@code cause} may be attached for local diagnostics but must not be used
     * to derive user-facing output.</li>
     * </ul>
     */
    private static final class InvalidRequestException extends Exception {
        private static final long serialVersionUID = 2058759559902131220L;
        private final String detailCode;

        private InvalidRequestException(String detailCode) {
            super(detailCode);
            this.detailCode = detailCode;
        }

        private InvalidRequestException(String detailCode, Throwable cause) {
            super(detailCode, cause);
            this.detailCode = detailCode;
        }
    }
}
