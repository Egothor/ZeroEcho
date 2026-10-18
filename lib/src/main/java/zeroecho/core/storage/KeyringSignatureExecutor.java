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
package zeroecho.core.storage;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.common.sig.SignatureInteropProfile;
import zeroecho.core.alg.common.sig.SignatureInteropProfiles;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.core.err.UnsupportedSpecException;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Executes a streaming signature while confining private-key resolution to the
 * keyring-owning library boundary.
 *
 * <p>
 * Instances retain only the owning {@link KeyringStore} and
 * {@link ZeroEchoSession}; they never retain, expose, encode, or log private key
 * material. Each invocation resolves its key entries independently and creates
 * operation-local signature contexts. Instances are safe for concurrent use when
 * callers provide independent content and cancellation objects.
 * </p>
 *
 * <p>
 * Signing runs in {@code O(n)} time for an {@code n}-byte payload and uses
 * {@code O(1)} transfer memory plus storage bounded by the selected algorithm's
 * signature length. The executor closes streams opened for the invocation but
 * does not close the caller-owned {@link RepeatableContent}.
 * </p>
 */
public final class KeyringSignatureExecutor {
    private static final int TRANSFER_BUFFER_BYTES = 16 * 1024;

    private final KeyringStore keyring;
    private final ZeroEchoSession session;

    /**
     * Stable, non-sensitive failure categories.
     */
    public enum FailureCode {
        /** A requested key entry is absent or has the wrong entry kind. */
        KEY_UNAVAILABLE,
        /** The identity is incompatible, or a stored LMS/XMSS key cannot safely sign. */
        ALGORITHM_MISMATCH,
        /** Cryptographic-provider execution failed. */
        PROVIDER_FAILURE
    }

    /**
     * Checked, redacted failure raised by key resolution or provider execution.
     */
    public static final class Failure extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;
        /** Stable redacted failure category. */
        private final FailureCode code;

        private Failure(FailureCode code) {
            super(Objects.requireNonNull(code, "code must not be null").name());
            this.code = code;
        }

        /**
         * Returns the stable failure category.
         *
         * @return non-sensitive failure code
         */
        public FailureCode code() {
            return code;
        }
    }

    /**
     * Cause-free marker indicating cancellation observed at a documented signing
     * checkpoint.
     */
    public static final class Cancellation extends InterruptedIOException {
        private static final long serialVersionUID = 1L;

        private Cancellation() {
            super("SIGNING_CANCELLED");
        }
    }

    /**
     * Creates an executor bound to an open keyring and a session.
     *
     * @param keyring owning keyring used to resolve provider-local aliases
     * @param session session whose policy and provider configuration govern signing
     * @throws NullPointerException if either argument is {@code null}
     */
    public KeyringSignatureExecutor(KeyringStore keyring, ZeroEchoSession session) {
        this.keyring = Objects.requireNonNull(keyring, "keyring must not be null");
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Signs repeatable content using a private key resolved within this executor.
     *
     * <p>
     * The algorithm identity must resolve to a registered interop profile through
     * its canonical form. The stored private-key entry must carry that profile's
     * exact key algorithm identifier. Cancellation is checked before key
     * resolution, before opening the content, and between bounded reads.
     * </p>
     *
     * @param privateAlias     provider-local private-key alias; must not be blank
     * @param algorithmIdentity exact canonical signature identity
     * @param content          caller-owned repeatable content; never closed here
     * @param cancellation     cancellation signal consulted during the operation
     * @return independently owned external signature bytes
     * @throws IllegalArgumentException if an alias is blank or the identity is not
     *                                  a signature identity
     * @throws NullPointerException     if any non-alias argument is {@code null}
     * @throws IOException              if keyring resolution, authentication, or
     *                                  filesystem I/O fails; if content opening or
     *                                  streaming fails; or if a stream makes zero
     *                                  progress
     * @throws Failure                  if a key is unavailable, the algorithm does
     *                                  not match, or provider execution fails;
     *                                  LMS/XMSS keys yield {@code ALGORITHM_MISMATCH}
     */
    public byte[] sign(String privateAlias, AlgorithmIdentity algorithmIdentity, RepeatableContent content,
            CancellationSignal cancellation) throws IOException, Failure {
        requireNonBlank(privateAlias, "privateAlias");
        Objects.requireNonNull(algorithmIdentity, "algorithmIdentity must not be null");
        Objects.requireNonNull(content, "content must not be null");
        Objects.requireNonNull(cancellation, "cancellation must not be null");
        if (algorithmIdentity.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw new IllegalArgumentException("algorithmIdentity must have SIGNATURE kind");
        }

        Optional<SignatureInteropProfile> resolvedProfile = SignatureInteropProfiles
                .resolve(algorithmIdentity.canonicalForm());
        if (resolvedProfile.isEmpty()) {
            throw new Failure(FailureCode.ALGORITHM_MISMATCH);
        }
        SignatureInteropProfile profile = resolvedProfile.get();

        checkCancellation(cancellation);
        KeyringStore.PrivateWithId privateEntry = null;
        FailureCode resolutionFailure = null;
        try {
            privateEntry = keyring.getPrivateWithId(privateAlias);
        } catch (IllegalArgumentException unavailable) {
            resolutionFailure = FailureCode.KEY_UNAVAILABLE;
        } catch (GeneralSecurityException | IllegalStateException | SecurityException
                | ProviderException providerFailure) {
            resolutionFailure = FailureCode.PROVIDER_FAILURE;
        }
        if (resolutionFailure != null) {
            throw new Failure(resolutionFailure);
        }

        try {
            zeroecho.core.alg.common.sig.StatefulSigningGuard.requireStateless(privateEntry.algorithm(), privateEntry.key());
        } catch (UnsupportedRoleException unavailable) {
            throw new Failure(FailureCode.ALGORITHM_MISMATCH); // NOPMD PreserveStackTrace - Expose a redacted category without provider details.
        }
        String expectedKeyAlgorithm = profile.keyAlgorithmId();
        if (!expectedKeyAlgorithm.equals(privateEntry.algorithm())) {
            throw new Failure(FailureCode.ALGORITHM_MISMATCH);
        }

        PrivateKey privateKey = privateEntry.key();
        SignatureContext signer = null;
        boolean creationFailed = false;
        try {
            signer = session.createContext(profile.contextAlgorithmId(), KeyUsage.SIGN, privateKey,
                    profile.contextSpec());
        } catch (UnsupportedRoleException | UnsupportedSpecException | IllegalArgumentException
                | IllegalStateException | SecurityException | ProviderException providerFailure) {
            creationFailed = true;
        }
        if (creationFailed) {
            throw new Failure(FailureCode.PROVIDER_FAILURE);
        }

        ExecutionResult result = ExecutionResult.providerFailure();
        try (SignatureContext ownedSigner = signer) {
            result = executeOpenContent(ownedSigner, profile, content, cancellation);
        } catch (IOException | IllegalArgumentException | IllegalStateException | SecurityException
                | ProviderException providerCloseFailure) {
            result = result.withProviderFailure();
        }
        return result.valueOrThrow();
    }

    private static ExecutionResult executeOpenContent(SignatureContext signer, SignatureInteropProfile profile,
            RepeatableContent content, CancellationSignal cancellation) {
        int signatureLength;
        try {
            signatureLength = signer.tagLength();
        } catch (IllegalArgumentException | IllegalStateException | SecurityException
                | ProviderException providerFailure) {
            return ExecutionResult.providerFailure();
        }
        if (signatureLength <= 0) {
            return ExecutionResult.providerFailure();
        }
        try {
            checkCancellation(cancellation);
        } catch (Cancellation cancelled) {
            return ExecutionResult.cancelled();
        }

        ProgressCheckedInputStream source;
        try {
            source = new ProgressCheckedInputStream(content.openStream(), cancellation);
        } catch (IOException contentFailure) {
            return ExecutionResult.contentFailure(contentFailure);
        }
        ExecutionResult result = ExecutionResult.providerFailure();
        try (source; InputStream input = signer.wrap(source)) {
            result = readSignatureTail(input, signatureLength, cancellation);
            if (result.kind == ExecutionKind.SUCCESS) {
                source.disableCancellationChecks();
                result = convertSignature(profile, result);
                if (result.kind == ExecutionKind.PROVIDER_FAILURE) {
                    source.abortReads();
                }
            } else {
                source.abortReads();
            }
        } catch (ContentBoundaryIOException contentFailure) {
            result = result.withContentFailure(contentFailure.original);
        } catch (Cancellation cancelled) {
            result = ExecutionResult.cancelled();
        } catch (IOException | IllegalArgumentException | IllegalStateException | SecurityException
                | ProviderException providerFailure) {
            result = result.withProviderFailure();
        }
        return result;
    }

    private static ExecutionResult convertSignature(SignatureInteropProfile profile, ExecutionResult internal) {
        byte[] internalSignature = internal.signature;
        try {
            byte[] external = profile.internalToExternalSignature(internalSignature);
            return ExecutionResult.success(external);
        } catch (IOException | IllegalArgumentException | IllegalStateException | SecurityException
                | ProviderException malformedResult) {
            return ExecutionResult.providerFailure();
        } finally {
            Arrays.fill(internalSignature, (byte) 0);
        }
    }

    private static ExecutionResult readSignatureTail(InputStream input, int signatureLength,
            CancellationSignal cancellation) {
        byte[] transfer = new byte[TRANSFER_BUFFER_BYTES];
        byte[] tail = new byte[signatureLength];
        int tailCount = 0;
        int tailPosition = 0;
        try {
            while (true) {
                try {
                    checkCancellation(cancellation);
                } catch (Cancellation cancelled) {
                    return ExecutionResult.cancelled();
                }
                int count;
                try {
                    count = input.read(transfer);
                } catch (ContentBoundaryIOException contentFailure) {
                    return ExecutionResult.contentFailure(contentFailure.original);
                } catch (Cancellation cancelled) {
                    return ExecutionResult.cancelled();
                } catch (IOException | IllegalArgumentException | IllegalStateException | SecurityException
                        | ProviderException providerFailure) {
                    return ExecutionResult.providerFailure();
                }
                if (count < 0) {
                    break;
                }
                if (count == 0) {
                    return ExecutionResult.providerFailure();
                }
                if (count >= signatureLength) {
                    System.arraycopy(transfer, count - signatureLength, tail, 0, signatureLength);
                    tailCount = signatureLength;
                    tailPosition = 0;
                } else {
                    int first = Math.min(count, signatureLength - tailPosition);
                    System.arraycopy(transfer, 0, tail, tailPosition, first);
                    int remaining = count - first;
                    if (remaining > 0) {
                        System.arraycopy(transfer, first, tail, 0, remaining);
                    }
                    tailPosition = (tailPosition + count) % signatureLength;
                    tailCount = Math.min(signatureLength, tailCount + count);
                }
            }
            if (tailCount != signatureLength) {
                return ExecutionResult.providerFailure();
            }
            byte[] signature = new byte[signatureLength];
            int first = signatureLength - tailPosition;
            System.arraycopy(tail, tailPosition, signature, 0, first);
            if (tailPosition > 0) {
                System.arraycopy(tail, 0, signature, first, tailPosition);
            }
            try {
                checkCancellation(cancellation);
                return ExecutionResult.success(signature);
            } catch (Cancellation cancelled) {
                Arrays.fill(signature, (byte) 0);
                return ExecutionResult.cancelled();
            }
        } finally {
            Arrays.fill(transfer, (byte) 0);
            Arrays.fill(tail, (byte) 0);
        }
    }

    private static void checkCancellation(CancellationSignal cancellation) throws Cancellation {
        if (cancellation.isCancelled()) {
            throw new Cancellation();
        }
    }

    private static String requireNonBlank(String value, String parameterName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(parameterName + " must not be blank");
        }
        return value;
    }

    /** Content reader that marks caller-owned I/O and enforces read checkpoints. */
    private static final class ProgressCheckedInputStream extends FilterInputStream {
        private final CancellationSignal cancellation;
        private boolean readsAborted;
        private boolean cancellationChecksEnabled = true;
        private boolean closed;

        private ProgressCheckedInputStream(InputStream source, CancellationSignal cancellation) {
            super(Objects.requireNonNull(source, "source must not be null"));
            this.cancellation = cancellation;
        }

        @Override
        public int read() throws IOException {
            if (readsAborted) {
                return -1;
            }
            checkCancellationWhenEnabled();
            try {
                return super.read();
            } catch (IOException contentFailure) {
                throw new ContentBoundaryIOException(contentFailure);
            }
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            if (readsAborted) {
                return length == 0 ? 0 : -1;
            }
            checkCancellationWhenEnabled();
            int count;
            try {
                count = super.read(bytes, offset, length);
            } catch (IOException contentFailure) {
                throw new ContentBoundaryIOException(contentFailure);
            }
            if (length > 0 && count == 0) {
                throw new ContentBoundaryIOException(new IOException("Content stream made no progress"));
            }
            return count;
        }

        private void checkCancellationWhenEnabled() throws Cancellation {
            if (cancellationChecksEnabled) {
                checkCancellation(cancellation);
            }
        }

        private void disableCancellationChecks() {
            cancellationChecksEnabled = false;
        }

        private void abortReads() {
            readsAborted = true;
            cancellationChecksEnabled = false;
        }

        @Override
        public void close() throws IOException {
            if (!closed) {
                closed = true;
                try {
                    super.close();
                } catch (IOException contentFailure) {
                    throw new ContentBoundaryIOException(contentFailure);
                }
            }
        }
    }

    /** Internal marker retaining a caller-owned content failure until cleanup ends. */
    private static final class ContentBoundaryIOException extends IOException {
        private static final long serialVersionUID = 1L;
        private final IOException original;

        private ContentBoundaryIOException(IOException original) {
            super("CONTENT_IO");
            this.original = original;
        }
    }

    /** Exhaustive outcomes of provider signing execution. */
    private enum ExecutionKind {
        SUCCESS, CONTENT_FAILURE, CANCELLED, PROVIDER_FAILURE
    }

    /** Phase result that carries either owned signature bytes or one safe failure. */
    private static final class ExecutionResult {
        private final ExecutionKind kind;
        private final byte[] signature;
        private final IOException contentFailure;

        private ExecutionResult(ExecutionKind kind, byte[] signature, IOException contentFailure) {
            this.kind = kind;
            this.signature = signature;
            this.contentFailure = contentFailure;
        }

        private static ExecutionResult success(byte[] signature) {
            return new ExecutionResult(ExecutionKind.SUCCESS, signature, null);
        }

        private static ExecutionResult contentFailure(IOException failure) {
            return new ExecutionResult(ExecutionKind.CONTENT_FAILURE, null, failure);
        }

        private static ExecutionResult cancelled() {
            return new ExecutionResult(ExecutionKind.CANCELLED, null, null);
        }

        private static ExecutionResult providerFailure() {
            return new ExecutionResult(ExecutionKind.PROVIDER_FAILURE, null, null);
        }

        private ExecutionResult withContentFailure(IOException failure) {
            if (kind != ExecutionKind.SUCCESS) {
                return this;
            }
            Arrays.fill(signature, (byte) 0);
            return contentFailure(failure);
        }

        private ExecutionResult withProviderFailure() {
            if (signature != null) {
                Arrays.fill(signature, (byte) 0);
            }
            return kind == ExecutionKind.SUCCESS ? providerFailure() : this;
        }

        private byte[] valueOrThrow() throws IOException, Failure {
            return switch (kind) {
                case SUCCESS -> signature;
                case CONTENT_FAILURE -> throw contentFailure;
                case CANCELLED -> throw new Cancellation();
                case PROVIDER_FAILURE -> throw new Failure(FailureCode.PROVIDER_FAILURE);
            };
        }
    }
}
