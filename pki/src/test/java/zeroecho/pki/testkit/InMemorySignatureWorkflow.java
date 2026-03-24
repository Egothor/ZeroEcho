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
package zeroecho.pki.testkit;

import java.security.KeyPair;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * Test-only in-memory signature workflow.
 */
public final class InMemorySignatureWorkflow implements SignatureWorkflow {

    private final Map<String, KeyPair> keys;
    private final Map<PkiId, OperationStatus> status;
    private long counter;

    public InMemorySignatureWorkflow(Map<String, KeyPair> keys) {
        this.keys = new HashMap<>(Objects.requireNonNull(keys, "keys"));
        this.status = new HashMap<>();
        this.counter = 1L;
    }

    @Override
    public String id() {
        return "test-signer";
    }

    @Override
    public PkiId submitSign(SignRequest request) {
        Objects.requireNonNull(request, "request");
        PkiId opId = new PkiId("sig:" + (counter++));

        try {
            KeyPair kp = keys.get(request.keyRef().value());
            if (kp == null) {
                OperationStatus st = new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNKNOWN_KEY"),
                        Optional.empty());
                status.put(opId, st);
                return opId;
            }

            java.security.Signature sig = java.security.Signature.getInstance(request.algorithmId());
            sig.initSign(kp.getPrivate());
            sig.update(request.payload().bytes());
            byte[] s = sig.sign();

            OperationResult res = new OperationResult(Optional.of(new EncodedObject(Encoding.BINARY, s)),
                    Optional.empty());
            OperationStatus st = new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of("SIGNED"),
                    Optional.of(res));
            status.put(opId, st);
            return opId;
        } catch (Exception ex) {
            OperationStatus st = new OperationStatus(State.FAILED, Instant.now(), Optional.of("SIGN_FAILED"),
                    Optional.empty());
            status.put(opId, st);
            return opId;
        }
    }

    @Override
    public PkiId submitVerify(VerifyRequest request) {
        Objects.requireNonNull(request, "request");
        PkiId opId = new PkiId("verify:" + (counter++));
        OperationStatus st = new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNSUPPORTED"),
                Optional.empty());
        status.put(opId, st);
        return opId;
    }

    @Override
    public OperationStatus status(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        OperationStatus st = status.get(operationId);
        if (st == null) {
            return new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNKNOWN_OP"), Optional.empty());
        }
        return st;
    }

    @Override
    public boolean cancel(PkiId operationId, String reason) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        return false;
    }

    @Override
    public Registration register(NotificationSink sink) {
        Objects.requireNonNull(sink, "sink");
        return () -> {
            // no-op
        };
    }

    @Override
    public Set<String> supportedAlgorithms() {
        return Set.of("SHA256withRSA");
    }

    @Override
    public void close() {
        // no-op
    }
}
