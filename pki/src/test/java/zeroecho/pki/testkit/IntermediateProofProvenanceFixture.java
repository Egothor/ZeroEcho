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

package zeroecho.pki.testkit;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.IntermediateSigningCommand;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Structural fixture only; does not manufacture a retained completed proof. */
public final class IntermediateProofProvenanceFixture {
    private IntermediateProofProvenanceFixture() { }

    /** Adds exact structural provenance to synthetic internal acceptance fixtures. */
    public static DomainContinuationTemplate withProof(DomainContinuationTemplate template, String namespace,
            ConfigurationCommitment configuration, long tbsLength, String tbsSha256) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(template.command());
        List<String> fields = new ArrayList<>(command.fields());
        DomainContinuationTemplate proof = DomainCommandEncoding.template(DomainContinuationStore.Kind.KEY_PROOF,
                ManagedKeyProofCommand.OPERATION, "CA_SUBJECT_KEY", fields.get(1),
                IntermediateSigningCommand.CREATE.equals(command.operation()) ? "" : fields.get(2), fields.get(7), "", fields.get(6),
                namespace, HexFormat.of().formatHex(configuration.bytes()),
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), "300506032b6570",
                "44", fields.get(17), "1", "0".repeat(64));
        fields.set(18, "zsign:v1:" + namespace + ":0:" + "0".repeat(32));
        fields.set(19, IntermediateSigningCommand.encodeProof(proof.command()));
        fields.set(20, DomainAttributeEncoding.encode(new SimpleAttributeSet(List.of())));
        fields.add(Long.toString(tbsLength));
        fields.add(tbsSha256);
        DomainContinuationTemplate encoded = DomainCommandEncoding.template(template.kind(),
                command.operation(), fields.toArray(String[]::new));
        return new DomainContinuationTemplate(encoded.kind(), template.correlationId(), encoded.command(), encoded.commandCommitment());
    }
}
