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
package zeroecho.pki.cli;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationValue;

/** Explicit stable operation-name to typed-request binding registry. */
@SuppressWarnings("PMD.UnusedFormalParameter")
final class PkiOperationRegistry {

    private static final String CREDENTIAL_ID = "credentialId";

    private final Map<String, Binding> bindings;

    /* default */ PkiOperationRegistry() {
        Map<String, Binding> configured = new LinkedHashMap<>();
        add(configured, PkiOperation.ValidateConfiguration.NAME, this::configuration);
        add(configured, PkiOperation.ValidateProfile.NAME, this::profile);
        add(configured, PkiOperation.InspectCredential.NAME, this::credential);
        add(configured, PkiOperation.RevokeCredential.NAME, this::revoke);
        add(configured, PkiOperation.ReadRevocationHistory.NAME, this::history);
        add(configured, PkiOperation.InspectPublication.NAME, this::publication);
        bindings = Map.copyOf(configured);
    }

    /* default */ Set<String> names() {
        return bindings.keySet();
    }

    /* default */ PkiOperation bind(String name, PkiOperationValue.ObjectValue arguments, Path baseDirectory)
            throws IOException {
        Binding binding = bindings.get(name);
        if (binding == null) {
            throw new IllegalArgumentException("Unknown PKI operation");
        }
        return binding.bind(arguments, baseDirectory);
    }

    private PkiOperation configuration(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of());
        return new PkiOperation.ValidateConfiguration();
    }

    private PkiOperation profile(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException {
        requireFields(arguments, Set.of("profileFile"));
        Path path = resolve(baseDirectory, text(arguments, "profileFile"));
        byte[] document = PkiCliFiles.readRegularFile(path, CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES);
        return new PkiOperation.ValidateProfile(document);
    }

    private PkiOperation credential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiOperation.InspectCredential(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiOperation revoke(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID, "reason"));
        RevocationReason reason = RevocationReason.valueOf(text(arguments, "reason"));
        return new PkiOperation.RevokeCredential(new PkiId(text(arguments, CREDENTIAL_ID)), reason);
    }

    private PkiOperation history(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID, "limit"));
        int limit = Math.toIntExact(integer(arguments, "limit"));
        return new PkiOperation.ReadRevocationHistory(new PkiId(text(arguments, CREDENTIAL_ID)), limit);
    }

    private PkiOperation publication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of("publicationId"));
        return new PkiOperation.InspectPublication(new PkiId(text(arguments, "publicationId")));
    }

    private static void add(Map<String, Binding> target, String name, Binding binding) {
        if (target.putIfAbsent(name, binding) != null) {
            throw new IllegalStateException("Duplicate PKI operation identity");
        }
    }

    private static void requireFields(PkiOperationValue.ObjectValue arguments, Set<String> expected) {
        if (!arguments.fields().keySet().equals(expected)) {
            throw new IllegalArgumentException("PKI operation arguments are invalid");
        }
    }

    private static String text(PkiOperationValue.ObjectValue arguments, String name) {
        return PkiCliConfiguration.text(PkiCliConfiguration.required(arguments, name));
    }

    private static long integer(PkiOperationValue.ObjectValue arguments, String name) {
        return PkiCliConfiguration.integer(PkiCliConfiguration.required(arguments, name));
    }

    private static Path resolve(Path baseDirectory, String value) {
        Path supplied = Path.of(value);
        return (supplied.isAbsolute() ? supplied : baseDirectory.resolve(supplied)).toAbsolutePath().normalize();
    }

    /** One explicit typed binding. */
    @FunctionalInterface
    private interface Binding {
        /** Binds validated structured arguments to one typed operation. */
        PkiOperation bind(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException;
    }
}
