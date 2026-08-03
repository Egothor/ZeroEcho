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

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.spi.ProviderConfig;

/** Strict versioned CLI configuration loader. */
final class PkiCliConfiguration {

    private static final Set<String> ROOT_FIELDS = Set.of("version", "store", "audit");
    private static final Set<String> PROVIDER_FIELDS = Set.of("provider", "properties");
    private static final String STDOUT_PROVIDER = "stdout";

    private PkiCliConfiguration() {
    }

    /* default */ static PkiSessionConfiguration read(Path path) throws java.io.IOException {
        byte[] document = PkiCliFiles.readRegularFile(path, PkiCliJson.MAXIMUM_DOCUMENT_BYTES);
        PkiOperationValue.ObjectValue root = object(PkiCliJson.parse(document));
        requireExactFields(root.fields(), ROOT_FIELDS);
        int version = Math.toIntExact(integer(required(root, "version")));
        ProviderConfig store = provider(required(root, "store"));
        ProviderConfig audit = provider(required(root, "audit"));
        if (STDOUT_PROVIDER.equals(audit.backendId())) {
            throw new IllegalArgumentException("CLI audit provider must not write to standard output");
        }
        return new PkiSessionConfiguration(version, store, audit);
    }

    private static ProviderConfig provider(PkiOperationValue value) {
        PkiOperationValue.ObjectValue object = object(value);
        requireExactFields(object.fields(), PROVIDER_FIELDS);
        String provider = text(required(object, "provider"));
        PkiOperationValue.ObjectValue properties = object(required(object, "properties"));
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, PkiOperationValue> entry : properties.fields().entrySet()) {
            result.put(entry.getKey(), text(entry.getValue()));
        }
        return new ProviderConfig(provider, result);
    }

    /* default */ static PkiOperationValue required(PkiOperationValue.ObjectValue object, String name) {
        PkiOperationValue value = object.fields().get(name);
        if (value == null) {
            throw new IllegalArgumentException("Required CLI field is missing");
        }
        return value;
    }

    /* default */ static PkiOperationValue.ObjectValue object(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.ObjectValue object) {
            return object;
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }

    /* default */ static String text(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.Text text) {
            return text.value();
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }

    /* default */ static long integer(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.IntegerValue integer) {
            return integer.value();
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }

    /* default */ static void requireExactFields(Map<String, PkiOperationValue> actual, Set<String> expected) {
        if (!actual.keySet().equals(expected)) {
            throw new IllegalArgumentException("CLI document fields are invalid");
        }
    }
}
