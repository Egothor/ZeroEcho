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
package zeroecho.pki.server;

import zeroecho.pki.application.PkiOperationValue;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Provides typed access to a JSON object while tracking consumed configuration fields.
 *
 * <p>Tracks consumed properties so that unknown or unused configuration fields can be rejected.
 */
final class ConfigurationFields {
    private final Map<String, PkiOperationValue> values;
    private final Set<String> consumed = new LinkedHashSet<>();

    private ConfigurationFields(Map<String, PkiOperationValue> values) {
        this.values = values;
    }

    /* default */ static ConfigurationFields of(PkiOperationValue value) {
        if (!(value instanceof PkiOperationValue.ObjectValue object)) {
            throw new IllegalArgumentException("Configuration value must be an object");
        }
        return new ConfigurationFields(object.fields());
    }

    /* default */ void exact(String... names) {
        allowed(Set.of(names));
        if (values.size() != names.length) {
            throw new IllegalArgumentException("Configuration fields are incomplete");
        }
    }

    /* default */ void allowed(Set<String> names) {
        if (!names.containsAll(values.keySet())) {
            throw new IllegalArgumentException("Unknown configuration field");
        }
    }

    /* default */ String text(String name) {
        consumed.add(name);
        return text(require(name));
    }

    /* default */ Optional<String> optionalText(String name) {
        if (!values.containsKey(name)) {
            return Optional.empty();
        }
        return Optional.of(text(name));
    }

    /* default */ int integer(String name) {
        long value = longValue(name);
        return Math.toIntExact(value);
    }

    /* default */ Optional<Integer> optionalInteger(String name) {
        return optionalLong(name).map(Math::toIntExact);
    }

    /* default */ long longValue(String name) {
        consumed.add(name);
        PkiOperationValue value = require(name);
        if (!(value instanceof PkiOperationValue.IntegerValue integer)) {
            throw type();
        }
        return integer.value();
    }

    /* default */ Optional<Long> optionalLong(String name) {
        if (!values.containsKey(name)) {
            return Optional.empty();
        }
        return Optional.of(longValue(name));
    }

    /* default */ boolean bool(String name) {
        consumed.add(name);
        PkiOperationValue value = require(name);
        if (!(value instanceof PkiOperationValue.BooleanValue bool)) {
            throw type();
        }
        return bool.value();
    }

    /* default */ ConfigurationFields object(String name) {
        consumed.add(name);
        return of(require(name));
    }

    /* default */ Optional<ConfigurationFields> optionalObject(String name) {
        if (!values.containsKey(name)) {
            return Optional.empty();
        }
        return Optional.of(object(name));
    }

    /* default */ List<PkiOperationValue> list(String name) {
        consumed.add(name);
        PkiOperationValue value = require(name);
        if (!(value instanceof PkiOperationValue.ListValue list)) {
            throw type();
        }
        return list.values();
    }

    /* default */ List<PkiOperationValue> optionalList(String name) {
        if (!values.containsKey(name)) {
            return List.of();
        }
        return list(name);
    }

    /* default */ Map<String, PkiOperationValue> remaining() {
        return values;
    }

    /* default */ void consumeAll() {
        consumed.addAll(values.keySet());
    }

    /* default */ void complete() {
        if (!consumed.equals(values.keySet())) {
            throw new IllegalArgumentException("Configuration fields were not consumed");
        }
    }

    private PkiOperationValue require(String name) {
        PkiOperationValue value = values.get(name);
        if (value == null) {
            throw new IllegalArgumentException("Required configuration field is missing");
        }
        return value;
    }

    /* default */ static String text(PkiOperationValue value) {
        if (!(value instanceof PkiOperationValue.Text text)) {
            throw type();
        }
        return text.value();
    }

    private static IllegalArgumentException type() {
        return new IllegalArgumentException("Configuration field type is invalid");
    }
}
