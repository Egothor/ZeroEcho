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

package zeroecho.pki.api.ca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.content.DurableContentReference;

final class CaCommandTest {
    private static final String SENTINEL = "privileged-sentinel";
    private static final FormatId FORMAT = new FormatId(SENTINEL);
    private static final SubjectRef SUBJECT = new SubjectRef(SENTINEL);
    private static final PkiId CA = new PkiId(SENTINEL);
    private static final KeyRef KEY = new KeyRef(SENTINEL);
    // A historical ID remains structurally valid without consulting a clock or store.
    private static final PkiId PROOF = new PkiId("zsign:v1:" + SENTINEL + ":0:" + "ab".repeat(16));
    private static final AttributeSet ATTRIBUTES = untouched(AttributeSet.class);
    private static final DurableContentReference CREDENTIAL = untouched(DurableContentReference.class);

    @Test void allConcreteCommandsPreserveInputsAndRedactDiagnosticsWithoutReadingDependencies() {
        List<Record> commands = commands();
        assertEquals(8, commands.size());
        for (Record command : commands) {
            assertTrue(command.toString().endsWith("[redacted]"));
            assertFalse(command.toString().contains(SENTINEL));
            assertFalse(command.toString().contains(PROOF.value()));
        }
        CaCreateCommand root = (CaCreateCommand) commands.get(0);
        assertSame(KEY, root.keyRef());
        assertSame(ATTRIBUTES, root.attributes());
        CaImportCommand imported = (CaImportCommand) commands.get(1);
        assertSame(CA, imported.targetAuthorityId());
        assertSame(KEY, imported.keyRef());
        assertSame(PROOF, imported.proofId());
        assertSame(CREDENTIAL, imported.existingCaCredential());
        assertEquals(Optional.empty(), ((IntermediateCertIssueCommand) commands.get(3)).requestedValidity());
        assertEquals(Optional.empty(), ((CaRolloverCommand.Root) commands.get(4)).requestedValidity());
        assertEquals(Optional.empty(), ((CaRolloverCommand.Intermediate) commands.get(5)).requestedValidity());
        assertSame(KEY, ((CaKeyRotationCommand.Root) commands.get(6)).newKeyRef());
        assertSame(KEY, ((CaKeyRotationCommand.Intermediate) commands.get(7)).newKeyRef());
    }

    @Test void everyNullComponentIncludingOptionalContainersIsRejected() throws Exception {
        for (Record command : commands()) {
            for (RecordComponent component : command.getClass().getRecordComponents()) {
                invalid(command, component.getName(), null);
            }
        }
    }

    @Test void strictUtf8LimitsAreInclusiveForEveryApplicableComponent() throws Exception {
        String maximumId = "\u00e9".repeat(2048);
        String maximumProfile = "\u20ac".repeat(85) + "x";
        String maximumKey = "\ud83d\ude00".repeat(262_144);
        for (Record command : commands()) {
            for (RecordComponent component : command.getClass().getRecordComponents()) {
                String name = component.getName();
                if (component.getType() == PkiId.class && !name.equals("proofId")) {
                    replace(command, name, new PkiId(maximumId));
                    invalid(command, name, new PkiId(maximumId + "x"));
                    for (String malformed : malformedUtf16()) { invalid(command, name, new PkiId(malformed)); }
                } else if (component.getType() == KeyRef.class) {
                    replace(command, name, new KeyRef(maximumKey));
                    invalid(command, name, new KeyRef(maximumKey + "x"));
                    for (String malformed : malformedUtf16()) { invalid(command, name, new KeyRef(malformed)); }
                } else if (name.equals("profileId")) {
                    replace(command, name, maximumProfile);
                    invalid(command, name, maximumProfile + "x");
                    for (String malformed : malformedUtf16()) { invalid(command, name, malformed); }
                    for (String blank : List.of("", " ", "\t\n")) { invalid(command, name, blank); }
                }
            }
        }
        // Identifiers and key records already reject blank values at their own boundary.
        assertThrows(IllegalArgumentException.class, () -> new PkiId(" "));
        assertThrows(IllegalArgumentException.class, () -> new KeyRef(" "));
    }

    @Test void proofIdsAreBoundedBeforeParsingAndMalformedIdsHaveSafeDiagnostics() throws Exception {
        for (Record command : commands()) {
            if (!componentNames(command.getClass()).contains("proofId")) { continue; }
            for (String invalid : List.of(SENTINEL, "zsign:v2:provider:0:" + "00".repeat(16),
                    "zsign:v1:provider:not-a-time:" + "00".repeat(16),
                    "zsign:v1:provider:0:" + "zz".repeat(16),
                    "zsign:v1:provider:0:00", "x".repeat(4097), "x\ud800", "x\udc00")) {
                IllegalArgumentException failure = invalid(command, "proofId", new PkiId(invalid));
                assertEquals("CA command component is invalid", failure.getMessage());
                assertNull(failure.getCause());
            }
        }
    }

    @Test void rootsAndIntermediatesHaveClosedDistinctMandatoryShapes() throws Exception {
        assertTrue(CaRolloverCommand.class.isSealed());
        assertTrue(CaKeyRotationCommand.class.isSealed());
        assertEquals(Set.of(CaRolloverCommand.Root.class, CaRolloverCommand.Intermediate.class),
                Set.of(CaRolloverCommand.class.getPermittedSubclasses()));
        assertEquals(Set.of(CaKeyRotationCommand.Root.class, CaKeyRotationCommand.Intermediate.class),
                Set.of(CaKeyRotationCommand.class.getPermittedSubclasses()));
        for (Class<?> root : List.of(CaCreateCommand.class, CaRolloverCommand.Root.class, CaKeyRotationCommand.Root.class)) {
            assertFalse(componentNames(root).contains("proofId"));
            assertFalse(componentNames(root).contains("issuerCaId"));
        }
        for (Class<?> intermediate : List.of(IntermediateCreateCommand.class, IntermediateCertIssueCommand.class,
                CaRolloverCommand.Intermediate.class, CaKeyRotationCommand.Intermediate.class)) {
            assertFalse(componentNames(intermediate).contains("proofId"));
            assertEquals(PkiId.class, intermediate.getMethod("issuerCaId").getReturnType());
        }
        assertEquals(KeyRef.class, CaCreateCommand.class.getMethod("keyRef").getReturnType());
        assertEquals(KeyRef.class, IntermediateCreateCommand.class.getMethod("keyRef").getReturnType());
        assertEquals(KeyRef.class, IntermediateCertIssueCommand.class.getMethod("keyRef").getReturnType());
        assertFalse(componentNames(CaRolloverCommand.Intermediate.class).contains("profileId"));
        assertFalse(componentNames(CaKeyRotationCommand.Intermediate.class).contains("profileId"));
    }

    @Test void formatAndSubjectRetainTheirExistingInvariantsWithoutNewBounds() {
        FormatId format = new FormatId("x".repeat(4097));
        SubjectRef subject = new SubjectRef("x".repeat(4097));
        CaCreateCommand command = new CaCreateCommand(format, subject, "profile", KEY, ATTRIBUTES);
        assertSame(format, command.formatId());
        assertSame(subject, command.subjectRef());
    }

    private static List<Record> commands() {
        return List.of(new CaCreateCommand(FORMAT, SUBJECT, SENTINEL, KEY, ATTRIBUTES),
                new CaImportCommand(CA, FORMAT, SUBJECT, SENTINEL, KEY, PROOF, CREDENTIAL, ATTRIBUTES),
                new IntermediateCreateCommand(FORMAT, CA, SUBJECT, SENTINEL, KEY, ATTRIBUTES),
                new IntermediateCertIssueCommand(FORMAT, CA, CA, SENTINEL, KEY, Optional.empty(), ATTRIBUTES),
                new CaRolloverCommand.Root(CA, Optional.empty(), ATTRIBUTES),
                new CaRolloverCommand.Intermediate(CA, CA, KEY, Optional.empty(), ATTRIBUTES),
                new CaKeyRotationCommand.Root(CA, KEY, ATTRIBUTES),
                new CaKeyRotationCommand.Intermediate(CA, KEY, CA, ATTRIBUTES));
    }

    private static List<String> malformedUtf16() { return List.of("x\ud800", "x\udc00", "\ud800x"); }

    private static List<String> componentNames(Class<?> type) {
        return Arrays.stream(type.getRecordComponents()).map(RecordComponent::getName).toList();
    }

    private static Object replace(Record command, String name, Object replacement) throws ReflectiveOperationException {
        RecordComponent[] components = command.getClass().getRecordComponents();
        Object[] arguments = new Object[components.length];
        Class<?>[] types = new Class<?>[components.length];
        for (int index = 0; index < components.length; index++) {
            RecordComponent component = components[index];
            arguments[index] = component.getName().equals(name) ? replacement : component.getAccessor().invoke(command);
            types[index] = component.getType();
        }
        Constructor<?> constructor = command.getClass().getConstructor(types);
        return constructor.newInstance(arguments);
    }

    private static IllegalArgumentException invalid(Record command, String name, Object replacement) {
        InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                () -> replace(command, name, replacement));
        return assertInstanceOf(IllegalArgumentException.class, failure.getCause());
    }

    private static <T> T untouched(Class<T> type) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                (proxy, method, args) -> { throw new AssertionError("Command must not inspect supplied dependencies"); }));
    }
}
