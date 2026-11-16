package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import org.junit.jupiter.api.Test;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Local CLI parsing preserves distinct role overrides and strictly rejects forged head fields.
 */
class CliLifecycleArgumentsTest {
    /**
     * Checks lifecycle role overrides and rejects malformed command inputs.
     */
    @Test void parsesRoleOverridesAndRejectsInvalidInputs() {
        var parsed=CliLifecycleArguments.selection(Map.of("newAlternativeKeyRef",new PkiOperationValue.Text("managed:alt")));
        assertTrue(parsed.primary().isEmpty());assertEquals("managed:alt",parsed.alternative().orElseThrow().keyRef().orElseThrow().value());
        assertTrue(CliLifecycleArguments.head(Map.of()).isEmpty());
        assertThrows(IllegalArgumentException.class,()->CliLifecycleArguments.selection(Map.of("newKeyRef",new PkiOperationValue.IntegerValue(1))));
        assertThrows(IllegalArgumentException.class,()->CliLifecycleArguments.head(Map.of("expectedHead",new PkiOperationValue.ObjectValue(Map.of("actorId",new PkiOperationValue.Text("forged"))))));
        assertThrows(IllegalArgumentException.class,()->CliLifecycleArguments.text(Map.of(),"missing"));
    }
}
