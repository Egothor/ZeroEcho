package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSigningOperation;

/**
 * Strict public lifecycle syntax and canonical approval-field coverage.
 */
class LifecycleProjectionTest {
    /**
     * Checks exact selected-head round-trip, optional absence and rejection of unknown fields, versions or root value types.
     */
    @Test void headRoundTripsAndRejectsUnknownFieldsInvalidVersionAndWrongTypes() {
        var head=new CaHeadSnapshot(1,new PkiId("ca;one"),Long.MAX_VALUE,new PkiId("issuer=one"),new PkiId("path;one"),"a".repeat(64));
        var encoded=LifecycleProjection.headValue(head);
        assertEquals(Optional.of(head),LifecycleProjection.head(Map.of("expectedHead",encoded)));
        assertTrue(LifecycleProjection.head(Map.of()).isEmpty());
        var changed=new java.util.TreeMap<>(encoded.fields());changed.put("actorId",new PkiOperationValue.Text("forged"));
        assertThrows(IllegalArgumentException.class,()->LifecycleProjection.head(Map.of("expectedHead",new PkiOperationValue.ObjectValue(changed))));
        changed.remove("actorId");changed.put("version",new PkiOperationValue.IntegerValue(2));
        assertThrows(IllegalArgumentException.class,()->LifecycleProjection.head(Map.of("expectedHead",new PkiOperationValue.ObjectValue(changed))));
        assertThrows(IllegalArgumentException.class,()->LifecycleProjection.head(Map.of("expectedHead",new PkiOperationValue.Text("{}"))));
    }
    /**
     * Checks canonical JSON bytes and sorted keys are independent of incoming outer/nested map order.
     */
    @Test void canonicalProjectionIgnoresIncomingMapOrderAtEveryNewObjectBoundary() {
        var head=new CaHeadSnapshot(1,new PkiId("ca"),7,new PkiId("issuer"),new PkiId("path"),"d".repeat(64));
        var headFields=LifecycleProjection.headValue(head).fields();
        var reverseHead=new java.util.LinkedHashMap<String,PkiOperationValue>();
        headFields.keySet().stream().sorted(java.util.Comparator.reverseOrder()).forEach(key->reverseHead.put(key,headFields.get(key)));
        var first=new java.util.LinkedHashMap<String,PkiOperationValue>();first.put("caId",new PkiOperationValue.Text("ca"));first.put("newKeyRef",new PkiOperationValue.Text("managed:primary"));first.put("expectedHead",new PkiOperationValue.ObjectValue(headFields));
        var second=new java.util.LinkedHashMap<String,PkiOperationValue>();second.put("expectedHead",new PkiOperationValue.ObjectValue(reverseHead));second.put("newKeyRef",first.get("newKeyRef"));second.put("caId",first.get("caId"));
        assertEquals(LifecycleProjection.head(first),LifecycleProjection.head(second));
        var operation=new AdministrativeOperation.Signing(new PkiSigningOperation.RotateCaKey(new PkiId("ca"),LifecycleProjection.selection(first),Optional.empty(),LifecycleProjection.head(first)));
        var canonical=LifecycleProjection.arguments(new PkiOperationValue.ObjectValue(first),operation);
        var reordered=LifecycleProjection.arguments(new PkiOperationValue.ObjectValue(second),operation);
        assertArrayEquals(zeroecho.pki.server.http.StrictJson.encode(canonical),zeroecho.pki.server.http.StrictJson.encode(reordered));
        assertEquals(canonical.fields().keySet().stream().sorted().toList(),canonical.fields().keySet().stream().toList());
        var nested=((PkiOperationValue.ObjectValue)canonical.fields().get("expectedHead")).fields();
        assertEquals(nested.keySet().stream().sorted().toList(),nested.keySet().stream().toList());
        assertEquals(Optional.of(head),LifecycleProjection.head(reordered.fields()));
    }

    /**
     * Checks alternative-key role and selected-head epoch are preserved in exact lifecycle coordinates and malformed selection types are rejected.
     */
    @Test void roleAndEpochChangesProduceDifferentCanonicalApprovalCoordinates() {
        var fields=Map.<String,PkiOperationValue>of("newAlternativeKeyRef",new PkiOperationValue.Text("managed:key;role=alt"),"alternativeSignatureAlgorithmId",new PkiOperationValue.Text("canonical;signature=alt"));
        var selection=LifecycleProjection.selection(fields);
        assertTrue(selection.primary().isEmpty());assertEquals(new KeyRef("managed:key;role=alt"),selection.alternative().orElseThrow().keyRef().orElseThrow());
        var head=new CaHeadSnapshot(1,new PkiId("ca"),1,new PkiId("issuer"),new PkiId("path"),"a".repeat(64));
        var operation=new PkiSigningOperation.RotateCaKey(new PkiId("ca"),selection,Optional.empty(),Optional.of(head));
        var encoded=LifecycleProjection.arguments(new PkiOperationValue.ObjectValue(Map.of()),new AdministrativeOperation.Signing(operation));
        assertEquals(Optional.of(head),LifecycleProjection.head(encoded.fields()));assertEquals(selection,LifecycleProjection.selection(encoded.fields()));
        assertThrows(IllegalArgumentException.class,()->LifecycleProjection.selection(Map.of("newKeyRef",new PkiOperationValue.BooleanValue(true))));
        assertThrows(IllegalArgumentException.class,()->LifecycleProjection.text(Map.of(),"missing"));
        var next=new CaHeadSnapshot(1,head.caId(),2,head.issuerId(),head.pathId(),head.bindingCommitment());
        assertFalse(java.util.Arrays.equals(zeroecho.pki.server.http.StrictJson.encode(encoded),zeroecho.pki.server.http.StrictJson.encode(LifecycleProjection.arguments(new PkiOperationValue.ObjectValue(Map.of()),new AdministrativeOperation.Signing(new PkiSigningOperation.RotateCaKey(operation.caId(),selection,Optional.empty(),Optional.of(next)))))));
    }
}
