package zeroecho.pki.server;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.api.ca.CaRotationSelection;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSigningOperation;

/**
 * Canonical public lifecycle coordinates shared by retained envelopes and approval commitments.
 */
public final class LifecycleProjection {
    private LifecycleProjection() { }
    /**
     * Decodes an optional exact selected-head object without checking current authoritative state.
     *
     * @param fields typed arguments, borrowed without modification
     * @return decoded fence, or empty when expectedHead is absent
     * @throws NullPointerException if the map is null
     * @throws IllegalArgumentException if the head object has unknown/missing fields, wrong types or invalid
     *     coordinates
     * @throws ArithmeticException if the version is not representable as an int
     */
    public static Optional<CaHeadSnapshot> head(Map<String,PkiOperationValue> fields) {
        if(!fields.containsKey("expectedHead"))return Optional.empty();
        var object=fields.get("expectedHead");
        if(!(object instanceof PkiOperationValue.ObjectValue value)||!value.fields().keySet().equals(Set.of("version","caId","epoch","issuerId","pathId","bindingCommitment")))throw new IllegalArgumentException("Invalid expectedHead fields");
        var f=value.fields();return Optional.of(new CaHeadSnapshot(Math.toIntExact(integer(f,"version")),new PkiId(text(f,"caId")),integer(f,"epoch"),new PkiId(text(f,"issuerId")),new PkiId(text(f,"pathId")),text(f,"bindingCommitment")));
    }
    /**
     * Decodes explicit outgoing-role overrides without resolving retained keys or authorizing signing.
     *
     * @param fields typed arguments, borrowed without modification
     * @return version-one role changes; omitted members remain for domain resolution
     * @throws NullPointerException if the map is null
     * @throws IllegalArgumentException if supplied text or role selection constraints fail
     */
    public static CaRotationSelection selection(Map<String,PkiOperationValue> fields) {
        return new CaRotationSelection(1,role(fields,"newKeyRef","primarySignatureAlgorithmId"),role(fields,"newAlternativeKeyRef","alternativeSignatureAlgorithmId"));
    }
    private static Optional<CaRotationSelection.RoleChange> role(Map<String,PkiOperationValue> f,String key,String algorithm) {
        if(!f.containsKey(key)&&!f.containsKey(algorithm))return Optional.empty();
        return Optional.of(new CaRotationSelection.RoleChange(optional(f,key).map(KeyRef::new),optional(f,algorithm)));
    }
    /**
     * Projects all six exact selected-head coordinates into a sorted immutable typed object.
     *
     * @param head immutable fence to project
     * @return new structural representation, without reading or replacing the current head
     * @throws NullPointerException if the head is null
     */
    public static PkiOperationValue.ObjectValue headValue(CaHeadSnapshot head) {
        return new PkiOperationValue.ObjectValue(new java.util.TreeMap<>(Map.of("version",new PkiOperationValue.IntegerValue(head.version()),"caId",value(head.caId().value()),"epoch",new PkiOperationValue.IntegerValue(head.epoch()),"issuerId",value(head.issuerId().value()),"pathId",value(head.pathId().value()),"bindingCommitment",value(head.bindingCommitment()))));
    }
    /**
     * Copies argument fields and overlays lifecycle coordinates from the supplied normalized target.
     *
     * @param original existing immutable arguments
     * @param operation already normalized typed operation; normalization is not performed here
     * @return new sorted immutable arguments; unrelated original fields are retained
     * @throws NullPointerException if original is null
     */
    public static PkiOperationValue.ObjectValue arguments(PkiOperationValue.ObjectValue original,AdministrativeOperation operation) {
        var f=new LinkedHashMap<>(original.fields());
        if(operation instanceof AdministrativeOperation.Signing signing) {
            var op=signing.operation();
            if(op instanceof PkiSigningOperation.RotateCaKey rotate) {
                putRole(f,rotate.selection().primary(),"newKeyRef","primarySignatureAlgorithmId");putRole(f,rotate.selection().alternative(),"newAlternativeKeyRef","alternativeSignatureAlgorithmId");rotate.expectedHead().ifPresent(h->f.put("expectedHead",headValue(h)));
            } else if(op instanceof PkiSigningOperation.RolloverCaCertificate rollover)rollover.expectedHead().ifPresent(h->f.put("expectedHead",headValue(h)));
            else if(op instanceof PkiSigningOperation.IssueIntermediateCertificate issue)issue.expectedHead().ifPresent(h->f.put("expectedHead",headValue(h)));
        } else if(operation instanceof AdministrativeOperation.Pki pki&&pki.operation() instanceof PkiOperation.SelectIssuancePath selected) {
            selected.expectedHead().ifPresent(h->f.put("expectedHead",headValue(h)));selected.transitionCommitment().ifPresent(c->f.put("transitionCommitment",value(c)));f.put("distributionAcknowledged",new PkiOperationValue.BooleanValue(selected.distributionAcknowledged()));
        }
        return new PkiOperationValue.ObjectValue(new java.util.TreeMap<>(f));
    }
    private static void putRole(Map<String,PkiOperationValue> f,Optional<CaRotationSelection.RoleChange> role,String key,String algorithm) {
        role.ifPresent(r->{r.keyRef().ifPresent(k->f.put(key,value(k.value())));r.signatureAlgorithmId().ifPresent(a->f.put(algorithm,value(a)));});
    }
    /**
     * Reads required typed text without trimming or normalizing it.
     *
     * @param fields typed argument map
     * @param name field key
     * @return exact supplied text
     * @throws NullPointerException if the map is null or rejects a null key
     * @throws IllegalArgumentException if the field is absent or not text
     */
    public static String text(Map<String,PkiOperationValue> fields,String name) {if(fields.get(name) instanceof PkiOperationValue.Text text)return text.value();throw new IllegalArgumentException("Invalid lifecycle text: "+name);}
    private static Optional<String> optional(Map<String,PkiOperationValue> f,String name){return f.containsKey(name)?Optional.of(text(f,name)):Optional.empty();}
    private static long integer(Map<String,PkiOperationValue> f,String name){if(f.get(name) instanceof PkiOperationValue.IntegerValue value)return value.value();throw new IllegalArgumentException("Invalid lifecycle integer");}
    private static PkiOperationValue.Text value(String text){return new PkiOperationValue.Text(text);}
}
