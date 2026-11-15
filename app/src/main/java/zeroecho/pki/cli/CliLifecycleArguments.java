package zeroecho.pki.cli;

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

/** Strict lifecycle argument reader for the existing local CLI operation registry. */
final class CliLifecycleArguments {
    private CliLifecycleArguments() { }
    /** @param fields exact wire arguments @return optional strictly typed selected-head fence */
    public static Optional<CaHeadSnapshot> head(Map<String,PkiOperationValue> fields) {
        if(!fields.containsKey("expectedHead"))return Optional.empty();
        var object=fields.get("expectedHead");
        if(!(object instanceof PkiOperationValue.ObjectValue value)||!value.fields().keySet().equals(Set.of("version","caId","epoch","issuerId","pathId","bindingCommitment")))throw new IllegalArgumentException("Invalid expectedHead fields");
        var f=value.fields();return Optional.of(new CaHeadSnapshot(Math.toIntExact(integer(f,"version")),new PkiId(text(f,"caId")),integer(f,"epoch"),new PkiId(text(f,"issuerId")),new PkiId(text(f,"pathId")),text(f,"bindingCommitment")));
    }
    /** @param fields exact wire arguments @return explicit role overrides, with omitted members retained by domain */
    public static CaRotationSelection selection(Map<String,PkiOperationValue> fields) {
        return new CaRotationSelection(1,role(fields,"newKeyRef","primarySignatureAlgorithmId"),role(fields,"newAlternativeKeyRef","alternativeSignatureAlgorithmId"));
    }
    private static Optional<CaRotationSelection.RoleChange> role(Map<String,PkiOperationValue> f,String key,String algorithm) {
        if(!f.containsKey(key)&&!f.containsKey(algorithm))return Optional.empty();
        return Optional.of(new CaRotationSelection.RoleChange(optional(f,key).map(KeyRef::new),optional(f,algorithm)));
    }
    /** @param fields typed object @param name required text name @return exact text */
    public static String text(Map<String,PkiOperationValue> fields,String name) {if(fields.get(name) instanceof PkiOperationValue.Text text)return text.value();throw new IllegalArgumentException("Invalid lifecycle text: "+name);}
    private static Optional<String> optional(Map<String,PkiOperationValue> f,String name){return f.containsKey(name)?Optional.of(text(f,name)):Optional.empty();}
    private static long integer(Map<String,PkiOperationValue> f,String name){if(f.get(name) instanceof PkiOperationValue.IntegerValue value)return value.value();throw new IllegalArgumentException("Invalid lifecycle integer");}
    private static PkiOperationValue.Text value(String text){return new PkiOperationValue.Text(text);}
}
