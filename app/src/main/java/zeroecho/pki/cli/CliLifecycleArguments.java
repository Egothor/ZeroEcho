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

/**
 * Strict lifecycle argument reader for the existing local CLI operation registry.
 */
final class CliLifecycleArguments {
    private CliLifecycleArguments() { }
    /**
     * Decodes an optional exact selected-head object without reading authoritative state.
     *
     * <p>The nested object must contain exactly version, caId, epoch, issuerId,
     * pathId and bindingCommitment. Unrelated top-level fields are left to the
     * operation registry. The returned fence is not proof that this head is current.</p>
     *
     * @param fields typed operation arguments, borrowed without modification
     * @return decoded head fence, or empty when expectedHead is absent
     * @throws NullPointerException if the argument map is null
     * @throws IllegalArgumentException if nested fields/types or head coordinates are invalid
     * @throws ArithmeticException if the version cannot be represented as an int
     */
    public static Optional<CaHeadSnapshot> head(Map<String,PkiOperationValue> fields) {
        if(!fields.containsKey("expectedHead"))return Optional.empty();
        var object=fields.get("expectedHead");
        if(!(object instanceof PkiOperationValue.ObjectValue value)||!value.fields().keySet().equals(Set.of("version","caId","epoch","issuerId","pathId","bindingCommitment")))throw new IllegalArgumentException("Invalid expectedHead fields");
        var f=value.fields();return Optional.of(new CaHeadSnapshot(Math.toIntExact(integer(f,"version")),new PkiId(text(f,"caId")),integer(f,"epoch"),new PkiId(text(f,"issuerId")),new PkiId(text(f,"pathId")),text(f,"bindingCommitment")));
    }
    /**
     * Decodes explicit primary/alternative key and signature-algorithm overrides.
     *
     * <p>Omitted members are resolved against retained roles by the domain later;
     * this helper neither chooses a current key nor validates provider authority.</p>
     *
     * @param fields typed operation arguments, borrowed without modification
     * @return version-one role selection with the supplied overrides
     * @throws NullPointerException if the argument map is null
     * @throws IllegalArgumentException if a supplied member is not text or a role selection is invalid
     */
    public static CaRotationSelection selection(Map<String,PkiOperationValue> fields) {
        return new CaRotationSelection(1,role(fields,"newKeyRef","primarySignatureAlgorithmId"),role(fields,"newAlternativeKeyRef","alternativeSignatureAlgorithmId"));
    }
    private static Optional<CaRotationSelection.RoleChange> role(Map<String,PkiOperationValue> f,String key,String algorithm) {
        if(!f.containsKey(key)&&!f.containsKey(algorithm))return Optional.empty();
        return Optional.of(new CaRotationSelection.RoleChange(optional(f,key).map(KeyRef::new),optional(f,algorithm)));
    }
    /**
     * Reads a required text field without trimming or normalizing its content.
     *
     * @param fields typed argument object, borrowed without modification
     * @param name field key to read
     * @return exact text retained in the typed value
     * @throws NullPointerException if the map is null, or its implementation rejects a null key
     * @throws IllegalArgumentException if the field is absent or is not text
     */
    public static String text(Map<String,PkiOperationValue> fields,String name) {if(fields.get(name) instanceof PkiOperationValue.Text text)return text.value();throw new IllegalArgumentException("Invalid lifecycle text: "+name);}
    private static Optional<String> optional(Map<String,PkiOperationValue> f,String name){return f.containsKey(name)?Optional.of(text(f,name)):Optional.empty();}
    private static long integer(Map<String,PkiOperationValue> f,String name){if(f.get(name) instanceof PkiOperationValue.IntegerValue value)return value.value();throw new IllegalArgumentException("Invalid lifecycle integer");}
    private static PkiOperationValue.Text value(String text){return new PkiOperationValue.Text(text);}
}
