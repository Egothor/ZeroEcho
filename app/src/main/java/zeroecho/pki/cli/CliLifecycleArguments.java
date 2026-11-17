/*
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

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.api.ca.CaRotationSelection;
import zeroecho.pki.application.PkiOperationValue;

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
        if(!fields.containsKey("expectedHead")){ return Optional.empty(); }
        PkiOperationValue object=fields.get("expectedHead");
        if(!(object instanceof PkiOperationValue.ObjectValue value)||!value.fields().keySet().equals(Set.of("version","caId","epoch","issuerId","pathId","bindingCommitment"))){ throw new IllegalArgumentException("Invalid expectedHead fields"); }
        Map<String,PkiOperationValue> f=value.fields();return Optional.of(new CaHeadSnapshot(Math.toIntExact(integer(f,"version")),new PkiId(text(f,"caId")),integer(f,"epoch"),new PkiId(text(f,"issuerId")),new PkiId(text(f,"pathId")),text(f,"bindingCommitment")));
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
        if(!f.containsKey(key)&&!f.containsKey(algorithm)){ return Optional.empty(); }
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
    public static String text(Map<String,PkiOperationValue> fields,String name) {if(fields.get(name) instanceof PkiOperationValue.Text text){ return text.value(); }throw new IllegalArgumentException("Invalid lifecycle text: "+name);}
    private static Optional<String> optional(Map<String,PkiOperationValue> f,String name){return f.containsKey(name)?Optional.of(text(f,name)):Optional.empty();}
    private static long integer(Map<String,PkiOperationValue> f,String name){if(f.get(name) instanceof PkiOperationValue.IntegerValue value){ return value.value(); }throw new IllegalArgumentException("Invalid lifecycle integer");}
}
