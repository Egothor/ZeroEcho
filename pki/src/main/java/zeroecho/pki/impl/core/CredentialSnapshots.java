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
package zeroecho.pki.impl.core;

import java.util.ArrayList;
import java.util.List;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/**
 * Internal defensive snapshot boundary for framework-produced credentials.
 */
final class CredentialSnapshots {

    private CredentialSnapshots() {
    }

    /* default */ static CredentialBundle copy(CredentialBundle source) {
        Credential credential = copy(source.credential());
        List<EncodedObject> supporting = source.supportingObjects().stream().map(CredentialSnapshots::copy).toList();
        return new CredentialBundle(credential, supporting);
    }

    /* default */ static Credential copy(Credential source) {
        return new Credential(source.credentialId(), source.formatId(), source.issuerRef(), source.subjectRef(),
                source.validity(), source.serialOrUniqueId(), source.publicKeyId(), source.profileId(), source.status(),
                copy(source.encoded()), copy(source.attributes()));
    }

    private static EncodedObject copy(EncodedObject source) {
        return new EncodedObject(source.encoding(), source.bytes().clone());
    }

    private static AttributeSet copy(AttributeSet source) {
        List<SimpleAttributeSet.Entry> entries = new ArrayList<>();
        for (AttributeId id : source.ids()) {
            List<AttributeValue> values = source.getAll(id).stream().map(CredentialSnapshots::copy).toList();
            entries.add(new SimpleAttributeSet.Entry(id, values));
        }
        return new SimpleAttributeSet(entries);
    }

    private static AttributeValue copy(AttributeValue source) {
        if (source instanceof AttributeValue.BytesValue bytesValue) {
            return new AttributeValue.BytesValue(bytesValue.value().clone());
        }
        return source;
    }
}
