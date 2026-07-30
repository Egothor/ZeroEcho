/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.request;

import java.nio.charset.StandardCharsets;

import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;

/**
 * One ordered, single-valued, typed subject distinguished-name component.
 *
 * @param type  supported RDN type
 * @param value exact value, with country names canonicalized to uppercase
 */
public record SubjectRdn(SubjectRdnType type, String value) {

    /**
     * Validates and constructs the component.
     */
    public SubjectRdn {
        if (type == null) {
            throw new IllegalArgumentException("Subject RDN type must not be null");
        }
        value = SubjectRdnRule.canonicalValue(type, value);
        if (value.getBytes(StandardCharsets.UTF_8).length > SubjectRdnRule.HARD_MAXIMUM_UTF8_BYTES) {
            throw new IllegalArgumentException("Subject RDN value exceeds the hard limit");
        }
    }
}
