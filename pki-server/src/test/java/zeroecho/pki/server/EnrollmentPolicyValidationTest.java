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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;
import zeroecho.pki.server.enrollment.EnrollmentSubjectPattern;

/** Bounded subject grammar and canonical enrollment policy validation. */
class EnrollmentPolicyValidationTest {
    @Test
    void matchesLiteralAndWildcardSegmentsWithoutBacktracking() {
        assertTrue(EnrollmentSubjectPattern.compile("^CN=.*example.*,O=Egothor$").matches("CN=device.example.test,O=Egothor"));
        assertFalse(EnrollmentSubjectPattern.compile("CN=.*example.*,O=Egothor").matches("CN=device.example.test,O=Other"));
        assertTrue(EnrollmentSubjectPattern.compile(".*").matches(""));
        assertTrue(EnrollmentSubjectPattern.compile("CN=device").matches("CN=device"));
        assertFalse(EnrollmentSubjectPattern.compile("CN=device").matches("prefix,CN=device"));
        assertFalse(EnrollmentSubjectPattern.compile("aa.*aa").matches("aaa"));
        assertTrue(EnrollmentSubjectPattern.compile(".*ab.*ab.*").matches("xababx"));
        assertTrue(EnrollmentSubjectPattern.compile("CN=device\\.example\\$").matches("CN=device.example$"));
        assertFalse(EnrollmentSubjectPattern.compile(".*" + "a".repeat(250) + "b.*").matches("a".repeat(4096)));
    }

    @Test
    void rejectsUnboundedOrUnsupportedRegexGrammar() {
        for (String pattern : List.of("", "(a+)+", "CN=[a-z]*", "CN=.+", "CN=foo|bar",
                "CN=\\1", "CN=foo\\", "CN={1,3}", "CN=foo$", "x".repeat(513))) {
            if (pattern.equals("CN=foo$")) {
                assertTrue(EnrollmentSubjectPattern.compile(pattern).matches("CN=foo"));
            } else {
                assertThrows(IllegalArgumentException.class, () -> EnrollmentSubjectPattern.compile(pattern), pattern);
            }
        }
        assertThrows(IllegalArgumentException.class, () -> EnrollmentSubjectPattern.compile(".*").matches("x".repeat(4097)));
    }

    @Test
    void normalizesDnsSuffixOrderAndCaseForStablePolicyCommitment() {
        EnrollmentProfile first = profile("certificate", Set.of("authority-b", "authority-a"),
                Optional.of("CN=.*"), List.of("Example.TEST.", "a.example.test"));
        EnrollmentProfile second = profile("certificate", Set.of("authority-a", "authority-b"),
                Optional.of("CN=.*"), List.of("a.example.test", "example.test"));
        assertEquals(first, second);
        assertEquals(List.of("a.example.test", "example.test"), first.requiredSanDomains());
        assertEquals(EnrollmentProfileService.commitment(first), EnrollmentProfileService.commitment(second));
    }

    @Test
    void rejectsInvalidIdsPatternsAndDomainSuffixesAtConstruction() {
        for (String id : List.of("", " ", "with space", "x".repeat(257))) {
            assertThrows(IllegalArgumentException.class, () -> profile(id, Set.of(), Optional.empty(), List.of()));
            assertThrows(IllegalArgumentException.class, () -> profile("certificate", Set.of(id), Optional.empty(), List.of()));
        }
        for (String domain : List.of("", ".", "example..test", "-bad.test", "bad-.test", "*.test", "é.test", "K.test", "a".repeat(64) + ".test")) {
            assertThrows(IllegalArgumentException.class, () -> profile("certificate", Set.of(), Optional.empty(), List.of(domain)));
        }
        assertThrows(IllegalArgumentException.class, () -> profile("certificate", Set.of(), Optional.empty(), List.of("EXAMPLE.TEST", "example.test.")));
        assertThrows(IllegalArgumentException.class, () -> profile("certificate", Set.of(), Optional.of("(a+)+"), List.of()));
    }

    private static EnrollmentProfile profile(String certificate, Set<String> authorities, Optional<String> pattern, List<String> domains) {
        return new EnrollmentProfile("policy", "Policy", EnrollmentProfileState.ACTIVE, certificate, authorities, pattern, domains, false);
    }
}
