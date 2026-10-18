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
package zeroecho.pki.api.profile;

/**
 * Occurrence and IP-family rule for one supported SAN type.
 *
 * @param type      SAN type
 * @param minimum   minimum occurrences
 * @param maximum   maximum occurrences
 * @param allowIpv4 whether IPv4 is allowed for
 *                  {@link SubjectAlternativeNameType#IP_ADDRESS}
 * @param allowIpv6 whether IPv6 is allowed for
 *                  {@link SubjectAlternativeNameType#IP_ADDRESS}
 */
public record SubjectAlternativeNameRule(SubjectAlternativeNameType type, int minimum, int maximum, boolean allowIpv4,
        boolean allowIpv6) {

    /**
     * Validates and constructs the rule.
     */
    public SubjectAlternativeNameRule {
        if (type == null || minimum < 0 || maximum < minimum
                || maximum > SubjectAlternativeNamePolicy.HARD_MAXIMUM_COUNT) {
            throw new IllegalArgumentException("Invalid SAN type rule");
        }
        if (type == SubjectAlternativeNameType.IP_ADDRESS) {
            if (maximum > 0 && !allowIpv4 && !allowIpv6) {
                throw new IllegalArgumentException("An IP SAN rule must allow at least one address family");
            }
        } else if (allowIpv4 || allowIpv6) {
            throw new IllegalArgumentException("IP family flags apply only to IP SAN rules");
        }
    }
}
