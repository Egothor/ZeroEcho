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
package zeroecho.pki.server.http;

/**
 * Strict single decoding for finite ASCII public/admin object identifiers.
 */
/* default */ final class HttpPathIdentifier {
    private static final char PERCENT_ESCAPE = '%';

    private HttpPathIdentifier() { }
    /**
     * Decodes exactly one bounded ASCII object identifier without permitting separators or double encoding.
     *
     * @param raw raw route segment of at most 768 characters
     * @return decoded identifier of at most 256 safe ASCII characters
     * @throws IllegalArgumentException if the input is null, empty, oversized or contains
     *         malformed escapes, separators, traversal syntax or unsupported characters
     */
    /* default */ static String decode(String raw) {
        if(raw==null||raw.isEmpty()||raw.length()>768){ throw new IllegalArgumentException("Invalid object identifier"); }
        StringBuilder decoded=new StringBuilder(raw.length());
        int index = 0;
        while(index<raw.length()) {
            char value=raw.charAt(index);
            if(value==PERCENT_ESCAPE) {
                if(index+2>=raw.length()){ throw new IllegalArgumentException("Invalid object identifier"); }
                int high=Character.digit(raw.charAt(index+1),16);
                int low=Character.digit(raw.charAt(index+2),16);
                if(high<0||low<0){ throw new IllegalArgumentException("Invalid object identifier"); }
                value=(char)((high<<4)|low);index+=2;
            }
            decoded.append(value);
            index++;
        }
        String result=decoded.toString();
        if(!result.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")){ throw new IllegalArgumentException("Invalid object identifier"); }
        return result;
    }
}
