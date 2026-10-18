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
package zeroecho.core.spec;

/**
 * Trusted-code canonical codec for one typed algorithm-parameter schema.
 *
 * <p>
 * Encoding takes an immediate immutable snapshot. Decoding must return fresh
 * values or intrinsically immutable values and must reject malformed,
 * incomplete, or contradictory input. Codec identifiers are stable semantic
 * identity and cannot be redefined by catalog ordering or configuration.
 * </p>
 */
public interface AlgorithmIdentityCodec {

    /**
     * Returns the stable namespaced codec identifier.
     *
     * @return canonical codec identifier
     */
    String id();

    /**
     * Encodes complete typed parameters.
     *
     * @param parameters typed parameters
     * @return independently owned canonical bytes
     */
    byte[] encode(AlgorithmIdentity.Parameters parameters);

    /**
     * Decodes complete canonical bytes.
     *
     * @param encoded canonical bytes
     * @return fresh validated typed parameters
     */
    AlgorithmIdentity.Parameters decode(byte[] encoded);
}
