/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.annotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Declares a human-friendly display name for a class, specification, or
 * capability.
 *
 * <p>
 * The {@code DisplayName} annotation is intended for use in contexts where a
 * concise, stable label is required for presentation or diagnostic purposes.
 * Frameworks such as catalogs, serializers, or logging utilities may check for
 * this annotation and use its value instead of relying on
 * {@link Class#getSimpleName()}.
 * </p>
 *
 * <h2>Design considerations</h2>
 * <ul>
 * <li>Display names are not identifiers and must not be used for protocol
 * negotiation or security-critical decisions.</li>
 * <li>The value should be concise, human-readable, and stable across versions
 * where compatibility matters.</li>
 * <li>When absent, consumers typically fall back to {@code Describable} or
 * class names.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * &#64;DisplayName("AES-GCM 256-bit")
 * public final class AesSpec implements AlgorithmKeySpec {
 *     ...
 * }
 * }</pre>
 *
 * @since 1.0
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface DisplayName {
    /**
     * Returns the human-friendly display name.
     *
     * @return a descriptive string, never {@code null}
     */
    String value();
}
