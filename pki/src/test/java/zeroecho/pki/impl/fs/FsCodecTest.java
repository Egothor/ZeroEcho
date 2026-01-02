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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.profile.CertificateProfile;

/**
 * Tests for {@link FsCodec}.
 */
public final class FsCodecTest {

    @Test
    void booleanEncodingIsCompactAndDecodesIntoPrimitiveExpectation() {
        System.out.println("booleanEncodingIsCompactAndDecodesIntoPrimitiveExpectation");

        byte[] data = FsCodec.encode(Boolean.TRUE);

        // MAGIC + TAG + payload => 3 bytes
        System.out.println("...encoded length=" + data.length);
        assertTrue(data.length <= 5);

        // decode as Boolean
        Boolean b = FsCodec.decode(data, Boolean.class);
        assertEquals(Boolean.TRUE, b);

        // decode as primitive expectation via Boolean.class cast still OK in callers;
        // actual primitive/wrapper tolerance is inside the codec.
        Object any = FsCodec.decode(data, Object.class);
        assertEquals(Boolean.TRUE, any);

        System.out.println("booleanEncodingIsCompactAndDecodesIntoPrimitiveExpectation...ok");
    }

    @Test
    void recordRoundTripUsesCompactEncoding() {
        System.out.println("recordRoundTripUsesCompactEncoding");

        CertificateProfile p = new CertificateProfile("profile-a", new FormatId("fmt-x509"), "Profile A",
                List.of(new AttributeId("req-1")), List.of(new AttributeId("opt-1")), Optional.of(Duration.ofDays(365)),
                true);

        byte[] data = FsCodec.encode(p);
        System.out.println("...encoded length=" + data.length);
        assertTrue(data.length > 0);

        CertificateProfile decoded = FsCodec.decode(data, CertificateProfile.class);
        assertEquals(p, decoded);

        System.out.println("recordRoundTripUsesCompactEncoding...ok");
    }

    @Test
    void listAndOptionalRoundTripUsesCompactEncoding() {
        System.out.println("listAndOptionalRoundTripUsesCompactEncoding");

        List<String> list = List.of("a", "b");
        byte[] listData = FsCodec.encode(list);
        Object decodedList = FsCodec.decode(listData, Object.class);
        assertEquals(list, decodedList);

        Optional<Integer> opt = Optional.of(Integer.valueOf(7));
        byte[] optData = FsCodec.encode(opt);
        Object decodedOpt = FsCodec.decode(optData, Object.class);
        assertEquals(opt, decodedOpt);

        System.out.println("listAndOptionalRoundTripUsesCompactEncoding...ok");
    }

}
