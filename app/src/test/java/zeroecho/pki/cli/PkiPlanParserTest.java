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
package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PkiPlanParserTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void rejectsEmptyDuplicateAndUnknownOperationPlans() throws IOException {
        System.out.println("rejectsEmptyDuplicateAndUnknownOperationPlans");
        PkiOperationRegistry registry = new PkiOperationRegistry();
        assertInvalid("empty.json", "{\"version\":1,\"failurePolicy\":\"FAIL_FAST\",\"operations\":[]}", registry);
        assertInvalid("duplicate.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"same","operation":"configuration.validate","arguments":{}},
                  {"id":"same","operation":"configuration.validate","arguments":{}}
                ]}
                """, registry);
        assertInvalid("unknown.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"unknown","operation":"system.exec","arguments":{}}
                ]}
                """, registry);
        System.out.println("...rejections=3");
        System.out.println("...ok");
    }

    @Test
    void rejectsUnknownFutureAndEmbeddedReferences() throws IOException {
        System.out.println("rejectsUnknownFutureAndEmbeddedReferences");
        PkiOperationRegistry registry = new PkiOperationRegistry();
        assertInvalid("unknown-reference.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"inspect","operation":"credential.inspect","arguments":{"credentialId":"${absent.id}"}}
                ]}
                """, registry);
        assertInvalid("future-reference.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"inspect","operation":"credential.inspect","arguments":{"credentialId":"${later.id}"}},
                  {"id":"later","operation":"configuration.validate","arguments":{}}
                ]}
                """, registry);
        assertInvalid("embedded-reference.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"config","operation":"configuration.validate","arguments":{}},
                  {"id":"inspect","operation":"credential.inspect","arguments":{"credentialId":"prefix-${config.storeProvider}"}}
                ]}
                """, registry);
        System.out.println("...rejections=3");
        System.out.println("...ok");
    }

    @Test
    void rejectsDuplicateJsonKeysAndTrailingDocuments() throws IOException {
        System.out.println("rejectsDuplicateJsonKeysAndTrailingDocuments");
        PkiOperationRegistry registry = new PkiOperationRegistry();
        assertInvalid("duplicate-key.json", """
                {"version":1,"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"config","operation":"configuration.validate","arguments":{}}
                ]}
                """, registry);
        assertInvalid("trailing.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"config","operation":"configuration.validate","arguments":{}}
                ]} {}
                """, registry);
        System.out.println("...rejections=2");
        System.out.println("...ok");
    }

    private void assertInvalid(String name, String content, PkiOperationRegistry registry) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        Files.writeString(path, content, StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> PkiPlanParser.read(path, registry.names()));
    }
}
