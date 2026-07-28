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
package zeroecho.sdk.content.builtin;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class SecretPasswordTest {
    @Test
    void redactsDiagnosticsAndOwnsPasswordCharacters() {
        System.out.print("SecretPassword/redaction...");
        char[] caller = "correct horse".toCharArray();
        char[] expected = caller.clone();
        SecretPassword password = new SecretPassword(caller);
        Arrays.fill(caller, 'x');

        assertEquals("[REDACTED]", password.toText());
        assertEquals("[REDACTED]", password.toString());
        assertArrayEquals(expected, password.chars());
        char[] copy = password.chars();
        copy[0] = 'x';
        assertArrayEquals(expected, password.chars());
        System.out.println("ok");
    }

    @Test
    void destroysOwnedCharactersAndRejectsSecretAccess() throws Exception {
        System.out.print("SecretPassword/destroy...");
        SecretPassword password = new SecretPassword("sensitive".toCharArray());
        assertFalse(password.isDestroyed());

        password.destroy();
        password.destroy();

        assertTrue(password.isDestroyed());
        assertThrows(IllegalStateException.class, password::chars);
        assertThrows(IllegalStateException.class, password::toBytes);
        assertThrows(IllegalStateException.class, password::getStream);
        Field field = SecretPassword.class.getDeclaredField("password");
        field.setAccessible(true);
        char[] owned = (char[]) field.get(password);
        assertTrue(Arrays.equals(new char[owned.length], owned));
        System.out.println("ok");
    }

    @Test
    void streamOwnsAndWipesItsUtf8BufferOnClose() throws Exception {
        System.out.print("SecretPassword/stream...");
        SecretPassword password = new SecretPassword("päss".toCharArray());
        InputStream stream = password.getStream();
        assertArrayEquals("päss".getBytes(StandardCharsets.UTF_8), stream.readAllBytes());

        Field field = stream.getClass().getDeclaredField("ownedBuffer");
        field.setAccessible(true);
        byte[] buffer = (byte[]) field.get(stream);
        stream.close();
        assertTrue(Arrays.equals(new byte[buffer.length], buffer));
        System.out.println("ok");
    }
}
