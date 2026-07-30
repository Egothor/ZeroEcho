/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk.guard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.Util;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;

class SessionRecipientOpenerContractTest {

    @Test
    void publicApiExposesOnlyReusableSessionOpeners() {
        System.out.println("publicApiExposesOnlyReusableSessionOpeners");
        assertSessionOnlyConstructor(KemCtxOpener.class);
        assertSessionOnlyConstructor(EncCtxOpener.class);

        List<Method> addOpenerMethods = Arrays.stream(MultiRecipientDataSourceBuilder.class.getMethods())
                .filter(method -> method.getName().equals("addOpener")).toList();
        assertEquals(1, addOpenerMethods.size());
        assertEquals(RecipientOpener.class, addOpenerMethods.get(0).getParameterTypes()[0]);

        System.out.println("...addOpenerOverloads=1");
        System.out.println("publicApiExposesOnlyReusableSessionOpeners...ok");
    }

    @Test
    void sessionOpenersIgnoreUnrelatedEntryFamilies() throws Exception {
        System.out.println("sessionOpenersIgnoreUnrelatedEntryFamilies");
        ZeroEchoSession session = new ZeroEchoSession();
        UnlockMaterial.Password material = new UnlockMaterial.Password(new char[] { 'p' });
        try {
            assertNull(new KemCtxOpener(session).tryOpen("CTX-ENC:RSA", new byte[0], material));
            assertNull(new EncCtxOpener(session).tryOpen("KEM:ML-KEM:GCM-WRAP", new byte[0], material));
        } finally {
            material.destroy();
        }
        System.out.println("...ignoredFamilies=2");
        System.out.println("sessionOpenersIgnoreUnrelatedEntryFamilies...ok");
    }

    @Test
    void customReusableOpenerScansEveryEntryAndClosesOnce() throws Exception {
        System.out.println("customReusableOpenerScansEveryEntryAndClosesOnce");
        ZeroEchoSession session = new ZeroEchoSession().withPbkdf2Limits(new Pbkdf2Limits(20_000, 30_000));
        TrackingOpener opener = new TrackingOpener();
        UnlockMaterial.Password material = new UnlockMaterial.Password(new char[] { 'p' });
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader()).unlockWith(material)
                .addOpener(opener); MultiRecipientContent content = builder.build(false)) {
            content.setInput(() -> new ByteArrayInputStream(twoEntryHeader()));
            assertThrows(IOException.class, content::getStream);
        } finally {
            material.destroy();
        }

        assertEquals(2, opener.attempts);
        assertEquals(1, opener.closeCount);
        System.out.println("...attempts=" + opener.attempts);
        System.out.println("customReusableOpenerScansEveryEntryAndClosesOnce...ok");
    }

    private static void assertSessionOnlyConstructor(Class<?> openerClass) {
        Constructor<?>[] constructors = openerClass.getConstructors();
        assertEquals(1, constructors.length);
        assertEquals(ZeroEchoSession.class, constructors[0].getParameterTypes()[0]);
    }

    private static byte[] twoEntryHeader() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Util.writePack7I(output, 2);
        Util.writeUTF8(output, "first");
        Util.write(output, new byte[] { 1 });
        Util.writeUTF8(output, "second");
        Util.write(output, new byte[] { 2 });
        return output.toByteArray();
    }

    private static final class TrackingOpener implements RecipientOpener {
        private int attempts;
        private int closeCount;

        @Override
        public byte[] tryOpen(String entryId, byte[] entryBlob, UnlockMaterial material) {
            attempts++;
            return null;
        }

        @Override
        public void close() {
            closeCount++;
        }
    }
}
