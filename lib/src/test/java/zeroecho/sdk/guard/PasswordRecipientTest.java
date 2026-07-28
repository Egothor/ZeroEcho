/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk.guard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.Util;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.content.api.DataContent;

class PasswordRecipientTest {
    private static final Pbkdf2Limits LIMITS = new Pbkdf2Limits(20_000, 30_000);

    @Test
    void ownsAndDestroysRetainedPassword() throws Exception {
        System.out.print("PasswordRecipient/lifecycle...");
        char[] caller = "envelope-password".toCharArray();
        char[] expected = caller.clone();
        PasswordRecipient recipient = new PasswordRecipient(caller, 10_000, 16, 32, false, LIMITS);
        Arrays.fill(caller, 'x');

        Field field = PasswordRecipient.class.getDeclaredField("password");
        field.setAccessible(true);
        char[] owned = (char[]) field.get(recipient);
        assertArrayEquals(expected, owned);

        recipient.destroy();
        recipient.destroy();
        assertTrue(recipient.isDestroyed());
        assertTrue(Arrays.equals(new char[owned.length], owned));
        assertThrows(IllegalStateException.class, () -> recipient.buildRecipientEntry(new byte[32]));
        System.out.println("ok");
    }

    @Test
    void constructorsRejectIterationsBelowMinimumAndAcceptBoundary() {
        System.out.print("PasswordRecipient/constructorsRejectIterationsBelowMinimumAndAcceptBoundary...");
        int[] invalidValues = { -1, 0, 1, 9_999 };
        for (int iterations : invalidValues) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PasswordRecipient(new char[] { 'p' }, iterations, 16, 32, false, LIMITS));
            assertThrows(IllegalArgumentException.class,
                    () -> new PasswordRecipient(new char[] { 'p' }, iterations, 16, 32, true, LIMITS));
        }

        new PasswordRecipient(new char[] { 'p' }, 10_000, 16, 32, false, LIMITS);
        new PasswordRecipient(new char[] { 'p' }, 10_001, 16, 32, true, LIMITS);
        System.out.println("...minimum=" + Pbkdf2Limits.MINIMUM);
        System.out.println("ok");
    }

    @Test
    void constructorsAcceptOnlyOpenableKekSizes() throws Exception {
        System.out.println("constructorsAcceptOnlyOpenableKekSizes");
        int[] invalidValues = { -1, 0, 1, 15, 17, 24, 31, 33, Integer.MAX_VALUE };
        for (int kekBytes : invalidValues) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PasswordRecipient(new char[] { 'p' }, 10_000, 16, kekBytes, false, LIMITS));
        }

        PasswordRecipient aes128 =
                new PasswordRecipient(new char[] { 'p' }, 10_000, 16, 16, false, LIMITS);
        PasswordRecipient aes256 =
                new PasswordRecipient(new char[] { 'p' }, 10_000, 16, 32, false, LIMITS);
        aes128.close();
        aes256.close();
        System.out.println("...acceptedKekBytes=16,32");
        System.out.println("constructorsAcceptOnlyOpenableKekSizes...ok");
    }

    @Test
    void builderMethodsRejectBeforeRecipientListMutation() throws Exception {
        System.out.print("PasswordRecipient/builderMethodsRejectBeforeRecipientListMutation...");
        MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder
                .builder(new ZeroEchoSession().withPbkdf2Limits(LIMITS));
        int[] invalidValues = { -1, 0, 1, 9_999 };

        for (int iterations : invalidValues) {
            assertThrows(IllegalArgumentException.class,
                    () -> builder.addPasswordRecipient(new char[] { 'p' }, iterations, 16, 32));
            assertThrows(IllegalArgumentException.class,
                    () -> builder.addPasswordRecipientDecoy(new char[] { 'p' }, iterations, 16, 32));
            assertEquals(0, recipients(builder).size());
        }

        builder.addPasswordRecipient(new char[] { 'p' }, 10_000, 16, 32);
        builder.addPasswordRecipientDecoy(new char[] { 'p' }, 10_001, 16, 32);
        assertEquals(2, recipients(builder).size());
        System.out.println("...recipientCount=" + recipients(builder).size());
        System.out.println("ok");
    }

    @Test
    void builderRejectsUnsupportedKekBeforeStateMutation() throws Exception {
        System.out.println("builderRejectsUnsupportedKekBeforeStateMutation");
        MultiRecipientDataSourceBuilder builder = builderWithAes();
        int[] invalidValues = { -1, 0, 1, 15, 17, 24, 31, 33, Integer.MAX_VALUE };

        for (int kekBytes : invalidValues) {
            assertThrows(IllegalArgumentException.class,
                    () -> builder.addPasswordRecipient(new char[] { 'p' }, 10_000, 16, kekBytes));
            assertThrows(IllegalArgumentException.class,
                    () -> builder.addPasswordRecipientDecoy(new char[] { 'p' }, 10_000, 16, kekBytes));
            assertEquals(0, recipients(builder).size());
        }
        builder.close();
        System.out.println("...recipientCount=0");
        System.out.println("builderRejectsUnsupportedKekBeforeStateMutation...ok");
    }

    @Test
    void passwordOpenerRejectsSubminimumDecodedIterations() throws Exception {
        System.out.print("PasswordRecipient/passwordOpenerRejectsSubminimumDecodedIterations...");
        ByteArrayOutputStream blob = new ByteArrayOutputStream();
        Util.writePack7I(blob, 9_999);

        assertThrows(IOException.class, () -> new PasswordOpener(LIMITS).tryOpen(
                "PWD:PBKDF2-SHA256:GCM-WRAP", blob.toByteArray(),
                new UnlockMaterial.Password(new char[] { 'p' })));
        System.out.println("ok");
    }

    @Test
    void passwordOpenerRejectsUnterminatedIterationEncoding() {
        System.out.print("PasswordRecipient/passwordOpenerRejectsUnterminatedIterationEncoding...");
        PasswordOpener opener = new PasswordOpener(LIMITS);
        UnlockMaterial.Password material = new UnlockMaterial.Password(new char[] { 'p' });

        assertThrows(IOException.class,
                () -> opener.tryOpen("PWD:PBKDF2-SHA256:GCM-WRAP", new byte[] { 1 }, material));
        assertThrows(IOException.class,
                () -> opener.tryOpen("PWD:PBKDF2-SHA256:GCM-WRAP",
                        new byte[] { 1, 1, 1, 1, 1, (byte) 0x80 }, material));
        System.out.println("...malformedCases=2");
        System.out.println("ok");
    }

    @Test
    void builderCloseDestroysAbandonedPasswordRecipients() throws Exception {
        System.out.println("builderCloseDestroysAbandonedPasswordRecipients");
        MultiRecipientDataSourceBuilder builder = builderWithAes();
        builder.addPasswordRecipient(new char[] { 'p' }, 10_000, 16, 32);
        PasswordRecipient recipient = (PasswordRecipient) recipients(builder).get(0);

        builder.close();
        builder.close();

        assertTrue(builder.isDestroyed());
        assertTrue(recipient.isDestroyed());
        assertThrows(IllegalStateException.class, () -> builder.payloadKeyBytes(16));
        System.out.println("...destroyed=true");
        System.out.println("builderCloseDestroysAbandonedPasswordRecipients...ok");
    }

    @Test
    void transferredRecipientSurvivesBuilderCloseUntilTerminalFailure() throws Exception {
        System.out.println("transferredRecipientSurvivesBuilderCloseUntilTerminalFailure");
        MultiRecipientDataSourceBuilder builder = builderWithAes();
        builder.addPasswordRecipient(new char[] { 'p' }, 10_000, 16, 32);
        PasswordRecipient recipient = (PasswordRecipient) recipients(builder).get(0);
        DataContent encryptor = builder.build(true);

        builder.close();
        assertFalse(recipient.isDestroyed());
        assertThrows(NullPointerException.class, encryptor::getStream);
        assertTrue(recipient.isDestroyed());

        System.out.println("...ownershipTransferred=true");
        System.out.println("transferredRecipientSurvivesBuilderCloseUntilTerminalFailure...ok");
    }

    @Test
    void abandonedBuiltContentOwnsAndDestroysTransferredRecipient() throws Exception {
        System.out.println("abandonedBuiltContentOwnsAndDestroysTransferredRecipient");
        MultiRecipientDataSourceBuilder builder = builderWithAes();
        builder.addPasswordRecipient(new char[] { 'p' }, 10_000, 16, 32);
        PasswordRecipient recipient = (PasswordRecipient) recipients(builder).get(0);
        MultiRecipientContent content = builder.build(true);

        builder.close();
        assertFalse(recipient.isDestroyed());
        content.close();
        content.close();

        assertTrue(content.isDestroyed());
        assertTrue(recipient.isDestroyed());
        assertThrows(IllegalStateException.class,
                () -> content.setInput(() -> new ByteArrayInputStream(new byte[0])));
        assertThrows(IllegalStateException.class, content::getStream);
        System.out.println("...contentDestroyed=true");
        System.out.println("abandonedBuiltContentOwnsAndDestroysTransferredRecipient...ok");
    }

    @Test
    void terminalLimitAndRandomFailuresDestroyPasswordRecipients() throws Exception {
        System.out.println("terminalLimitAndRandomFailuresDestroyPasswordRecipients");
        MultiRecipientDataSourceBuilder limitedBuilder = builderWithAes().headerLimits(1, 1024);
        limitedBuilder.addPasswordRecipient(new char[] { 'a' }, 10_000, 16, 32);
        limitedBuilder.addPasswordRecipient(new char[] { 'b' }, 10_000, 16, 32);
        List<Recipient> limitedRecipients = List.copyOf(recipients(limitedBuilder));
        DataContent limited = limitedBuilder.build(true);
        limited.setInput(() -> new ByteArrayInputStream(new byte[0]));
        assertThrows(IOException.class, limited::getStream);
        assertTrue(limitedRecipients.stream()
                .map(PasswordRecipient.class::cast).allMatch(PasswordRecipient::isDestroyed));

        PasswordRecipient randomRecipient =
                new PasswordRecipient(new char[] { 'c' }, 10_000, 16, 32, false, LIMITS);
        Encryptor randomFailure = new Encryptor(List.of(randomRecipient),
                AesDataContentBuilder.builder(new ZeroEchoSession()).modeGcm(128).withHeader(),
                null, 32, 4, 1024, ignored -> {
                    throw new IllegalStateException("controlled random failure");
                });
        randomFailure.setInput(() -> new ByteArrayInputStream(new byte[0]));
        assertThrows(IllegalStateException.class, randomFailure::getStream);
        assertTrue(randomRecipient.isDestroyed());

        System.out.println("...terminalFailures=2");
        System.out.println("terminalLimitAndRandomFailuresDestroyPasswordRecipients...ok");
    }

    private static MultiRecipientDataSourceBuilder builderWithAes() {
        ZeroEchoSession session = new ZeroEchoSession().withPbkdf2Limits(LIMITS);
        return MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader());
    }

    @SuppressWarnings("unchecked")
    private static List<Recipient> recipients(MultiRecipientDataSourceBuilder builder) throws Exception {
        Field field = MultiRecipientDataSourceBuilder.class.getDeclaredField("recipients");
        field.setAccessible(true);
        return (List<Recipient>) field.get(builder);
    }
}
